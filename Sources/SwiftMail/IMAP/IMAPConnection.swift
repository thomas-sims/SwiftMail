import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers
import NIOSSL

/// Internal connection wrapper used by IMAPServer to manage per-connection state.
final class IMAPConnection {
    private struct PendingConnect {
        let id: UUID
        let promise: EventLoopPromise<Channel>
    }

    private struct LifecycleState {
        var channel: Channel?
        var pendingConnect: PendingConnect?
        var isRetired = false
        var idleHandler: IdleHandler?
        var idleTerminationInProgress = false
    }

    private let host: String
    private let port: Int
    private let group: EventLoopGroup
    private let lifecycleState = NIOLockedValueBox(LifecycleState())
    private var commandTagCounter: Int = 0
    private var capabilities: Set<NIOIMAPCore.Capability> = []
    private let commandQueue = IMAPCommandQueue()
    private let responseBuffer = UntaggedResponseBuffer()

    private let logger: Logging.Logger
    private let duplexLogger: IMAPLogger

    init(host: String, port: Int, group: EventLoopGroup, loggerLabel: String, outboundLabel: String, inboundLabel: String) {
        self.host = host
        self.port = port
        self.group = group

        self.logger = Logging.Logger(label: loggerLabel)
        let outboundLogger = Logging.Logger(label: outboundLabel)
        let inboundLogger = Logging.Logger(label: inboundLabel)
        self.duplexLogger = IMAPLogger(outboundLogger: outboundLogger, inboundLogger: inboundLogger)
    }

    var isConnected: Bool {
        lifecycleState.withLockedValue { state in
            state.channel?.isActive ?? false
        }
    }

    var capabilitiesSnapshot: Set<NIOIMAPCore.Capability> {
        capabilities
    }

    func supportsCapability(_ check: (Capability) -> Bool) -> Bool {
        capabilities.contains(where: check)
    }

    func connect() async throws {
        try ensureNotRetired()

        let sslContext = try NIOSSLContext(configuration: TLSConfiguration.makeClientConfiguration())
        let host = self.host

        let duplexLogger = self.duplexLogger
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                let sslHandler = try! NIOSSLClientHandler(context: sslContext, serverHostname: host)

                let parserOptions = ResponseParser.Options(
                    bufferLimit: 1024 * 1024,
                    messageAttributeLimit: .max,
                    bodySizeLimit: .max,
                    literalSizeLimit: IMAPDefaults.literalSizeLimit
                )

                try! channel.pipeline.syncOperations.addHandlers([
                    sslHandler,
                    IMAPClientHandler(parserOptions: parserOptions),
                    duplexLogger
                ])

                return channel.eventLoop.makeSucceededFuture(())
            }

        let connectFuture = bootstrap.connect(host: host, port: port)
        let pendingConnect = PendingConnect(
            id: UUID(),
            promise: connectFuture.eventLoop.makePromise(of: Channel.self)
        )
        let registered = lifecycleState.withLockedValue { state in
            guard !state.isRetired, state.pendingConnect == nil else {
                return false
            }
            state.pendingConnect = pendingConnect
            return true
        }

        guard registered else {
            connectFuture.whenSuccess { channel in
                channel.close(promise: nil)
            }
            try ensureNotRetired()
            throw IMAPError.connectionFailed("Connection attempt already in progress")
        }

        let lifecycleState = self.lifecycleState
        connectFuture.whenComplete { result in
            Self.completePendingConnect(pendingConnect, with: result, lifecycleState: lifecycleState)
        }

        let channel = try await pendingConnect.promise.futureResult.get()

        // Add the persistent untagged response buffer as the LAST handler in the pipeline.
        // Transient command handlers are added BEFORE it (position: .before(responseBuffer)).
        // channelRead flows first→last, so: command handler processes response → calls
        // fireChannelRead → buffer sees it. When no command handler is active, responses
        // flow directly to the buffer which captures them for later draining.
        try await channel.pipeline.addHandler(responseBuffer).get()

        try ensureNotRetired()

        logger.info("Connected to IMAP server with 1MB buffer limit for large responses")

        let greetingCapabilities: [Capability] = try await executeHandlerOnly(handlerType: IMAPGreetingHandler.self, timeoutSeconds: 5)
        try await refreshCapabilities(using: greetingCapabilities)
    }

    @discardableResult func fetchCapabilities() async throws -> [Capability] {
        let command = CapabilityCommand()
        let serverCapabilities = try await executeCommand(command)
        self.capabilities = Set(serverCapabilities)
        return serverCapabilities
    }

    func login(username: String, password: String) async throws {
        let command = LoginCommand(username: username, password: password)
        let loginCapabilities = try await executeCommand(command)
        try await refreshCapabilities(using: loginCapabilities)
    }

    func authenticateXOAUTH2(email: String, accessToken: String) async throws {
        try await commandQueue.run { [self] in
            try await self.authenticateXOAUTH2Body(email: email, accessToken: accessToken)
        }
    }

    func id(_ identification: Identification = Identification()) async throws -> Identification {
        guard capabilities.contains(.id) else {
            throw IMAPError.commandNotSupported("ID command not supported by server")
        }

        let command = IDCommand(identification: identification)
        return try await executeCommand(command)
    }

    func idle() async throws -> AsyncStream<IMAPServerEvent> {
        var continuationRef: AsyncStream<IMAPServerEvent>.Continuation!
        let stream = AsyncStream<IMAPServerEvent> { continuation in
            continuationRef = continuation
        }

        guard let continuation = continuationRef else {
            throw IMAPError.commandFailed("Failed to start IDLE session")
        }

        do {
            try await commandQueue.run { [self] in
                try await self.startIdleSession(continuation: continuation)
            }
        } catch {
            continuation.finish()
            throw error
        }

        return stream
    }

    func done() async throws {
        let snapshot = lifecycleState.withLockedValue { state in
            let shouldSendDone = !state.idleTerminationInProgress
            if state.idleHandler != nil, shouldSendDone {
                state.idleTerminationInProgress = true
            }
            return (state.idleHandler, state.channel, shouldSendDone)
        }

        guard let handler = snapshot.0 else {
            logger.debug("No active IDLE session, skipping DONE command")
            return
        }

        guard let channel = snapshot.1 else {
            handler.abort()
            lifecycleState.withLockedValue { state in
                state.idleTerminationInProgress = false
                if state.idleHandler === handler {
                    state.idleHandler = nil
                }
            }
            return
        }

        guard !snapshot.2 else {
            try await handler.promise.futureResult.get()
            return
        }

        defer {
            lifecycleState.withLockedValue { state in
                state.idleTerminationInProgress = false
                if state.idleHandler === handler {
                    state.idleHandler = nil
                }
            }
            responseBuffer.hasActiveHandler = false
        }

        do {
            try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.idleDone)).get()
        } catch {
            // Ignore write errors during DONE.
        }

        try await handler.promise.futureResult.get()
    }

    func noop() async throws -> [IMAPServerEvent] {
        let command = NoopCommand()
        return try await executeCommand(command)
    }

    /// Drain any untagged responses that were buffered between command handlers.
    ///
    /// Returns them converted to `IMAPServerEvent`s. Responses that don't map
    /// to a known event type are logged and skipped.
    func drainBufferedEvents() -> [IMAPServerEvent] {
        let raw = responseBuffer.drainBuffer()
        guard !raw.isEmpty else { return [] }

        logger.debug("Draining \(raw.count) buffered response(s)")
        var events: [IMAPServerEvent] = []

        for response in raw {
            switch response {
            case .untagged(let payload):
                switch payload {
                case .mailboxData(let data):
                    switch data {
                    case .exists(let count):
                        events.append(.exists(Int(count)))
                    case .recent(let count):
                        events.append(.recent(Int(count)))
                    case .flags(let flags):
                        events.append(.flags(flags.map { Flag(nio: $0) }))
                    default:
                        logger.debug("Buffered unhandled mailboxData: \(data)")
                    }
                case .messageData(let data):
                    switch data {
                    case .expunge(let seq):
                        events.append(.expunge(SequenceNumber(seq.rawValue)))
                    default:
                        logger.debug("Buffered unhandled messageData: \(data)")
                    }
                case .conditionalState(let status):
                    switch status {
                    case .ok(let text):
                        if text.code == .alert {
                            events.append(.alert(text.text))
                        }
                    case .bye(let text):
                        events.append(.bye(text.text))
                    default:
                        break
                    }
                case .capabilityData(let caps):
                    events.append(.capability(caps.map { String($0) }))
                default:
                    logger.debug("Buffered unhandled payload: \(payload)")
                }
            case .fetch(let fetch):
                // Collect fetch attributes from buffered fetch sequence
                switch fetch {
                case .start, .startUID, .simpleAttribute, .finish:
                    // Individual fetch parts can't be meaningfully reconstructed here
                    // since we may not have the complete sequence. Log it.
                    logger.debug("Buffered fetch response part: \(fetch)")
                default:
                    logger.debug("Buffered unhandled fetch: \(fetch)")
                }
            case .fatal(let text):
                events.append(.bye(text.text))
            default:
                break
            }
        }

        return events
    }

    func disconnect() async throws {
        let channel = lifecycleState.withLockedValue { state -> Channel? in
            let channel = state.channel
            state.channel = nil
            return channel
        }

        guard let channel else {
            logger.warning("Attempted to disconnect when channel was already nil")
            return
        }

        try await channel.close(mode: CloseMode.all).get()
        try await channel.closeFuture.get()
    }

    /// Permanently retire this connection and immediately tear down its transport.
    /// No DONE or LOGOUT command is sent, and future commands cannot reconnect it.
    func hardAbort() async {
        let snapshot = lifecycleState.withLockedValue { state -> (Channel?, IdleHandler?, PendingConnect?) in
            state.isRetired = true
            let channel = state.channel
            let idleHandler = state.idleHandler
            let pendingConnect = state.pendingConnect
            state.channel = nil
            state.pendingConnect = nil
            state.idleHandler = nil
            state.idleTerminationInProgress = false
            return (channel, idleHandler, pendingConnect)
        }

        await commandQueue.abort()
        snapshot.1?.abort()
        snapshot.2?.promise.fail(Self.abortedError)

        if let channel = snapshot.0 {
            try? await channel.close(mode: CloseMode.all).get()
            try? await channel.closeFuture.get()
        }
    }

    // MARK: - Private Helpers

    private func refreshCapabilities(using reportedCapabilities: [Capability]) async throws {
        if !reportedCapabilities.isEmpty {
            self.capabilities = Set(reportedCapabilities)
        } else {
            try await fetchCapabilities()
        }
    }

    private func authenticateXOAUTH2Body(email: String, accessToken: String) async throws {
        try ensureNotRetired()

        let mechanism = AuthenticationMechanism("XOAUTH2")
        let xoauthCapability = Capability.authenticate(mechanism)

        guard capabilities.contains(xoauthCapability) else {
            throw IMAPError.unsupportedAuthMechanism("XOAUTH2 not advertised by server")
        }

        try await waitForIdleCompletionIfNeeded()

        clearInvalidChannel()

        if currentChannel == nil {
            logger.info("Channel is nil, re-establishing connection before authentication")
            try await connect()
        }

        guard let channel = currentChannel else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }

        let expectsChallenge = !capabilities.contains(.saslIR)
        let tag = generateCommandTag()

        let handlerPromise = channel.eventLoop.makePromise(of: [Capability].self)
        let credentialBuffer = makeXOAUTH2InitialResponseBuffer(email: email, accessToken: accessToken)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: tag,
            promise: handlerPromise,
            credentials: credentialBuffer,
            expectsChallenge: expectsChallenge,
            logger: logger
        )

        try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
        responseBuffer.hasActiveHandler = true

        let initialResponse = expectsChallenge ? nil : InitialResponse(credentialBuffer)

        let command = TaggedCommand(tag: tag, command: .authenticate(mechanism: mechanism, initialResponse: initialResponse))
        let wrapped = IMAPClientHandler.OutboundIn.part(CommandStreamPart.tagged(command))

        let authenticationTimeoutSeconds = 10
        let logger = self.logger
        let scheduledTask = group.next().scheduleTask(in: .seconds(Int64(authenticationTimeoutSeconds))) {
            logger.warning("XOAUTH2 authentication timed out after \(authenticationTimeoutSeconds) seconds")
            handler.failWithError(IMAPError.timeout)
        }

        do {
            try await channel.writeAndFlush(wrapped).get()
            let refreshedCapabilities = try await handlerPromise.futureResult.get()

            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            try await refreshCapabilities(using: refreshedCapabilities)
        } catch {
            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            try? await channel.pipeline.removeHandler(handler)

            throw error
        }
    }

    private func startIdleSession(continuation: AsyncStream<IMAPServerEvent>.Continuation) async throws {
        try ensureNotRetired()

        if !capabilities.contains(.idle) {
            throw IMAPError.commandNotSupported("IDLE command not supported by server")
        }

        let hasIdleHandler = lifecycleState.withLockedValue { state in
            state.idleHandler != nil
        }
        guard !hasIdleHandler else {
            throw IMAPError.commandFailed("IDLE session already active")
        }

        guard let channel = currentChannel else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }

        let promise = channel.eventLoop.makePromise(of: Void.self)
        let tag = generateCommandTag()
        let handler = IdleHandler(commandTag: tag, promise: promise, continuation: continuation)
        let registered = lifecycleState.withLockedValue { state in
            guard !state.isRetired, state.idleHandler == nil else {
                return false
            }
            state.idleTerminationInProgress = false
            state.idleHandler = handler
            return true
        }

        guard registered else {
            handler.abort()
            throw Self.abortedError
        }

        do {
            try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
            responseBuffer.hasActiveHandler = true
            let command = IdleCommand()
            let tagged = command.toTaggedCommand(tag: tag)
            let wrapped = IMAPClientHandler.OutboundIn.part(CommandStreamPart.tagged(tagged))
            try await channel.writeAndFlush(wrapped).get()
        } catch {
            lifecycleState.withLockedValue { state in
                if state.idleHandler === handler {
                    state.idleHandler = nil
                }
            }
            handler.failWithError(error)
            continuation.finish()
            throw error
        }
    }

    private func handleConnectionTerminationInResponses(_ untaggedResponses: [Response]) async {
        for response in untaggedResponses {
            if case .untagged(let payload) = response,
               case .conditionalState(let status) = payload,
               case .bye = status {
                try? await self.disconnect()
                break
            }
            if case .fatal = response {
                try? await self.disconnect()
                break
            }
        }
    }

    private func waitForIdleCompletionIfNeeded() async throws {
        guard let handler = lifecycleState.withLockedValue({ $0.idleHandler }) else { return }
        try await handler.promise.futureResult.get()
    }

    private func makeXOAUTH2InitialResponseBuffer(email: String, accessToken: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: email.utf8.count + accessToken.utf8.count + 32)
        buffer.writeString("user=")
        buffer.writeString(email)
        buffer.writeInteger(UInt8(0x01))
        buffer.writeString("auth=Bearer ")
        buffer.writeString(accessToken)
        buffer.writeInteger(UInt8(0x01))
        buffer.writeInteger(UInt8(0x01))
        return buffer
    }

    func executeCommand<CommandType: IMAPCommand>(_ command: CommandType) async throws -> CommandType.ResultType {
        try await commandQueue.run { [self] in
            try await self.executeCommandBody(command)
        }
    }

    private func executeCommandBody<CommandType: IMAPCommand>(_ command: CommandType) async throws -> CommandType.ResultType {
        try ensureNotRetired()
        try command.validate()
        try await waitForIdleCompletionIfNeeded()

        clearInvalidChannel()

        if currentChannel == nil {
            logger.info("Channel is nil, re-establishing connection before sending command")
            try await connect()
        }

        guard let channel = currentChannel else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }

        let resultPromise = channel.eventLoop.makePromise(of: CommandType.ResultType.self)
        let tag = generateCommandTag()
        let handler = CommandType.HandlerType.init(commandTag: tag, promise: resultPromise)
        let timeoutSeconds = command.timeoutSeconds

        let logger = self.logger
        let scheduledTask = group.next().scheduleTask(in: .seconds(Int64(timeoutSeconds))) {
            logger.warning("Command timed out after \(timeoutSeconds) seconds")
            handler.failWithError(IMAPError.timeout)
        }

        do {
            try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
            responseBuffer.hasActiveHandler = true
            try await command.send(on: channel, tag: tag)
            let result = try await resultPromise.futureResult.get()

            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false

            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            return result
        } catch {
            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            handler.failWithError(error)
            try? await channel.pipeline.removeHandler(handler)
            throw error
        }
    }

    private func executeHandlerOnly<T: Sendable, HandlerType: IMAPCommandHandler>(
        handlerType: HandlerType.Type,
        timeoutSeconds: Int = 5
    ) async throws -> T where HandlerType.ResultType == T {
        try ensureNotRetired()
        clearInvalidChannel()

        if currentChannel == nil {
            logger.info("Channel is nil, re-establishing connection before executing handler")
            try await connect()
        }

        guard let channel = currentChannel else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }

        let resultPromise = channel.eventLoop.makePromise(of: T.self)
        let handler = HandlerType.init(commandTag: "", promise: resultPromise)

        let logger = self.logger
        let scheduledTask = group.next().scheduleTask(in: .seconds(Int64(timeoutSeconds))) {
            logger.warning("Handler execution timed out after \(timeoutSeconds) seconds")
            handler.failWithError(IMAPError.timeout)
        }

        do {
            try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
            responseBuffer.hasActiveHandler = true
            let result = try await resultPromise.futureResult.get()

            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false

            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            return result
        } catch {
            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            await handleConnectionTerminationInResponses(handler.untaggedResponses)
            duplexLogger.flushInboundBuffer()

            handler.failWithError(error)
            try? await channel.pipeline.removeHandler(handler)
            throw error
        }
    }

    private func clearInvalidChannel() {
        let didClear = lifecycleState.withLockedValue { state in
            if let channel = state.channel, !channel.isActive {
                state.channel = nil
                return true
            }
            return false
        }

        if didClear {
            logger.info("Channel is no longer active, clearing channel reference")
        }
    }

    private static func completePendingConnect(
        _ pendingConnect: PendingConnect,
        with result: Result<Channel, Error>,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) {
        switch result {
        case .success(let channel):
            let shouldAdopt = lifecycleState.withLockedValue { state in
                guard state.pendingConnect?.id == pendingConnect.id else {
                    return false
                }

                state.pendingConnect = nil
                guard !state.isRetired else { return false }
                state.channel = channel
                return true
            }

            if shouldAdopt {
                pendingConnect.promise.succeed(channel)
            } else {
                channel.close(promise: nil)
            }

        case .failure(let error):
            let shouldFail = lifecycleState.withLockedValue { state in
                guard state.pendingConnect?.id == pendingConnect.id else {
                    return false
                }
                state.pendingConnect = nil
                return true
            }

            if shouldFail {
                pendingConnect.promise.fail(error)
            }
        }
    }

    private var currentChannel: Channel? {
        lifecycleState.withLockedValue { $0.channel }
    }

    private func ensureNotRetired() throws {
        let isRetired = lifecycleState.withLockedValue { $0.isRetired }
        if isRetired {
            throw Self.abortedError
        }
    }

    private static var abortedError: IMAPError {
        IMAPError.connectionFailed("Connection was aborted")
    }

    private func generateCommandTag() -> String {
        let tagPrefix = "A"
        commandTagCounter += 1
        return "\(tagPrefix)\(String(format: "%03d", commandTagCounter))"
    }
}
