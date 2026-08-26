import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers
import NIOSSL

/// Internal connection wrapper used by IMAPServer to manage per-connection state.
final class IMAPConnection {
    typealias ConnectOverride = (@escaping @Sendable (Channel) -> Void) -> EventLoopFuture<Channel>

    private final class PendingConnect: @unchecked Sendable {
        let id: UUID
        let promise: EventLoopPromise<Channel>
        /// Completed once synchronous transport creation returns. Reserving this
        /// promise in lifecycle state first lets hard abort join creation itself,
        /// not only a transport future that has already been returned.
        let transportHandoffPromise: EventLoopPromise<EventLoopFuture<Channel>>
        /// Completed only after the connect caller has either finished greeting /
        /// capability setup or unwound from an error. Teardown joins this promise
        /// before allowing another connection generation to start.
        let settlementPromise: EventLoopPromise<Void>

        private struct CompletionState {
            var channelPromiseCompleted = false
            var handoffPromiseCompleted = false
            var settlementPromiseCompleted = false
        }

        private let completionState = NIOLockedValueBox(CompletionState())

        init(eventLoop: EventLoop) {
            self.id = UUID()
            self.promise = eventLoop.makePromise(of: Channel.self)
            self.transportHandoffPromise = eventLoop.makePromise(of: EventLoopFuture<Channel>.self)
            self.settlementPromise = eventLoop.makePromise(of: Void.self)
        }

        func completeChannel(with result: Result<Channel, Error>) {
            let shouldComplete = completionState.withLockedValue { state in
                guard !state.channelPromiseCompleted else { return false }
                state.channelPromiseCompleted = true
                return true
            }
            guard shouldComplete else { return }

            switch result {
            case .success(let channel):
                promise.succeed(channel)
            case .failure(let error):
                promise.fail(error)
            }
        }

        func completeTransportHandoff(with result: Result<EventLoopFuture<Channel>, Error>) {
            let shouldComplete = completionState.withLockedValue { state in
                guard !state.handoffPromiseCompleted else { return false }
                state.handoffPromiseCompleted = true
                return true
            }
            guard shouldComplete else { return }

            switch result {
            case .success(let future):
                transportHandoffPromise.succeed(future)
            case .failure(let error):
                transportHandoffPromise.fail(error)
            }
        }

        func settle() {
            let shouldComplete = completionState.withLockedValue { state in
                guard !state.settlementPromiseCompleted else { return false }
                state.settlementPromiseCompleted = true
                return true
            }
            if shouldComplete {
                settlementPromise.succeed(())
            }
        }
    }

    private struct LifecycleState {
        var channel: Channel?
        /// Every channel created for this connection, including Happy-Eyeballs
        /// candidates that have not won yet and channels that are closing.
        /// Entries are removed only by their `closeFuture` callback.
        var ownedChannels: [ObjectIdentifier: Channel] = [:]
        var pendingConnect: PendingConnect?
        var isRetired = false
        /// A recoverable generation fence. Unlike `isRetired`, this is cleared
        /// only after graceful teardown has joined the old connect attempt and
        /// closed all of its transports.
        var isGracefulDisconnectInProgress = false
        var idleHandler: IdleHandler?
        var idleTerminationInProgress = false
    }

    private let host: String
    private let port: Int
    private let group: EventLoopGroup
    private let connectOverride: ConnectOverride?
    private let lifecycleState = NIOLockedValueBox(LifecycleState())
    private var commandTagCounter: Int = 0
    private var capabilities: Set<NIOIMAPCore.Capability> = []
    private let commandQueue = IMAPCommandQueue()
    private let responseBuffer = UntaggedResponseBuffer()

    private let logger: Logging.Logger
    private let duplexLogger: IMAPLogger

    init(
        host: String,
        port: Int,
        group: EventLoopGroup,
        loggerLabel: String,
        outboundLabel: String,
        inboundLabel: String,
        connectOverride: ConnectOverride? = nil
    ) {
        self.host = host
        self.port = port
        self.group = group
        self.connectOverride = connectOverride

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

        // Claim the single transport-creation slot before invoking ClientBootstrap
        // (or the deterministic test override). Otherwise abort or a second connect
        // can run while creation is in progress but still invisible to lifecycle state.
        let pendingConnect = PendingConnect(eventLoop: group.next())
        let registrationError = lifecycleState.withLockedValue { state -> IMAPError? in
            guard !state.isRetired else { return Self.abortedError }
            guard !state.isGracefulDisconnectInProgress else { return Self.teardownError }
            guard state.pendingConnect == nil else {
                return IMAPError.connectionFailed("Connection attempt already in progress")
            }
            guard state.channel == nil else {
                return IMAPError.connectionFailed("Connection already established")
            }
            state.pendingConnect = pendingConnect
            return nil
        }

        if let registrationError {
            // These promises were never published. Resolve both so every rejected
            // attempt has exactly one terminal path and cannot leak NIO promises.
            pendingConnect.completeChannel(with: .failure(registrationError))
            pendingConnect.completeTransportHandoff(with: .failure(registrationError))
            pendingConnect.settle()
            throw registrationError
        }

        let lifecycleState = self.lifecycleState
        let connectAttemptID = pendingConnect.id
        let registerChannel: @Sendable (Channel) -> Void = { channel in
            Self.registerOwnedChannel(
                channel,
                connectAttemptID: connectAttemptID,
                lifecycleState: lifecycleState
            )
        }

        let connectFuture: EventLoopFuture<Channel>
        if let connectOverride {
            connectFuture = connectOverride(registerChannel)
        } else {
            let duplexLogger = self.duplexLogger
            connectFuture = ClientBootstrap(group: group)
                // Make the NIO-owned Happy-Eyeballs attempt explicitly bounded.
                // Hard abort additionally closes every candidate surfaced through
                // the initializer and awaits this underlying future.
                .connectTimeout(.seconds(10))
                .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
                .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
                .channelInitializer { channel in
                    registerChannel(channel)

                    let accepted = lifecycleState.withLockedValue { state in
                        !state.isRetired
                            && !state.isGracefulDisconnectInProgress
                            && state.pendingConnect?.id == connectAttemptID
                    }
                    guard accepted else {
                        return channel.close(mode: .all).flatMapThrowing {
                            throw Self.currentTeardownError(lifecycleState: lifecycleState)
                        }
                    }

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
                .connect(host: host, port: port)
        }

        connectFuture.whenComplete { result in
            Self.completePendingConnect(pendingConnect, with: result, lifecycleState: lifecycleState)
        }
        pendingConnect.completeTransportHandoff(with: .success(connectFuture))

        var adoptedChannel: Channel?
        do {
            let channel = try await pendingConnect.promise.futureResult.get()
            adoptedChannel = channel

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

            guard Self.establishPendingConnect(
                pendingConnect,
                channel: channel,
                lifecycleState: lifecycleState
            ) else {
                throw Self.currentTeardownError(lifecycleState: lifecycleState)
            }
            Self.settlePendingConnect(pendingConnect, lifecycleState: lifecycleState)
        } catch {
            let channelToClose = Self.releasePendingConnect(
                pendingConnect,
                adoptedChannel: adoptedChannel,
                lifecycleState: lifecycleState
            )
            if let channelToClose {
                channelToClose.close(mode: .all, promise: nil)
                try? await channelToClose.closeFuture.get()
            }
            Self.settlePendingConnect(pendingConnect, lifecycleState: lifecycleState)
            throw error
        }
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

        // The caller that atomically installed the termination marker owns the
        // sole DONE write. Every duplicate joins the same tagged-response promise.
        if snapshot.2 {
            do {
                try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.idleDone)).get()
            } catch {
                // Ignore write errors during DONE; channel teardown will resolve
                // the shared handler promise if the transport is no longer viable.
            }
        }

        defer {
            lifecycleState.withLockedValue { state in
                if state.idleHandler === handler {
                    state.idleHandler = nil
                    state.idleTerminationInProgress = false
                }
            }
            responseBuffer.hasActiveHandler = false
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
        let snapshot = lifecycleState.withLockedValue { state -> (didBegin: Bool, channels: [Channel], pendingConnect: PendingConnect?) in
            guard !state.isRetired else { return (false, [], nil) }
            guard !state.isGracefulDisconnectInProgress else { return (false, [], state.pendingConnect) }

            state.isGracefulDisconnectInProgress = true
            state.channel = nil
            return (true, Array(state.ownedChannels.values), state.pendingConnect)
        }

        guard snapshot.didBegin else {
            if lifecycleState.withLockedValue({ $0.isGracefulDisconnectInProgress && !$0.isRetired }) {
                throw Self.teardownError
            }
            return
        }

        // Unblock a connect caller that may be waiting for transport adoption,
        // while retaining the attempt object so this teardown can join the
        // factory handoff, underlying future, and caller settlement below.
        snapshot.pendingConnect?.completeChannel(with: .failure(Self.teardownError))

        if snapshot.channels.isEmpty, snapshot.pendingConnect == nil {
            logger.warning("Attempted to disconnect when channel was already nil")
        }

        for channel in snapshot.channels {
            channel.close(mode: CloseMode.all, promise: nil)
        }
        var firstCloseError: Error?
        for channel in snapshot.channels {
            do {
                try await channel.closeFuture.get()
            } catch {
                if firstCloseError == nil { firstCloseError = error }
            }
        }

        if let pendingConnect = snapshot.pendingConnect {
            if let transportFuture = try? await pendingConnect.transportHandoffPromise.futureResult.get() {
                _ = try? await transportFuture.get()
            }
            _ = try? await pendingConnect.settlementPromise.futureResult.get()
        }

        // No old-generation registration can be accepted after its attempt has
        // settled. Drain candidates surfaced during the initial close snapshot.
        await closeRemainingOwnedChannels()

        capabilities = []
        lifecycleState.withLockedValue { state in
            if state.pendingConnect?.id == snapshot.pendingConnect?.id {
                state.pendingConnect = nil
            }
            state.isGracefulDisconnectInProgress = false
        }

        if let firstCloseError { throw firstCloseError }
    }

    /// Permanently retire this connection and immediately tear down its transport.
    /// No DONE or LOGOUT command is sent, and future commands cannot reconnect it.
    func hardAbort() async {
        let snapshot = lifecycleState.withLockedValue { state -> (didRetire: Bool, channels: [Channel], idleHandler: IdleHandler?, pendingConnect: PendingConnect?) in
            let didRetire = !state.isRetired
            state.isRetired = true
            let idleHandler = state.idleHandler
            state.channel = nil
            state.idleHandler = nil
            state.idleTerminationInProgress = false
            return (didRetire, Array(state.ownedChannels.values), idleHandler, state.pendingConnect)
        }

        await commandQueue.abort()
        responseBuffer.hasActiveHandler = false
        snapshot.idleHandler?.abort()
        if snapshot.didRetire {
            snapshot.pendingConnect?.completeChannel(with: .failure(Self.abortedError))
        }

        // Close every channel the bootstrap has surfaced, including losing
        // Happy-Eyeballs candidates and channels already in graceful teardown.
        // Issue all closes before awaiting any one close so one slow transport
        // cannot postpone retirement of its siblings.
        for channel in snapshot.channels {
            channel.close(mode: CloseMode.all, promise: nil)
        }
        for channel in snapshot.channels {
            try? await channel.closeFuture.get()
        }

        // Failing the public wrapper promise is not transport cancellation.
        // First join synchronous transport creation, then wait for NIO's actual
        // ClientBootstrap/Happy-Eyeballs attempt. Its explicit connect timeout
        // bounds the no-candidate/DNS portion.
        if let pendingConnect = snapshot.pendingConnect {
            if let transportFuture = try? await pendingConnect.transportHandoffPromise.futureResult.get() {
                _ = try? await transportFuture.get()
            }
            _ = try? await pendingConnect.settlementPromise.futureResult.get()
        }

        // A candidate can be initialized concurrently with the first snapshot.
        // The retired registration path closes it immediately; this final drain
        // observes and awaits that late channel before hardAbort returns.
        await closeRemainingOwnedChannels()
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

    func startIdleSession(continuation: AsyncStream<IMAPServerEvent>.Continuation) async throws {
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

        var handlerInstalled = false
        do {
            try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
            handlerInstalled = true
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
                state.idleTerminationInProgress = false
            }
            responseBuffer.hasActiveHandler = false
            handler.failWithError(error)
            continuation.finish()
            if handlerInstalled {
                try? await channel.pipeline.removeHandler(handler)
            }
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

    /// Register a transport at channel-initializer time, before TCP/TLS has
    /// succeeded. This is the authoritative ownership boundary for abort: a
    /// channel remains present until its closeFuture fires, even if it never
    /// becomes the selected connection or graceful close has already begun.
    private static func registerOwnedChannel(
        _ channel: Channel,
        connectAttemptID: UUID? = nil,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) {
        let identifier = ObjectIdentifier(channel)
        let shouldClose = lifecycleState.withLockedValue { state -> Bool in
            state.ownedChannels[identifier] = channel
            guard !state.isRetired, !state.isGracefulDisconnectInProgress else {
                return true
            }
            if let connectAttemptID {
                return state.pendingConnect?.id != connectAttemptID
            }
            return false
        }

        channel.closeFuture.whenComplete { _ in
            lifecycleState.withLockedValue { state in
                state.ownedChannels.removeValue(forKey: identifier)
                if let active = state.channel, active === channel {
                    state.channel = nil
                }
            }
        }

        if shouldClose {
            channel.close(mode: CloseMode.all, promise: nil)
        }
    }

    private func closeRemainingOwnedChannels() async {
        while true {
            let channels = lifecycleState.withLockedValue { Array($0.ownedChannels.values) }
            guard !channels.isEmpty else { return }

            for channel in channels {
                channel.close(mode: CloseMode.all, promise: nil)
            }
            for channel in channels {
                try? await channel.closeFuture.get()
            }
        }
    }

    private static func completePendingConnect(
        _ pendingConnect: PendingConnect,
        with result: Result<Channel, Error>,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) {
        switch result {
        case .success(let channel):
            let rejectionError = lifecycleState.withLockedValue { state -> IMAPError? in
                guard state.pendingConnect?.id == pendingConnect.id else {
                    return Self.currentTeardownError(state: state)
                }

                guard !state.isRetired, !state.isGracefulDisconnectInProgress else {
                    return Self.currentTeardownError(state: state)
                }
                state.channel = channel
                return nil
            }

            if let rejectionError {
                pendingConnect.completeChannel(with: .failure(rejectionError))
                channel.close(mode: .all, promise: nil)
            } else {
                // Keep the attempt reserved until greeting and capability setup
                // have completed. This is transport adoption, not establishment.
                pendingConnect.completeChannel(with: .success(channel))
            }

        case .failure(let error):
            let completionError = lifecycleState.withLockedValue { state -> Error in
                guard state.pendingConnect?.id == pendingConnect.id else {
                    return Self.currentTeardownError(state: state)
                }
                guard !state.isRetired, !state.isGracefulDisconnectInProgress else {
                    return Self.currentTeardownError(state: state)
                }
                return error
            }
            pendingConnect.completeChannel(with: .failure(completionError))
        }
    }

    /// Commits the transport as an established generation only after greeting
    /// and capability setup have both completed successfully.
    private static func establishPendingConnect(
        _ pendingConnect: PendingConnect,
        channel: Channel,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) -> Bool {
        lifecycleState.withLockedValue { state in
            guard state.pendingConnect?.id == pendingConnect.id,
                  !state.isRetired,
                  !state.isGracefulDisconnectInProgress,
                  state.channel === channel else {
                return false
            }
            return true
        }
    }

    /// Releases a failed connect attempt and returns its adopted channel when
    /// this caller still owns it, allowing the caller to close and await it.
    private static func releasePendingConnect(
        _ pendingConnect: PendingConnect,
        adoptedChannel: Channel?,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) -> Channel? {
        lifecycleState.withLockedValue { state in
            guard state.pendingConnect?.id == pendingConnect.id else { return nil }
            guard let adoptedChannel, state.channel === adoptedChannel else { return nil }
            state.channel = nil
            return adoptedChannel
        }
    }

    /// Publishes attempt settlement before releasing its generation slot. There
    /// are no suspension points between these operations, so teardown either
    /// captures this attempt and joins an already-resolved promise or observes
    /// the fully released generation.
    private static func settlePendingConnect(
        _ pendingConnect: PendingConnect,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) {
        pendingConnect.settle()
        lifecycleState.withLockedValue { state in
            if state.pendingConnect?.id == pendingConnect.id {
                state.pendingConnect = nil
            }
        }
    }

    private static func currentTeardownError(
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) -> IMAPError {
        lifecycleState.withLockedValue { currentTeardownError(state: $0) }
    }

    private static func currentTeardownError(state: LifecycleState) -> IMAPError {
        state.isRetired ? abortedError : teardownError
    }

    // Internal lifecycle observability used by deterministic package tests.
    // These expose only counts/booleans, never hosts, mailbox data, or secrets.
    var ownedTransportCount: Int {
        lifecycleState.withLockedValue { $0.ownedChannels.count }
    }

    var hasPendingTransportConnect: Bool {
        lifecycleState.withLockedValue { $0.pendingConnect != nil }
    }

    var isGracefulDisconnecting: Bool {
        lifecycleState.withLockedValue { $0.isGracefulDisconnectInProgress }
    }

    var hasIdleHandler: Bool {
        lifecycleState.withLockedValue { $0.idleHandler != nil }
    }

    var hasActiveResponseHandler: Bool {
        responseBuffer.hasActiveHandler
    }

    func hasInstalledIdleHandler() async -> Bool {
        guard let channel = currentChannel else { return false }
        return (try? await channel.eventLoop.submit {
            do {
                _ = try channel.pipeline.syncOperations.context(handlerType: IdleHandler.self)
                return true
            } catch {
                return false
            }
        }.get()) ?? false
    }

    /// Installs an already-created channel at the same ownership and pipeline
    /// boundary used by `connect()`. Internal so package tests can deterministically
    /// exercise IDLE teardown without an external TLS server.
    func prepareEstablishedChannel(
        _ channel: Channel,
        capabilities: Set<NIOIMAPCore.Capability> = []
    ) async throws {
        Self.registerOwnedChannel(channel, lifecycleState: lifecycleState)
        let adopted = lifecycleState.withLockedValue { state -> Bool in
            guard !state.isRetired, !state.isGracefulDisconnectInProgress else { return false }
            state.channel = channel
            return true
        }
        guard adopted else {
            channel.close(mode: .all, promise: nil)
            throw Self.abortedError
        }

        try await channel.pipeline.addHandler(responseBuffer).get()
        self.capabilities = capabilities
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

    private static var teardownError: IMAPError {
        IMAPError.connectionFailed("Connection teardown in progress")
    }

    private func generateCommandTag() -> String {
        let tagPrefix = "A"
        commandTagCounter += 1
        return "\(tagPrefix)\(String(format: "%03d", commandTagCounter))"
    }
}
