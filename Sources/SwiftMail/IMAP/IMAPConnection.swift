import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers
import NIOSSL

/// Internal connection wrapper used by IMAPServer to manage per-connection state.
final class IMAPConnection {
    typealias ConnectOverride = (@escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> EventLoopFuture<Channel>
    typealias TLSHandlerFactory = @Sendable (NIOSSLContext, String?) throws -> ChannelHandler
    typealias CandidateLoggerFactory = @Sendable (Channel) -> IMAPLogger
    typealias CandidateResponseBufferFactory = @Sendable (Channel) -> UntaggedResponseBuffer

    struct ConnectionTarget: Equatable, Sendable {
        let connectionHost: String
        let tlsServerHostname: String?
    }

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

    private final class OwnedTransport: @unchecked Sendable {
        let channel: Channel
        let duplexLogger: IMAPLogger
        let responseBuffer: UntaggedResponseBuffer
        let loggerInstallationPromise: EventLoopPromise<Void>
        let responseBufferInstallationPromise: EventLoopPromise<Void>

        private struct InstallationState {
            var loggerStarted = false
            var responseBufferStarted = false
        }

        private let installationState = NIOLockedValueBox(InstallationState())

        init(
            channel: Channel,
            duplexLogger: IMAPLogger,
            responseBuffer: UntaggedResponseBuffer
        ) {
            self.channel = channel
            self.duplexLogger = duplexLogger
            self.responseBuffer = responseBuffer
            self.loggerInstallationPromise = channel.eventLoop.makePromise(of: Void.self)
            self.responseBufferInstallationPromise = channel.eventLoop.makePromise(of: Void.self)
        }

        func claimLoggerInstallation() -> Bool {
            installationState.withLockedValue { state in
                guard !state.loggerStarted else { return false }
                state.loggerStarted = true
                return true
            }
        }

        func claimResponseBufferInstallation() -> Bool {
            installationState.withLockedValue { state in
                guard !state.responseBufferStarted else { return false }
                state.responseBufferStarted = true
                return true
            }
        }
    }

    private struct OwnedTransportRegistration {
        let transport: OwnedTransport
        let wasInserted: Bool
        let shouldClose: Bool
    }

    private struct LifecycleState {
        /// Channel and logger authority are adopted atomically. A logger from a
        /// losing Happy-Eyeballs candidate can never become the command logger.
        var adoptedTransport: OwnedTransport?
        /// Every channel created for this connection, including Happy-Eyeballs
        /// candidates that have not won yet and channels that are closing.
        /// Entries are removed only by their `closeFuture` callback.
        var ownedTransports: [ObjectIdentifier: OwnedTransport] = [:]
        var pendingConnect: PendingConnect?
        var isRetired = false
        /// A recoverable generation fence. Unlike `isRetired`, this is cleared
        /// only after graceful teardown has joined the old connect attempt and
        /// closed all of its transports.
        var isGracefulDisconnectInProgress = false
        var idleHandler: IdleHandler?
        var idleTransport: OwnedTransport?
        var idleTerminationInProgress = false
        var capabilities: Set<NIOIMAPCore.Capability> = []
    }

    private let host: String
    private let port: Int
    private let group: EventLoopGroup
    private let connectOverride: ConnectOverride?
    private let tlsHandlerFactory: TLSHandlerFactory
    private let candidateLoggerFactory: CandidateLoggerFactory
    private let candidateResponseBufferFactory: CandidateResponseBufferFactory
    private let lifecycleState = NIOLockedValueBox(LifecycleState())
    private var commandTagCounter: Int = 0
    private let commandQueue = IMAPCommandQueue()

    private let logger: Logging.Logger

    init(
        host: String,
        port: Int,
        group: EventLoopGroup,
        loggerLabel: String,
        outboundLabel: String,
        inboundLabel: String,
        connectOverride: ConnectOverride? = nil,
        tlsHandlerFactory: TLSHandlerFactory? = nil,
        candidateLoggerFactory: CandidateLoggerFactory? = nil,
        candidateResponseBufferFactory: CandidateResponseBufferFactory? = nil
    ) {
        self.host = host
        self.port = port
        self.group = group
        self.connectOverride = connectOverride
        self.tlsHandlerFactory = tlsHandlerFactory ?? { context, serverHostname in
            try NIOSSLClientHandler(context: context, serverHostname: serverHostname)
        }
        self.candidateLoggerFactory = candidateLoggerFactory ?? { _ in
            IMAPLogger(
                outboundLogger: Logging.Logger(label: outboundLabel),
                inboundLogger: Logging.Logger(label: inboundLabel)
            )
        }
        self.candidateResponseBufferFactory = candidateResponseBufferFactory ?? { _ in
            UntaggedResponseBuffer()
        }

        self.logger = Logging.Logger(label: loggerLabel)
    }

    var isConnected: Bool {
        lifecycleState.withLockedValue { state in
            state.adoptedTransport?.channel.isActive ?? false
        }
    }

    var capabilitiesSnapshot: Set<NIOIMAPCore.Capability> {
        lifecycleState.withLockedValue { $0.capabilities }
    }

    func supportsCapability(_ check: (Capability) -> Bool) -> Bool {
        capabilitiesSnapshot.contains(where: check)
    }

    func connect() async throws {
        try ensureNotRetired()
        try await closeLingeringTransportsBeforeConnect()
        try ensureNotRetired()

        let target = try Self.connectionTarget(for: host)
        let sslContext = try NIOSSLContext(configuration: Self.makeTLSConfiguration())

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
            guard state.adoptedTransport == nil else {
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
        let candidateLoggerFactory = self.candidateLoggerFactory
        let candidateResponseBufferFactory = self.candidateResponseBufferFactory
        let createAndRegisterCandidate: @Sendable (Channel) -> OwnedTransportRegistration = { channel in
            Self.registerOwnedChannel(
                channel,
                candidateLoggerFactory: candidateLoggerFactory,
                candidateResponseBufferFactory: candidateResponseBufferFactory,
                connectAttemptID: connectAttemptID,
                lifecycleState: lifecycleState
            )
        }
        let registerChannel: @Sendable (Channel) -> EventLoopFuture<Void> = { channel in
            let registration = createAndRegisterCandidate(channel)
            return Self.installCandidateLoggerIfNeeded(registration)
        }

        let connectFuture: EventLoopFuture<Channel>
        if let connectOverride {
            connectFuture = connectOverride(registerChannel)
        } else {
            let tlsHandlerFactory = self.tlsHandlerFactory
            connectFuture = ClientBootstrap(group: group)
                // Make the NIO-owned Happy-Eyeballs attempt explicitly bounded.
                // Hard abort additionally closes every candidate surfaced through
                // the initializer and awaits this underlying future.
                .connectTimeout(.seconds(10))
                .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
                .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
                .channelInitializer { channel in
                    // SwiftNIO may invoke this initializer for multiple
                    // Happy-Eyeballs candidates. Every candidate must own a
                    // distinct stateful logger instance.
                    let registration = createAndRegisterCandidate(channel)
                    let transport = registration.transport

                    let accepted = lifecycleState.withLockedValue { state in
                        !state.isRetired
                            && !state.isGracefulDisconnectInProgress
                            && state.pendingConnect?.id == connectAttemptID
                    }
                    guard accepted else {
                        if transport.claimLoggerInstallation() {
                            transport.loggerInstallationPromise.fail(
                                Self.currentTeardownError(lifecycleState: lifecycleState)
                            )
                        }
                        return channel.close(mode: .all).flatMapThrowing {
                            throw Self.currentTeardownError(lifecycleState: lifecycleState)
                        }
                    }

                    guard transport.claimLoggerInstallation() else {
                        return transport.loggerInstallationPromise.futureResult
                    }

                    do {
                        let sslHandler = try tlsHandlerFactory(sslContext, target.tlsServerHostname)

                        let parserOptions = ResponseParser.Options(
                            bufferLimit: 1024 * 1024,
                            messageAttributeLimit: .max,
                            bodySizeLimit: .max,
                            literalSizeLimit: IMAPDefaults.literalSizeLimit
                        )

                        try channel.pipeline.syncOperations.addHandlers([
                            sslHandler,
                            IMAPClientHandler(parserOptions: parserOptions),
                            transport.duplexLogger
                        ])
                        transport.loggerInstallationPromise.succeed(())

                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        transport.loggerInstallationPromise.fail(error)
                        // Channel-initializer failures must fail the bootstrap future.
                        // Never crash or fall back to plaintext/permissive TLS.
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
                .connect(host: target.connectionHost, port: port)
        }

        connectFuture.whenComplete { result in
            Self.completePendingConnect(pendingConnect, with: result, lifecycleState: lifecycleState)
        }
        pendingConnect.completeTransportHandoff(with: .success(connectFuture))

        var adoptedChannel: Channel?
        do {
            let channel = try await pendingConnect.promise.futureResult.get()
            adoptedChannel = channel

            guard let adoptedTransport = currentTransport,
                  adoptedTransport.channel === channel else {
                throw IMAPError.connectionFailed("Adopted transport authority was lost")
            }

            // Add this generation's persistent untagged response buffer as the
            // LAST handler in the adopted pipeline. Transient command handlers
            // are added before this exact buffer. Candidate buffers are created
            // at reservation time but never installed on losing pipelines.
            // channelRead flows first→last, so: command handler processes response → calls
            // fireChannelRead → buffer sees it. When no command handler is active, responses
            // flow directly to the buffer which captures them for later draining.
            try await Self.installResponseBufferIfNeeded(on: adoptedTransport).get()

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
        lifecycleState.withLockedValue { $0.capabilities = Set(serverCapabilities) }
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
        guard capabilitiesSnapshot.contains(.id) else {
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
            return (state.idleHandler, state.idleTransport, shouldSendDone)
        }

        guard let handler = snapshot.0 else {
            logger.debug("No active IDLE session, skipping DONE command")
            return
        }

        // Only the caller that claimed the termination marker may retire this
        // IDLE generation. Duplicate callers merely observe its shared result.
        defer {
            if snapshot.2 {
                let didResetMatchingIdle = lifecycleState.withLockedValue { state in
                    guard state.idleHandler === handler else { return false }
                    state.idleHandler = nil
                    state.idleTransport = nil
                    state.idleTerminationInProgress = false
                    return true
                }
                if didResetMatchingIdle {
                    snapshot.1?.responseBuffer.hasActiveHandler = false
                }
            }
        }

        guard let transport = snapshot.1 else {
            handler.abort()
            // An already-failed shared handler keeps its original terminal
            // error; a genuinely missing transport fails every waiter instead
            // of making one caller silently report success.
            return try await handler.promise.futureResult.get()
        }
        let channel = transport.channel
        let responseBuffer = transport.responseBuffer

        // The caller that atomically installed the termination marker owns the
        // sole DONE write. Every duplicate joins the same tagged-response promise.
        if snapshot.2 {
            let writePromise = channel.eventLoop.makePromise(of: Void.self)
            writePromise.futureResult.whenFailure { error in
                // Publish the write failure on its event loop before a close from
                // the same outbound turn can reach IdleHandler.channelInactive.
                // IdleHandler's exactly-once gate preserves a genuinely earlier
                // hard-abort or disconnect result.
                handler.abort(error: error)
            }

            do {
                channel.writeAndFlush(
                    IMAPClientHandler.OutboundIn.part(.idleDone),
                    promise: writePromise
                )
                try await writePromise.futureResult.get()
            } catch {
                // A failed DONE write leaves the protocol state ambiguous. Exact
                // result ordering was established by the event-loop callback above;
                // now remove the matching handler and close/await the transport.

                if lifecycleState.withLockedValue({ $0.idleHandler === handler }) {
                    responseBuffer.hasActiveHandler = false
                }

                try? await channel.pipeline.removeHandler(handler)
                channel.close(mode: .all, promise: nil)
                try? await channel.closeFuture.get()
            }
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
        guard let transport = currentTransport else { return [] }
        let events = transport.responseBuffer.drainServerEvents(logger: logger)
        return lifecycleState.withLockedValue { state in
            state.adoptedTransport === transport ? events : []
        }
    }

    func disconnect() async throws {
        let snapshot = lifecycleState.withLockedValue { state -> (didBegin: Bool, transports: [OwnedTransport], pendingConnect: PendingConnect?) in
            guard !state.isRetired else { return (false, [], nil) }
            guard !state.isGracefulDisconnectInProgress else { return (false, [], state.pendingConnect) }

            state.isGracefulDisconnectInProgress = true
            state.adoptedTransport = nil
            return (true, Array(state.ownedTransports.values), state.pendingConnect)
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

        if snapshot.transports.isEmpty, snapshot.pendingConnect == nil {
            logger.warning("Attempted to disconnect when channel was already nil")
        }

        for transport in snapshot.transports {
            transport.responseBuffer.hasActiveHandler = false
            transport.channel.close(mode: CloseMode.all, promise: nil)
        }
        var firstCloseError: Error?
        for transport in snapshot.transports {
            do {
                try await transport.channel.closeFuture.get()
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

        lifecycleState.withLockedValue { state in
            if state.pendingConnect?.id == snapshot.pendingConnect?.id {
                state.pendingConnect = nil
            }
            state.capabilities = []
            state.isGracefulDisconnectInProgress = false
        }

        if let firstCloseError { throw firstCloseError }
    }

    /// Permanently retire this connection and immediately tear down its transport.
    /// No DONE or LOGOUT command is sent, and future commands cannot reconnect it.
    func hardAbort() async {
        let snapshot = lifecycleState.withLockedValue { state -> (didRetire: Bool, transports: [OwnedTransport], idleHandler: IdleHandler?, pendingConnect: PendingConnect?) in
            let didRetire = !state.isRetired
            state.isRetired = true
            let idleHandler = state.idleHandler
            state.adoptedTransport = nil
            state.idleHandler = nil
            state.idleTransport = nil
            state.idleTerminationInProgress = false
            return (didRetire, Array(state.ownedTransports.values), idleHandler, state.pendingConnect)
        }

        await commandQueue.abort()
        for transport in snapshot.transports {
            transport.responseBuffer.hasActiveHandler = false
        }
        snapshot.idleHandler?.abort()
        if snapshot.didRetire {
            snapshot.pendingConnect?.completeChannel(with: .failure(Self.abortedError))
        }

        // Close every channel the bootstrap has surfaced, including losing
        // Happy-Eyeballs candidates and channels already in graceful teardown.
        // Issue all closes before awaiting any one close so one slow transport
        // cannot postpone retirement of its siblings.
        for transport in snapshot.transports {
            transport.channel.close(mode: CloseMode.all, promise: nil)
        }
        for transport in snapshot.transports {
            try? await transport.channel.closeFuture.get()
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

    static func connectionTarget(for host: String) throws -> ConnectionTarget {
        // NIO's Darwin parser accepts scoped IPv6 spellings but its
        // SocketAddress(ipAddress:) initializer does not preserve a scope ID.
        // Reject them rather than silently connecting to a different interface.
        guard !host.contains("%") else {
            throw IMAPError.invalidArgument("Scoped IP literals are not supported as IMAP hosts")
        }

        if (try? SocketAddress(ipAddress: host, port: 0)) != nil {
            return ConnectionTarget(connectionHost: host, tlsServerHostname: nil)
        }

        // ClientBootstrap expects a raw IPv6 address, while operators may enter
        // the bracketed URI representation. Accept exactly one balanced pair
        // only when its contents are a strict IPv6 literal, and normalize only
        // the connection host. IPv4/DNS/scoped or malformed bracket forms are
        // rejected instead of being misclassified as DNS/SNI names.
        if host.contains("[") || host.contains("]") {
            guard host.first == "[", host.last == "]" else {
                throw IMAPError.invalidArgument("Invalid bracketed IMAP host")
            }

            let inner = String(host.dropFirst().dropLast())
            guard !inner.contains("["), !inner.contains("]"),
                  let address = try? SocketAddress(ipAddress: inner, port: 0),
                  case .v6 = address else {
                throw IMAPError.invalidArgument("Invalid bracketed IMAP host")
            }

            return ConnectionTarget(connectionHost: inner, tlsServerHostname: nil)
        }

        // A colon-bearing unbracketed value can only be an IPv6 literal in this
        // API. If strict numeric parsing rejected it, fail locally rather than
        // passing malformed input into DNS/TLS hostname handling.
        guard !host.contains(":") else {
            throw IMAPError.invalidArgument("Invalid unbracketed IMAP host")
        }

        // Classification is deliberately non-resolving. A value that is not a
        // strict numeric literal remains a DNS name and retains SNI/hostname
        // verification; it is never treated as an IP because it happens to
        // resolve to one.
        return ConnectionTarget(connectionHost: host, tlsServerHostname: host)
    }

    static func makeTLSConfiguration() -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .fullVerification
        return configuration
    }

    private func refreshCapabilities(using reportedCapabilities: [Capability]) async throws {
        if !reportedCapabilities.isEmpty {
            lifecycleState.withLockedValue { $0.capabilities = Set(reportedCapabilities) }
        } else {
            try await fetchCapabilities()
        }
    }

    private func authenticateXOAUTH2Body(email: String, accessToken: String) async throws {
        try ensureNotRetired()

        let mechanism = AuthenticationMechanism("XOAUTH2")
        let xoauthCapability = Capability.authenticate(mechanism)
        let advertisedCapabilities = capabilitiesSnapshot

        guard advertisedCapabilities.contains(xoauthCapability) else {
            throw IMAPError.unsupportedAuthMechanism("XOAUTH2 not advertised by server")
        }

        try await waitForIdleCompletionIfNeeded()

        clearInvalidChannel()

        if currentTransport == nil {
            logger.info("Channel is nil, re-establishing connection before authentication")
            try await connect()
        }

        guard let transport = currentTransport else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }
        let channel = transport.channel
        let duplexLogger = transport.duplexLogger
        let responseBuffer = transport.responseBuffer

        let expectsChallenge = !advertisedCapabilities.contains(.saslIR)
        let tag = generateCommandTag()

        let handlerPromise = channel.eventLoop.makePromise(of: [Capability].self)
        let credentialBuffer = makeXOAUTH2InitialResponseBuffer(email: email, accessToken: accessToken)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: tag,
            promise: handlerPromise,
            credentials: credentialBuffer,
            expectsChallenge: expectsChallenge,
            logger: logger,
            authenticationLogger: duplexLogger
        )

        do {
            try await channel.pipeline.addHandler(handler, position: .before(responseBuffer)).get()
        } catch {
            // A pipeline setup failure is not allowed to expose its raw error
            // through the authentication API or leave a possibly corrupt
            // transport eligible for reuse.
            handler.failAuthentication(requiresTransportClose: true)
            channel.close(mode: .all, promise: nil)
            try? await channel.closeFuture.get()
            clearInvalidChannel()
            throw IMAPError.xoauth2AuthenticationFailed
        }
        responseBuffer.hasActiveHandler = true

        let initialResponse = expectsChallenge ? nil : InitialResponse(credentialBuffer)

        let command = TaggedCommand(tag: tag, command: .authenticate(mechanism: mechanism, initialResponse: initialResponse))
        let wrapped = IMAPClientHandler.OutboundIn.part(CommandStreamPart.tagged(command))

        let authenticationTimeoutSeconds = 10
        let logger = self.logger
        let scheduledTask = group.next().scheduleTask(in: .seconds(Int64(authenticationTimeoutSeconds))) {
            logger.warning("XOAUTH2 authentication timed out after \(authenticationTimeoutSeconds) seconds")
            handler.failAuthentication(requiresTransportClose: true)
            channel.close(mode: .all, promise: nil)
        }

        do {
            do {
                try await channel.writeAndFlush(wrapped).get()
            } catch {
                // The original write error can carry channel/parser details and
                // the command outcome is protocol-ambiguous. Publish only the
                // fixed auth failure and retire the transport.
                handler.failAuthentication(requiresTransportClose: true)
                channel.close(mode: .all, promise: nil)
            }
            let refreshedCapabilities = try await handlerPromise.futureResult.get()

            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            if handler.observedConnectionTermination {
                try? await disconnect()
            }
            duplexLogger.flushInboundBuffer()

            try await refreshCapabilities(using: refreshedCapabilities)
        } catch {
            scheduledTask.cancel()
            responseBuffer.hasActiveHandler = false
            if handler.requiresTransportClose {
                channel.close(mode: .all, promise: nil)
                try? await channel.closeFuture.get()
                clearInvalidChannel()
            } else if handler.observedConnectionTermination {
                try? await disconnect()
            }
            duplexLogger.flushInboundBuffer()

            try? await channel.pipeline.removeHandler(handler)

            // Handler-owned auth failures are always the fixed category. The
            // only other reachable error here is post-auth capability refresh,
            // which occurs after the do-block's handler result has succeeded.
            throw error
        }
    }

    func startIdleSession(continuation: AsyncStream<IMAPServerEvent>.Continuation) async throws {
        try ensureNotRetired()

        if !capabilitiesSnapshot.contains(.idle) {
            throw IMAPError.commandNotSupported("IDLE command not supported by server")
        }

        let hasIdleHandler = lifecycleState.withLockedValue { state in
            state.idleHandler != nil
        }
        guard !hasIdleHandler else {
            throw IMAPError.commandFailed("IDLE session already active")
        }

        guard let transport = currentTransport else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }
        let channel = transport.channel
        let responseBuffer = transport.responseBuffer

        let promise = channel.eventLoop.makePromise(of: Void.self)
        let tag = generateCommandTag()
        let handler = IdleHandler(commandTag: tag, promise: promise, continuation: continuation)
        let registered = lifecycleState.withLockedValue { state in
            guard !state.isRetired,
                  state.idleHandler == nil,
                  state.adoptedTransport === transport else {
                return false
            }
            state.idleTerminationInProgress = false
            state.idleHandler = handler
            state.idleTransport = transport
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
                    state.idleTransport = nil
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

        if currentTransport == nil {
            logger.info("Channel is nil, re-establishing connection before sending command")
            try await connect()
        }

        guard let transport = currentTransport else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }
        let channel = transport.channel
        let duplexLogger = transport.duplexLogger
        let responseBuffer = transport.responseBuffer

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

        if currentTransport == nil {
            logger.info("Channel is nil, re-establishing connection before executing handler")
            try await connect()
        }

        guard let transport = currentTransport else {
            throw IMAPError.connectionFailed("Channel not initialized")
        }
        let channel = transport.channel
        let duplexLogger = transport.duplexLogger
        let responseBuffer = transport.responseBuffer

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
            if let transport = state.adoptedTransport, !transport.channel.isActive {
                state.adoptedTransport = nil
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
        candidateLoggerFactory: CandidateLoggerFactory,
        candidateResponseBufferFactory: CandidateResponseBufferFactory,
        connectAttemptID: UUID? = nil,
        lifecycleState: NIOLockedValueBox<LifecycleState>
    ) -> OwnedTransportRegistration {
        let identifier = ObjectIdentifier(channel)
        let registration = lifecycleState.withLockedValue { state -> OwnedTransportRegistration in
            if let existing = state.ownedTransports[identifier] {
                return OwnedTransportRegistration(
                    transport: existing,
                    wasInserted: false,
                    shouldClose: false
                )
            }

            // These private factories allocate handlers only and must not
            // re-enter IMAPConnection. Creating them inside the lifecycle lock
            // makes duplicate/concurrent reservation exactly once before any
            // factory side effect or pipeline installation.
            let transport = OwnedTransport(
                channel: channel,
                duplexLogger: candidateLoggerFactory(channel),
                responseBuffer: candidateResponseBufferFactory(channel)
            )
            state.ownedTransports[identifier] = transport

            let shouldClose: Bool
            guard !state.isRetired, !state.isGracefulDisconnectInProgress else {
                return OwnedTransportRegistration(
                    transport: transport,
                    wasInserted: true,
                    shouldClose: true
                )
            }
            if let connectAttemptID {
                shouldClose = state.pendingConnect?.id != connectAttemptID
            } else {
                shouldClose = false
            }
            return OwnedTransportRegistration(
                transport: transport,
                wasInserted: true,
                shouldClose: shouldClose
            )
        }

        if registration.wasInserted {
            let transport = registration.transport
            channel.closeFuture.whenComplete { _ in
                transport.responseBuffer.hasActiveHandler = false
                _ = transport.responseBuffer.drainBuffer()
                // Losing candidates never install an adopted response buffer.
                // Resolve both setup promises on transport retirement so no
                // unused generation leaves a pending promise behind.
                if transport.claimLoggerInstallation() {
                    transport.loggerInstallationPromise.fail(ChannelError.ioOnClosedChannel)
                }
                if transport.claimResponseBufferInstallation() {
                    transport.responseBufferInstallationPromise.fail(ChannelError.ioOnClosedChannel)
                }
                let retiredIdleHandler = lifecycleState.withLockedValue { state -> IdleHandler? in
                    if state.ownedTransports[identifier] === transport {
                        state.ownedTransports.removeValue(forKey: identifier)
                    }
                    if state.adoptedTransport === transport {
                        state.adoptedTransport = nil
                    }
                    if state.idleTransport === transport {
                        let idleHandler = state.idleHandler
                        state.idleHandler = nil
                        state.idleTransport = nil
                        state.idleTerminationInProgress = false
                        return idleHandler
                    }
                    return nil
                }
                retiredIdleHandler?.abort()
            }
        }

        if registration.shouldClose {
            if registration.transport.claimLoggerInstallation() {
                registration.transport.loggerInstallationPromise.fail(
                    Self.currentTeardownError(lifecycleState: lifecycleState)
                )
            }
            channel.close(mode: CloseMode.all, promise: nil)
        }
        return registration
    }

    private static func installCandidateLoggerIfNeeded(
        _ registration: OwnedTransportRegistration
    ) -> EventLoopFuture<Void> {
        let transport = registration.transport
        guard !registration.shouldClose else {
            return transport.loggerInstallationPromise.futureResult
        }

        if transport.claimLoggerInstallation() {
            let installation = transport.channel.pipeline.addHandler(transport.duplexLogger)
            installation.cascade(to: transport.loggerInstallationPromise)
            installation.whenFailure { _ in
                transport.channel.close(mode: .all, promise: nil)
            }
        }
        return transport.loggerInstallationPromise.futureResult
    }

    private static func installResponseBufferIfNeeded(
        on transport: OwnedTransport
    ) -> EventLoopFuture<Void> {
        if transport.claimResponseBufferInstallation() {
            let installation = transport.channel.pipeline.addHandler(transport.responseBuffer)
            installation.cascade(to: transport.responseBufferInstallationPromise)
            installation.whenFailure { _ in
                transport.channel.close(mode: .all, promise: nil)
            }
        }
        return transport.responseBufferInstallationPromise.futureResult
    }

    /// An inactive channel is not fully retired until NIO has run deferred
    /// handler removal and completed `closeFuture`. Never let an automatic or
    /// direct reconnect overlap those old generation handlers.
    private func closeLingeringTransportsBeforeConnect() async throws {
        while true {
            let snapshot = lifecycleState.withLockedValue { state -> (transports: [OwnedTransport], idleHandler: IdleHandler?) in
                guard state.pendingConnect == nil,
                      !state.isGracefulDisconnectInProgress else {
                    return ([], nil)
                }

                if let adopted = state.adoptedTransport {
                    guard !adopted.channel.isActive else { return ([], nil) }
                    state.adoptedTransport = nil

                    if state.idleTransport === adopted {
                        let idleHandler = state.idleHandler
                        state.idleHandler = nil
                        state.idleTransport = nil
                        state.idleTerminationInProgress = false
                        return (Array(state.ownedTransports.values), idleHandler)
                    }
                }
                return (Array(state.ownedTransports.values), nil)
            }
            snapshot.idleHandler?.abort()
            guard !snapshot.transports.isEmpty else { return }

            for transport in snapshot.transports {
                transport.responseBuffer.hasActiveHandler = false
                transport.channel.close(mode: .all, promise: nil)
            }
            for transport in snapshot.transports {
                try? await transport.channel.closeFuture.get()
            }

            try ensureNotRetired()
        }
    }

    private func closeRemainingOwnedChannels() async {
        while true {
            let transports = lifecycleState.withLockedValue { Array($0.ownedTransports.values) }
            guard !transports.isEmpty else { return }

            for transport in transports {
                transport.responseBuffer.hasActiveHandler = false
                transport.channel.close(mode: CloseMode.all, promise: nil)
            }
            for transport in transports {
                try? await transport.channel.closeFuture.get()
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
                guard let registered = state.ownedTransports[ObjectIdentifier(channel)],
                      registered.channel === channel else {
                    return IMAPError.connectionFailed("Connected channel was not registered")
                }
                state.adoptedTransport = registered
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
                      let registered = state.ownedTransports[ObjectIdentifier(channel)],
                      state.adoptedTransport === registered else {
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
            guard let adoptedChannel,
                  let registered = state.ownedTransports[ObjectIdentifier(adoptedChannel)],
                  state.adoptedTransport === registered else { return nil }
            state.adoptedTransport = nil
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
        lifecycleState.withLockedValue { $0.ownedTransports.count }
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
        currentTransport?.responseBuffer.hasActiveHandler ?? false
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
        let duplexLogger = try await prepareCandidateChannel(channel)
        guard let registered = lifecycleState.withLockedValue({
            $0.ownedTransports[ObjectIdentifier(channel)]
        }), registered.channel === channel,
           registered.duplexLogger === duplexLogger else {
            channel.close(mode: .all, promise: nil)
            throw Self.abortedError
        }

        try await Self.installResponseBufferIfNeeded(on: registered).get()

        let adopted = lifecycleState.withLockedValue { state -> Bool in
            guard !state.isRetired, !state.isGracefulDisconnectInProgress else { return false }
            guard state.ownedTransports[ObjectIdentifier(channel)] === registered else {
                return false
            }
            state.adoptedTransport = registered
            // Prepared-channel setup can be invoked concurrently by tests and
            // deterministic embedders. Publish its generation metadata at the
            // same serialized adoption boundary instead of racing readers or
            // duplicate writers after the transport has become visible.
            state.capabilities = capabilities
            return true
        }
        guard adopted else {
            channel.close(mode: .all, promise: nil)
            throw Self.abortedError
        }
    }

    /// Installs the exact per-candidate logger used by the production bootstrap
    /// without adopting the channel. Internal for deterministic Happy-Eyeballs
    /// ownership tests and prepared-channel callers.
    @discardableResult
    func prepareCandidateChannel(_ channel: Channel) async throws -> IMAPLogger {
        let registration = Self.registerOwnedChannel(
            channel,
            candidateLoggerFactory: candidateLoggerFactory,
            candidateResponseBufferFactory: candidateResponseBufferFactory,
            lifecycleState: lifecycleState
        )
        try await Self.installCandidateLoggerIfNeeded(registration).get()
        return registration.transport.duplexLogger
    }

    private var currentChannel: Channel? {
        currentTransport?.channel
    }

    private var currentTransport: OwnedTransport? {
        lifecycleState.withLockedValue { $0.adoptedTransport }
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
