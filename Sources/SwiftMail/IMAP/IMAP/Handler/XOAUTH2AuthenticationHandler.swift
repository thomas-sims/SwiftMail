import Foundation
import Logging
import NIO
import NIOIMAP
import NIOIMAPCore

/// Handler responsible for managing the IMAP XOAUTH2 authentication exchange.
final class XOAUTH2AuthenticationHandler: BaseIMAPCommandHandler<[Capability]>, IMAPCommandHandler, @unchecked Sendable {
    private var collectedCapabilities: [Capability] = []
    private var shouldSendCredentialsOnChallenge: Bool
    private var credentials: ByteBuffer
    private var _observedConnectionTermination = false
    private var _requiresTransportClose = false
    private let authenticationLogger: (any IMAPAuthenticationLogging)?

    var observedConnectionTermination: Bool {
        lock.withLock { _observedConnectionTermination }
    }

    var requiresTransportClose: Bool {
        lock.withLock { _requiresTransportClose }
    }

    init(
        commandTag: String,
        promise: EventLoopPromise<[Capability]>,
        credentials: ByteBuffer,
        expectsChallenge: Bool,
        logger _: Logger,
        authenticationLogger: (any IMAPAuthenticationLogging)? = nil
    ) {
        // SASL-IR puts the initial response on the AUTHENTICATE command, so the
        // handler must not retain a second credential buffer in that mode.
        self.credentials = expectsChallenge ? credentials : ByteBuffer()
        self.shouldSendCredentialsOnChallenge = expectsChallenge
        self.authenticationLogger = authenticationLogger
        super.init(commandTag: commandTag, promise: promise)
    }

    override init(commandTag: String, promise: EventLoopPromise<[Capability]>) {
        fatalError("Use init(commandTag:promise:credentials:expectsChallenge:logger:) instead")
    }

    override func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data)

        if case .authenticationChallenge = response {
            handleAuthenticationChallenge(context: context)
            // The base handler collects otherwise-unhandled responses. Do not
            // pass a challenge through that path or its raw bytes would be
            // retained in `untaggedResponses` for later inspection.
            context.fireChannelRead(data)
            return
        }

        super.channelRead(context: context, data: data)
    }

    private func handleAuthenticationChallenge(context: ChannelHandlerContext) {
        let sendCredentials = lock.withLock { () -> Bool in
            if shouldSendCredentialsOnChallenge {
                shouldSendCredentialsOnChallenge = false
                return true
            }
            return false
        }

        if sendCredentials {
            let credentialBuffer = credentials
            credentials = context.channel.allocator.buffer(capacity: 0)

            observeContinuationWrite(
                context.channel.writeAndFlush(
                    IMAPClientHandler.OutboundIn.part(.continuationResponse(credentialBuffer))
                ),
                context: context
            )
            return
        }

        // A post-credential challenge is server-controlled authentication data.
        // Never decode, stringify, retain, or log it. XOAUTH2 requires an empty
        // continuation response so that the server can send its tagged result.
        let emptyBuffer = context.channel.allocator.buffer(capacity: 0)
        observeContinuationWrite(
            context.channel.writeAndFlush(
                IMAPClientHandler.OutboundIn.part(.continuationResponse(emptyBuffer))
            ),
            context: context
        )
    }

    override func handleTaggedOKResponse(_ response: TaggedResponse) {
        finishAuthenticationLogging()
        let capabilities = lock.withLock { collectedCapabilities }
        if !capabilities.isEmpty {
            succeedWithResult(capabilities)
        } else if case .ok(let responseText) = response.state,
                  let code = responseText.code,
                  case .capability(let caps) = code {
            succeedWithResult(caps)
        } else {
            succeedWithResult([])
        }
    }

    override func handleTaggedErrorResponse(_ response: TaggedResponse) {
        // Tagged response text is server-controlled and can repeat challenge,
        // account, scope, or credential material. Expose one fixed category.
        failAuthentication()
    }

    override func handleError(_ error: Error) {
        // Never propagate a parser/pipeline error because IMAPDecoderError can
        // retain the complete hostile wire buffer.
        failAuthentication(requiresTransportClose: true)
    }

    override func handleUntaggedResponse(_ response: Response) -> Bool {
        if case .untagged(.conditionalState(.bye)) = response {
            lock.withLock { _observedConnectionTermination = true }
            failAuthentication()
            return true
        }

        if case .fatal = response {
            lock.withLock { _observedConnectionTermination = true }
            failAuthentication()
            return true
        }

        switch response {
        case .untagged(.capabilityData(let capabilities)):
            lock.withLock { collectedCapabilities = capabilities }
        default:
            break
        }

        return false
    }

    override func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Swallow the original error instead of forwarding it to an unhandled
        // pipeline logger. Its description or associated buffer may contain raw
        // authentication wire bytes.
        failAuthentication(requiresTransportClose: true)
        context.close(mode: .all, promise: nil)
    }

    override func channelInactive(context: ChannelHandlerContext) {
        failAuthentication()
        context.fireChannelInactive()
    }

    override func handlerRemoved(context: ChannelHandlerContext) {
        finishAuthenticationLogging()
        guard !isCompleted else { return }

        // Removing the response handler mid-exchange leaves the protocol state
        // ambiguous. Fail opaquely and retire that transport.
        failAuthentication(requiresTransportClose: true)
        context.close(mode: .all, promise: nil)
    }

    /// Fixed, opaque terminal result used by timeouts and write/setup failure
    /// paths owned by IMAPConnection. No original Error crosses this boundary.
    @discardableResult
    func failAuthentication(requiresTransportClose: Bool = false) -> Bool {
        if requiresTransportClose {
            lock.withLock { _requiresTransportClose = true }
        }
        finishAuthenticationLogging()
        return failWithError(IMAPError.xoauth2AuthenticationFailed)
    }

    private func observeContinuationWrite(
        _ future: EventLoopFuture<Void>,
        context: ChannelHandlerContext
    ) {
        future.whenFailure { [self] _ in
            failAuthentication(requiresTransportClose: true)
            context.close(mode: .all, promise: nil)
        }
    }

    private func finishAuthenticationLogging() {
        guard let commandTag else { return }
        authenticationLogger?.authenticationDidTerminate(tag: commandTag)
    }
}
