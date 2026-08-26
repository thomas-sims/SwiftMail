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

    init(
        commandTag: String,
        promise: EventLoopPromise<[Capability]>,
        credentials: ByteBuffer,
        expectsChallenge: Bool,
        logger: Logger
    ) {
        // SASL-IR puts the initial response on the AUTHENTICATE command, so the
        // handler must not retain a second credential buffer in that mode.
        self.credentials = expectsChallenge ? credentials : ByteBuffer()
        self.shouldSendCredentialsOnChallenge = expectsChallenge
        super.init(commandTag: commandTag, promise: promise)
    }

    override init(commandTag: String, promise: EventLoopPromise<[Capability]>) {
        fatalError("Use init(commandTag:promise:credentials:expectsChallenge:logger:) instead")
    }

    override func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data)

        if case .authenticationChallenge(var challengeBuffer) = response {
            handleAuthenticationChallenge(&challengeBuffer, context: context)
            // The base handler collects otherwise-unhandled responses. Do not
            // pass a challenge through that path or its raw bytes would be
            // retained in `untaggedResponses` for later inspection.
            context.fireChannelRead(data)
            return
        }

        super.channelRead(context: context, data: data)
    }

    private func handleAuthenticationChallenge(_ challenge: inout ByteBuffer, context: ChannelHandlerContext) {
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

            context.channel
                .writeAndFlush(IMAPClientHandler.OutboundIn.part(.continuationResponse(credentialBuffer)))
                .cascadeFailure(to: promise)
            return
        }

        // A post-credential challenge is server-controlled authentication data.
        // Never decode, stringify, retain, or log it. XOAUTH2 requires an empty
        // continuation response so that the server can send its tagged result.
        let emptyBuffer = context.channel.allocator.buffer(capacity: 0)
        context.channel
            .writeAndFlush(IMAPClientHandler.OutboundIn.part(.continuationResponse(emptyBuffer)))
            .cascadeFailure(to: promise)
    }

    override func handleTaggedOKResponse(_ response: TaggedResponse) {
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
        failWithError(IMAPError.xoauth2AuthenticationFailed)
    }

    override func handleError(_ error: Error) {
        failWithError(error)
    }

    override func handleUntaggedResponse(_ response: Response) -> Bool {
        if super.handleUntaggedResponse(response) {
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
}
