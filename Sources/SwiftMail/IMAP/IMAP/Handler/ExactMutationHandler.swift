import NIOIMAPCore

/// Fixed-data handler for exact destructive mutations. Server-controlled
/// response text is never retained in the surfaced error.
final class ExactMutationHandler: BaseIMAPCommandHandler<Void>, IMAPCommandHandler, @unchecked Sendable {
    override func handleTaggedOKResponse(_ response: TaggedResponse) {
        succeedWithResult(())
    }

    override func handleTaggedErrorResponse(_ response: TaggedResponse) {
        failWithError(MessageTransferCommandError.serverRejected)
    }
}
