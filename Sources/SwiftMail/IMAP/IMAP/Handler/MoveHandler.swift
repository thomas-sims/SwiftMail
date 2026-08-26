// MoveHandler.swift
// Handler for IMAP MOVE command

import Foundation
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers

/** Shared response collector for COPY and MOVE commands. */
class MessageTransferHandler: BaseIMAPCommandHandler<MessageTransferCommandResponse>, @unchecked Sendable {
    private var copyUID: ResponseCodeCopy?
    private var hasConflictingCopyUID = false

    override func handleTaggedOKResponse(_ response: TaggedResponse) {
        if case .ok(let responseText) = response.state {
            recordCOPYUID(from: responseText)
        }

        let result = lock.withLock {
            MessageTransferCommandResponse(
                copyUID: copyUID,
                hasConflictingCopyUID: hasConflictingCopyUID
            )
        }
        succeedWithResult(result)
    }

    override func handleTaggedErrorResponse(_ response: TaggedResponse) {
        failWithError(MessageTransferCommandError.serverRejected)
    }

    override func handleUntaggedResponse(_ response: Response) -> Bool {
        if case .untagged(.conditionalState(.ok(let responseText))) = response {
            recordCOPYUID(from: responseText)
        }
        return super.handleUntaggedResponse(response)
    }

    private func recordCOPYUID(from responseText: ResponseText) {
        guard case .uidCopy(let candidate)? = responseText.code else { return }
        lock.withLock {
            if let copyUID {
                if copyUID != candidate {
                    hasConflictingCopyUID = true
                }
            } else {
                copyUID = candidate
            }
        }
    }
}

/** Handler for IMAP MOVE command. */
final class MoveHandler: MessageTransferHandler, IMAPCommandHandler, @unchecked Sendable {
    typealias ResultType = MessageTransferCommandResponse
}
