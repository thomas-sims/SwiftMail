import NIO
import NIOConcurrencyHelpers
@preconcurrency import NIOIMAP
import NIOIMAPCore

/// The compact protocol metadata collected before a transfer command's tagged OK.
struct MessageTransferCommandResponse: Sendable {
    let copyUID: ResponseCodeCopy?
    let hasConflictingCopyUID: Bool
}

/// Internal categorical error used to avoid retaining server-controlled text.
enum MessageTransferCommandError: Error, Sendable {
    case serverRejected
    case unsupportedOperation
}

/// Records exactly how far a mutation progressed without changing the generic
/// command executor or its lifecycle/queue behavior.
final class MutationDispatchTracker: @unchecked Sendable {
    enum State: Equatable, Sendable {
        case notStarted
        case writeAttempted
        case writeCompleted
    }

    private let lock = NIOLock()
    private var storedState: State = .notStarted

    var state: State {
        lock.withLock { storedState }
    }

    func willWrite() {
        lock.withLock { storedState = .writeAttempted }
    }

    func didWrite() {
        lock.withLock { storedState = .writeCompleted }
    }
}

protocol IMAPMutationCommand: IMAPTaggedCommand {
    var dispatchTracker: MutationDispatchTracker { get }
}

protocol IMAPCapabilityRequiringCommand {
    var requiredCapability: Capability { get }
}

extension IMAPMutationCommand {
    func send(on channel: Channel, tag: String) async throws {
        let taggedCommand = toTaggedCommand(tag: tag)
        let wrapped = IMAPClientHandler.OutboundIn.part(CommandStreamPart.tagged(taggedCommand))
        dispatchTracker.willWrite()
        try await channel.writeAndFlush(wrapped).get()
        dispatchTracker.didWrite()
    }
}
