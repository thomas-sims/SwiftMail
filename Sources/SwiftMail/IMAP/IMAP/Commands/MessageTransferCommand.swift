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

    enum Terminal: Equatable, Sendable {
        case pending
        case command
        case cancelled
    }

    private let lock = NIOLock()
    private var storedState: State = .notStarted
    private var storedTerminal: Terminal = .pending

    var state: State {
        lock.withLock { storedState }
    }

    var terminal: Terminal {
        lock.withLock { storedTerminal }
    }

    /// Atomically assigns the first handler terminal. Command responses,
    /// transport failures, and timeouts use `.command`; task cancellation uses
    /// `.cancelled`.
    func acceptTerminal(isCancellation: Bool) -> Bool {
        lock.withLock {
            guard storedTerminal == .pending else { return false }
            storedTerminal = isCancellation ? .cancelled : .command
            return true
        }
    }

    func willWrite() -> Bool {
        lock.withLock {
            guard storedTerminal == .pending else { return false }
            storedState = .writeAttempted
            return true
        }
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
        guard dispatchTracker.willWrite() else { return }
        try await channel.writeAndFlush(wrapped).get()
        dispatchTracker.didWrite()
    }
}
