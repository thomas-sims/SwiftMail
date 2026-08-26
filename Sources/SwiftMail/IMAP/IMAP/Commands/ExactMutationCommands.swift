import NIO
@preconcurrency import NIOIMAP
import NIOIMAPCore

/// Marks an exact UID set as deleted without requesting unsolicited FETCH data.
struct UIDStoreDeletedCommand: IMAPMutationCommand {
    typealias ResultType = Void
    typealias HandlerType = ExactMutationHandler

    let identifierSet: UIDSet
    let dispatchTracker = MutationDispatchTracker()
    let timeoutSeconds: Int

    init(identifierSet: UIDSet, timeoutSeconds: Int = 5) {
        self.identifierSet = identifierSet
        self.timeoutSeconds = timeoutSeconds
    }

    func validate() throws {
        try identifierSet.validateMutationUIDs()
    }

    func toTaggedCommand(tag: String) -> TaggedCommand {
        let data = StoreData.flags([.deleted], .add, silent: true)
        return TaggedCommand(
            tag: tag,
            command: .uidStore(.set(identifierSet.toNIOSet()), [], data.toNIO())
        )
    }
}

/// Permanently removes only the specified UIDs under RFC 4315 UIDPLUS.
struct UIDExpungeCommand: IMAPMutationCommand, IMAPCapabilityRequiringCommand {
    typealias ResultType = Void
    typealias HandlerType = ExactMutationHandler

    let identifierSet: UIDSet
    let dispatchTracker = MutationDispatchTracker()
    let requiredCapability: Capability = .uidPlus
    let timeoutSeconds: Int

    init(identifierSet: UIDSet, timeoutSeconds: Int = 5) {
        self.identifierSet = identifierSet
        self.timeoutSeconds = timeoutSeconds
    }

    func validate() throws {
        try identifierSet.validateMutationUIDs()
    }

    func toTaggedCommand(tag: String) -> TaggedCommand {
        TaggedCommand(
            tag: tag,
            command: .uidExpunge(.set(identifierSet.toNIOSet()))
        )
    }
}

private extension MessageIdentifierSet where Identifier == UID {
    func validateMutationUIDs() throws {
        guard !isEmpty else {
            throw IMAPError.emptyIdentifierSet
        }
        guard ranges.allSatisfy({
            $0.lowerBound > 0 && $0.upperBound <= Int(UInt32.max)
        }) else {
            throw IMAPError.invalidArgument("UIDs must be valid non-zero 32-bit values")
        }
    }
}
