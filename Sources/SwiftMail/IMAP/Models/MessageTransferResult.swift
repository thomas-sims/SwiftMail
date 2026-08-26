import Foundation
import NIOIMAPCore

/// A compact UID-to-UID mapping returned by a successful IMAP COPY or MOVE.
///
/// Ranges retain the ordering supplied by the server because each source UID
/// corresponds positionally to a destination UID. Large ranges are never
/// expanded into individual identifiers.
public struct UIDMapping: Hashable, Sendable {
    /// An inclusive, non-empty UID range.
    public struct Range: Hashable, Sendable {
        public let lowerBound: UID
        public let upperBound: UID

        /// The number of UIDs represented by this range.
        public var count: UInt64 {
            UInt64(upperBound.value) - UInt64(lowerBound.value) + 1
        }

        init(lowerBound: UID, upperBound: UID) {
            self.lowerBound = lowerBound
            self.upperBound = upperBound
        }
    }

    /// UIDVALIDITY for the destination mailbox containing the copied messages.
    public let destinationUIDValidity: UIDValidity

    /// Ordered source UID ranges from COPYUID.
    public let sourceRanges: [Range]

    /// Ordered destination UID ranges from COPYUID.
    public let destinationRanges: [Range]

    /// The total number of messages represented by both range arrays.
    public let messageCount: UInt64

    init(
        destinationUIDValidity: UIDValidity,
        sourceRanges: [Range],
        destinationRanges: [Range],
        messageCount: UInt64
    ) {
        self.destinationUIDValidity = destinationUIDValidity
        self.sourceRanges = sourceRanges
        self.destinationRanges = destinationRanges
        self.messageCount = messageCount
    }
}

/// The typed outcome of a COPY or native MOVE command that completed with OK.
public enum MessageTransferResult: Hashable, Sendable {
    /// The server supplied a valid, source-proven COPYUID mapping.
    case completed(UIDMapping)

    /// The command completed, but its destination identity must be reconciled
    /// before the caller can safely make another destructive or duplicate-prone
    /// mutation.
    case completedRequiringReconciliation(ReconciliationReason)

    public enum ReconciliationReason: Hashable, Sendable {
        /// No COPYUID response code was supplied.
        case mappingUnavailable

        /// COPYUID data was structurally invalid or had unequal cardinality.
        case mappingMalformed

        /// Multiple COPYUID response codes disagreed.
        case conflictingMappings

        /// A UID COPYUID mapping cannot prove the identity of a sequence-number request.
        case sourceIdentityUnprovable

        /// The COPYUID source set did not exactly equal the requested UID set.
        case requestedSourceMismatch
    }
}

/// A categorized COPY or MOVE failure with an explicit retry-safety boundary.
///
/// This error intentionally does not retain server response text or transport
/// errors, which may contain private mailbox or authentication data.
public struct IMAPMutationFailure: Error, Hashable, Sendable {
    public enum Operation: Hashable, Sendable {
        case copy
        case move
    }

    public enum Phase: Hashable, Sendable {
        case validation
        case dispatch
        case response
    }

    public enum Certainty: Hashable, Sendable {
        /// The command was rejected before any write was attempted.
        case definitelyNotApplied

        /// A write was attempted; callers must reconcile rather than retry blindly.
        case outcomeUnknown
    }

    public enum Reason: Hashable, Sendable {
        case invalidRequest
        case unsupportedOperation
        case transportFailure
        case timedOut
        case serverRejected
        case protocolFailure
    }

    public let operation: Operation
    public let phase: Phase
    public let certainty: Certainty
    public let reason: Reason

    public init(operation: Operation, phase: Phase, certainty: Certainty, reason: Reason) {
        self.operation = operation
        self.phase = phase
        self.certainty = certainty
        self.reason = reason
    }
}

extension IMAPMutationFailure: LocalizedError, CustomStringConvertible {
    public var description: String {
        "IMAP \(operation) failed during \(phase); mutation certainty: \(certainty) (\(reason))"
    }

    public var errorDescription: String? { description }

    public var recoverySuggestion: String? {
        switch certainty {
        case .definitelyNotApplied:
            return "Correct the request or connection state before trying again."
        case .outcomeUnknown:
            return "Reconcile the source and destination mailboxes before attempting another mutation."
        }
    }
}

// MARK: - Compact COPYUID validation

extension MessageTransferResult {
    static func make<T: MessageIdentifier>(
        from response: MessageTransferCommandResponse,
        requested identifiers: MessageIdentifierSet<T>
    ) -> MessageTransferResult {
        guard !response.hasConflictingCopyUID else {
            return .completedRequiringReconciliation(.conflictingMappings)
        }
        guard let copyUID = response.copyUID else {
            return .completedRequiringReconciliation(.mappingUnavailable)
        }
        guard let validated = UIDMapping.validated(copyUID) else {
            return .completedRequiringReconciliation(.mappingMalformed)
        }

        // Sequence numbers can change as unsolicited mailbox updates arrive.
        // COPYUID therefore cannot prove which sequence-number request produced
        // the reported source UIDs.
        guard T.self == UID.self else {
            return .completedRequiringReconciliation(.sourceIdentityUnprovable)
        }

        guard let requestedRanges = UIDMapping.requestedUIDRanges(identifiers),
              UIDMapping.coalescingAdjacent(validated.sourceRanges)
                == UIDMapping.coalescingAdjacent(requestedRanges) else {
            return .completedRequiringReconciliation(.requestedSourceMismatch)
        }
        return .completed(validated)
    }
}

extension UIDMapping {
    static func validated(_ copyUID: ResponseCodeCopy) -> UIDMapping? {
        guard UInt32(copyUID.destinationUIDValidity) > 0,
              let source = validate(copyUID.sourceUIDs),
              let destination = validate(copyUID.destinationUIDs),
              source.count == destination.count else {
            return nil
        }

        return UIDMapping(
            destinationUIDValidity: UIDValidity(nio: copyUID.destinationUIDValidity),
            sourceRanges: source.ranges,
            destinationRanges: destination.ranges,
            messageCount: source.count
        )
    }

    private static func validate(
        _ nioRanges: [NIOIMAPCore.UIDRange]
    ) -> (ranges: [Range], count: UInt64)? {
        guard !nioRanges.isEmpty else { return nil }

        var ranges: [Range] = []
        ranges.reserveCapacity(nioRanges.count)
        var total: UInt64 = 0
        var previousUpper: UInt32?

        for nioRange in nioRanges {
            let lower = nioRange.lowerBound.rawValue
            let upper = nioRange.upperBound.rawValue
            guard lower > 0, upper >= lower else { return nil }
            if let previousUpper, lower <= previousUpper {
                // COPYUID is positional; overlap and reordering are ambiguous.
                return nil
            }

            let width = UInt64(upper) - UInt64(lower) + 1
            let (newTotal, overflow) = total.addingReportingOverflow(width)
            guard !overflow else { return nil }
            total = newTotal
            ranges.append(Range(lowerBound: UID(lower), upperBound: UID(upper)))
            previousUpper = upper
        }
        return (ranges, total)
    }

    static func requestedUIDRanges<T: MessageIdentifier>(
        _ identifiers: MessageIdentifierSet<T>
    ) -> [Range]? {
        var result: [Range] = []
        result.reserveCapacity(identifiers.ranges.count)
        for range in identifiers.ranges {
            guard let lower = UInt32(exactly: range.lowerBound),
                  let upper = UInt32(exactly: range.upperBound),
                  lower > 0,
                  upper >= lower else {
                return nil
            }
            result.append(Range(lowerBound: UID(lower), upperBound: UID(upper)))
        }
        return result
    }

    static func coalescingAdjacent(_ ranges: [Range]) -> [Range] {
        var result: [Range] = []
        result.reserveCapacity(ranges.count)
        for range in ranges {
            if let last = result.last,
               last.upperBound.value < UInt32.max,
               last.upperBound.value + 1 == range.lowerBound.value {
                result[result.count - 1] = Range(
                    lowerBound: last.lowerBound,
                    upperBound: range.upperBound
                )
            } else {
                result.append(range)
            }
        }
        return result
    }
}
