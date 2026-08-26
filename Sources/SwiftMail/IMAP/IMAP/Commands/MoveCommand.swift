// MoveCommand.swift
// Commands related to moving messages in IMAP

import Foundation
import NIO
import NIOIMAP

/// Command for moving messages from one mailbox to another
struct MoveCommand<T: MessageIdentifier>: IMAPMutationCommand, IMAPCapabilityRequiringCommand {
    typealias ResultType = MessageTransferCommandResponse
    typealias HandlerType = MoveHandler
    
    /// The set of message identifiers to move
    let identifierSet: MessageIdentifierSet<T>
    
    /// The destination mailbox name
    let destinationMailbox: String

    /// Tracks whether this exact command crossed the transport write boundary.
    let dispatchTracker = MutationDispatchTracker()

    /// RFC 6851 MOVE is independent of UIDPLUS, including for UID MOVE.
    let requiredCapability: Capability = .move
    
    /// Initialize a new move command
    /// - Parameters:
    ///   - identifierSet: The set of message identifiers to move
    ///   - destinationMailbox: The destination mailbox name
    init(identifierSet: MessageIdentifierSet<T>, destinationMailbox: String) {
        self.identifierSet = identifierSet
        self.destinationMailbox = destinationMailbox
    }
    
    /// Validate the command before execution
    func validate() throws {
        guard !identifierSet.isEmpty else {
            throw IMAPError.emptyIdentifierSet
        }
        guard identifierSet.ranges.allSatisfy({
            $0.lowerBound > 0 && $0.upperBound <= Int(UInt32.max)
        }) else {
            throw IMAPError.invalidArgument("Message identifiers must be valid non-zero 32-bit values")
        }
    }
    
    /// Convert to an IMAP tagged command
    /// - Parameter tag: The command tag
    /// - Returns: A TaggedCommand ready to be sent to the server
    func toTaggedCommand(tag: String) -> TaggedCommand {
        let mailbox = MailboxName(ByteBuffer(string: destinationMailbox))
        
        if T.self == UID.self {
            return TaggedCommand(tag: tag, command: .uidMove(.set(identifierSet.toNIOSet()), mailbox))
        } else {
            return TaggedCommand(tag: tag, command: .move(.set(identifierSet.toNIOSet()), mailbox))
        }
    }
} 
