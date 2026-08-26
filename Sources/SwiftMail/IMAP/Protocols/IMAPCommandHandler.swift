// IMAPCommandHandler.swift
// Protocol for IMAP command handlers

import Foundation
import NIO
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore

/// Protocol for IMAP command handlers
protocol IMAPCommandHandler: ChannelInboundHandler, RemovableChannelHandler, Sendable where ResultType: Sendable {
    associatedtype ResultType
    
    /// Initialize the handler
    /// - Parameters:
    ///   - commandTag: The tag for the command (optional)
    ///   - promise: The promise to fulfill with the result
    init(commandTag: String, promise: EventLoopPromise<ResultType>)
    
    /// Get the untagged responses collected during command execution
    var untaggedResponses: [Response] { get }

    /// Fail the command if it has not already completed.
    @discardableResult
    func failWithError(_ error: Error) -> Bool

    /// Install an exactly-once gate for tracked mutation terminals. The gate is
    /// invoked while the handler owns its completion lock, before its promise is
    /// resolved. Returning false leaves the handler unresolved because another
    /// terminal already owns the command result.
    func installCompletionArbiter(_ arbiter: @escaping @Sendable (_ isCancellation: Bool) -> Bool)
}
