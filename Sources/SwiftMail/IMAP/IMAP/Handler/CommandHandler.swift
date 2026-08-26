// CommandHandler.swift
// Protocol for command-specific IMAP handlers

import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers

/// Protocol for command-specific IMAP handlers
/// These handlers are added to the pipeline when a command is sent and removed when the response is received
protocol CommandHandler: ChannelInboundHandler where InboundIn == Response {
    /// The tag associated with this command (optional)
    var commandTag: String? { get }
    
    /// Whether this handler has completed processing
    var isCompleted: Bool { get }
    
    /// Handle the completion of this command
    /// - Parameter context: The channel handler context
    func handleCompletion(context: ChannelHandlerContext)
}

/// Base implementation of CommandHandler with common functionality
class BaseIMAPCommandHandler<ResultType: Sendable>: CommandHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = Response
    typealias InboundOut = Response
    
    /// The tag associated with this command (optional)
    let commandTag: String?
    
    /// Whether this handler has completed processing
    private var _isCompleted: Bool = false

    /// Optional first-terminal gate used only by tracked mutation execution.
    /// It is installed before the handler can observe a response or error.
    private var completionArbiter: (@Sendable (_ isCancellation: Bool) -> Bool)?

    var isCompleted: Bool {
        lock.withLock { _isCompleted }
    }
    
    	/// Lock for thread-safe access to mutable properties
	let lock = NIOLock()
	
	/// Logger for command operations
	let logger = Logger(label: "com.swiftmail.imap.command")
	
	/// Buffer for logging during command processing
	var logBuffer: [String] = []
	
	/// Promise for the command result
	let promise: EventLoopPromise<ResultType>
    
    /// Collected untagged responses during command execution
    private(set) var untaggedResponses: [Response] = []
    
    /// Initialize a new command handler
    /// - Parameters:
    ///   - commandTag: The tag associated with this command
    ///   - promise: The promise to fulfill when the command completes
    init(commandTag: String, promise: EventLoopPromise<ResultType>) {
        self.commandTag = commandTag
        self.promise = promise
    }

    /// Concrete witness so specialized handlers can bind resources when added.
    /// A protocol-extension default selected by the base conformance would not
    /// dynamically dispatch a same-named method declared only by a subclass.
    func handlerAdded(context: ChannelHandlerContext) {}

    /// Concrete witness so specialized handlers can reliably observe removal.
    /// A protocol-extension default selected by the base conformance would not
    /// dynamically dispatch a same-named method declared only by a subclass.
    func handlerRemoved(context: ChannelHandlerContext) {}
    
    /// Handle the completion of this command
    /// - Parameter context: The channel handler context
    func handleCompletion(context: ChannelHandlerContext) {
        if !isCompleted {
            failWithError(IMAPError.commandFailed("Handler completed without resolving its command"))
        }

        // Remove this handler from the pipeline
        context.pipeline.removeHandler(self, promise: nil)
    }
    
    /// Succeed the promise with a result
    /// - Parameter result: The result to succeed with
    @discardableResult
    func succeedWithResult(_ result: ResultType) -> Bool {
        completePromise(with: .success(result))
    }
    
    /// Fail the promise with an error
    /// - Parameter error: The error to fail with
    @discardableResult
    func failWithError(_ error: Error) -> Bool {
        completePromise(with: .failure(error))
    }

    func installCompletionArbiter(
        _ arbiter: @escaping @Sendable (_ isCancellation: Bool) -> Bool
    ) {
        lock.withLock {
            precondition(!_isCompleted, "Completion arbiter must be installed before command execution")
            completionArbiter = arbiter
        }
    }
    
    /// Process an incoming response
    /// - Parameter response: The response to process
    /// - Returns: Whether the response was handled by this handler
    func processResponse(_ response: Response) -> Bool {
        
        // If commandTag is nil, we're only interested in untagged responses
        if commandTag == nil {
            return handleUntaggedResponse(response)
        }
        
        // Check if this is a tagged response that matches our command tag
        if case .tagged(let taggedResponse) = response, taggedResponse.tag == commandTag {
            // Check the response status
            if case .ok = taggedResponse.state {
                // Subclasses should override handleTaggedOKResponse to handle the OK response
                handleTaggedOKResponse(taggedResponse)
            } else {
                // Failed response, fail the promise with an error
                handleTaggedErrorResponse(taggedResponse)
            }
            return true
        }
        
        // Not our tagged response, see if subclasses want to handle untagged responses
        let handled = handleUntaggedResponse(response)
        return handled
    }
    
    	/// Handle a tagged OK response
	/// Subclasses should override this method to handle successful responses
	/// - Parameter response: The tagged response
	func handleTaggedOKResponse(_ response: TaggedResponse) {
		// Check for client bug warnings in the response
		if case .ok(let responseText) = response.state {
			if let code = responseText.code {
				// Check for CLIENTBUG response code
				if case .clientBug = code {
					logger.warning("CLIENTBUG warning: \(responseText.text)")
				}
			}
		}
		
		// Default implementation succeeds with Void for handlers that don't need a result
		// This only works for ResultType == Void, otherwise subclasses must override
		if ResultType.self == Void.self {
			succeedWithResult(() as! ResultType)
		}
		// For non-Void result types, subclasses must override this method
		// but we don't call fatalError here to allow them to call super for CLIENTBUG checking
	}
    
    /// Handle a tagged error response
    /// Subclasses can override this method to handle error responses differently
    /// - Parameter response: The tagged response
    func handleTaggedErrorResponse(_ response: TaggedResponse) {
        // Default implementation fails with a generic error
        failWithError(IMAPError.commandFailed(String(describing: response.state)))
    }
    
    /// Handle an untagged response
    /// Subclasses should override this method to handle untagged responses
    /// - Parameter response: The untagged response
    /// - Returns: Whether the response was handled by this handler
    func handleUntaggedResponse(_ response: Response) -> Bool {
        // Collect all untagged responses for later inspection
        untaggedResponses.append(response)
        
        // Check for BYE responses which can come at any time and terminate the connection
        if case .untagged(let payload) = response,
           case .conditionalState(let status) = payload,
           case .bye(let text) = status {
            // Fail the current command - executeCommand will handle disconnection
            failWithError(IMAPError.connectionFailed("Server terminated connection: \(text.text)"))
            return true
        }
        
        // Check for FATAL responses which also terminate the connection
        if case .fatal(let text) = response {
            // Fail the current command - executeCommand will handle disconnection
            failWithError(IMAPError.connectionFailed("Server fatal error: \(text.text)"))
            return true
        }
        
        // Default implementation doesn't handle other untagged responses
        return false
    }
    
    /// Channel read method from ChannelInboundHandler
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data)
        
        // Process the response (which will buffer it for logging)
        let handled = processResponse(response)
        
        // If this was our tagged response, handle completion
        if handled {
            handleCompletion(context: context)
        }
        
        // Always forward the response to the next handler
        context.fireChannelRead(data)
    }
    
    /// Error caught method from ChannelInboundHandler
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Handle the error
        handleError(error)
        
        // Forward the error to the next handler
        context.fireErrorCaught(error)
    }

    /// Complete an outstanding command when its transport disappears. NIO does
    /// not otherwise resolve command promises merely because a channel closed.
    func channelInactive(context: ChannelHandlerContext) {
        let error = IMAPConnectionError.disconnected
        if failWithError(error) {
            handleChannelTermination(error: error)
        }
        context.fireChannelInactive()
    }
    
    /// Handle an error
    /// This method should be overridden by subclasses
    func handleError(_ error: Error) {
        // Fail the promise with the error
        failWithError(error)
    }

    /// Hook for handlers that own resources in addition to their result promise.
    func handleChannelTermination(error: Error) {}

    private func completePromise(with result: Result<ResultType, Error>) -> Bool {
        let shouldComplete = lock.withLock {
            guard !_isCompleted else { return false }
            let isCancellation: Bool
            switch result {
            case .failure(let error):
                isCancellation = error is CancellationError
            case .success:
                isCancellation = false
            }
            guard completionArbiter?(isCancellation) ?? true else { return false }
            _isCompleted = true
            return true
        }

        guard shouldComplete else { return false }
        promise.completeWith(result)
        return true
    }
} 
