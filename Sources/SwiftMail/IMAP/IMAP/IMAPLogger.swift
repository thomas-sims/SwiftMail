// IMAPLogger.swift
// A channel handler that logs both outgoing and incoming IMAP messages

import Foundation
import Logging
import NIO
import NIOConcurrencyHelpers

@preconcurrency import NIOIMAP
import NIOIMAPCore

/// A channel handler that logs both outgoing and incoming IMAP messages
final class IMAPLogger: MailLogger, @unchecked Sendable {
	typealias InboundIn = Response
	typealias InboundOut = Response

    private var authenticationTag: String?

    var isAuthenticationRedactionActive: Bool {
        lock.withLock { authenticationTag != nil }
    }
    
    // Regular expressions for redacting sensitive information
    private let loginRegex = try! NSRegularExpression(pattern: "^[A-Za-z0-9]+ LOGIN", options: [])
    private let authRegex = try! NSRegularExpression(pattern: "^[A-Za-z0-9]+ AUTH", options: [])
    
    /// Process outgoing IMAP commands
	override func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let command = unwrapOutboundIn(data)

        if let message = command as? IMAPClientHandler.Message,
           case .part(let part) = message {
            switch part {
            case .tagged(let taggedCommand):
                if case .authenticate = taggedCommand.command {
                    lock.withLock { authenticationTag = taggedCommand.tag }
                    outboundLogger.trace("AUTHENTICATE command <redacted>")
                    context.write(data, promise: promise)
                    return
                }
            case .continuationResponse:
                // This frame carries authentication bytes by definition. Redact
                // it even if an earlier handler/state transition failed to
                // register (or already cleared) the AUTHENTICATE tag.
                outboundLogger.trace("AUTHENTICATE continuation <redacted>")
                context.write(data, promise: promise)
                return
            case .idleDone, .append:
                break
            }
        }

        // Get string representation of the command
        let commandString = stringRepresentation(from: command)
        
        // Redact sensitive information in LOGIN and AUTH commands
        let range = NSRange(location: 0, length: commandString.utf16.count)
        
        if loginRegex.firstMatch(in: commandString, options: [], range: range) != nil {
            // Use the String extension to redact sensitive LOGIN information
            outboundLogger.trace("\(commandString.redactAfter("LOGIN"))")
        } else if authRegex.firstMatch(in: commandString, options: [], range: range) != nil {
            // Also redact AUTH commands which may contain encoded credentials
            outboundLogger.trace("\(commandString.redactAfter("AUTH"))")
        } else {
            outboundLogger.trace("\(commandString)")
        }
        
        // Forward the command to the next handler
        context.write(data, promise: promise)
    }
    
	/// Process incoming IMAP responses
	override func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data) as! Response

        switch response {
        case .authenticationChallenge:
            // Authentication challenges are arbitrary server-provided bytes.
            // Never stringify or retain them in the logging buffer.
            bufferInboundResponse("AUTHENTICATE challenge <redacted>")
        case .tagged(let taggedResponse):
            let isAuthenticationResponse = lock.withLock { () -> Bool in
                guard let authenticationTag else { return false }
                if authenticationTag == taggedResponse.tag {
                    self.authenticationTag = nil
                }
                // While authentication is active, an unexpected tagged reply is
                // still hostile server-controlled text. Redact it without
                // clearing the expected tag so the real terminal reply is also
                // redacted and can end the auth logging state.
                return true
            }

            if isAuthenticationResponse {
                // Do not render the tagged state: its text can echo challenge,
                // account, scope, or credential material.
                bufferInboundResponse("AUTHENTICATE result <redacted>")
            } else {
                bufferInboundResponse(String(describing: response))
            }
        default:
            bufferInboundResponse(String(describing: response))
        }
        
        // Forward the response to the next handler
        context.fireChannelRead(data)
    }

    override func channelInactive(context: ChannelHandlerContext) {
        lock.withLock { authenticationTag = nil }
        context.fireChannelInactive()
    }
}
