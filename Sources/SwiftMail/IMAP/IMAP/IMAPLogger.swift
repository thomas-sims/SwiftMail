// IMAPLogger.swift
// A channel handler that logs both outgoing and incoming IMAP messages

import Foundation
import Logging
import NIO
import NIOConcurrencyHelpers

@preconcurrency import NIOIMAP
import NIOIMAPCore

protocol IMAPAuthenticationLogging: AnyObject, Sendable {
    /// Ends active authentication logging without making late authentication
    /// frames eligible for raw rendering.
    func authenticationDidTerminate(tag: String)
}

/// A channel handler that logs both outgoing and incoming IMAP messages
final class IMAPLogger: MailLogger, IMAPAuthenticationLogging, @unchecked Sendable {
	typealias InboundIn = Response
	typealias InboundOut = Response

    private struct AuthenticationState {
        var activeTag: String?
        /// Redact every inbound frame between authentication termination and
        /// the next structurally observed client command. This covers late
        /// untagged status/fatal frames that carry no correlation tag.
        var isTerminalQuarantineActive = false
        /// Authentication tags remain sensitive for the transport lifetime so
        /// duplicate or arbitrarily late same-tag results can never become raw.
        var sensitiveTags: Set<String> = []
    }

    private var authenticationState = AuthenticationState()

    var isAuthenticationRedactionActive: Bool {
        lock.withLock { authenticationState.activeTag != nil }
    }

    var isAuthenticationTerminalQuarantineActive: Bool {
        lock.withLock { authenticationState.isTerminalQuarantineActive }
    }

    func authenticationDidTerminate(tag: String) {
        lock.withLock {
            authenticationState.sensitiveTags.insert(tag)
            guard authenticationState.activeTag == tag else { return }
            authenticationState.activeTag = nil
            authenticationState.isTerminalQuarantineActive = true
        }
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
                    lock.withLock {
                        authenticationState.activeTag = taggedCommand.tag
                        authenticationState.isTerminalQuarantineActive = false
                        authenticationState.sensitiveTags.insert(taggedCommand.tag)
                    }
                    outboundLogger.trace("AUTHENTICATE command <redacted>")
                    context.write(data, promise: promise)
                    return
                }
                beginOrdinaryCommand()
            case .continuationResponse:
                // This frame carries authentication bytes by definition. Redact
                // it even if an earlier handler/state transition failed to
                // register (or already cleared) the AUTHENTICATE tag.
                outboundLogger.trace("AUTHENTICATE continuation <redacted>")
                context.write(data, promise: promise)
                return
            case .append:
                if part.tag != nil {
                    beginOrdinaryCommand()
                }
            case .idleDone:
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

        switch authenticationLoggingDisposition(for: response) {
        case .challenge:
            // Authentication challenges are arbitrary server-provided bytes.
            // Never stringify or retain them in the logging buffer.
            bufferInboundResponse("AUTHENTICATE challenge <redacted>")
        case .authenticationResult:
            // Tagged authentication results have an established fixed log
            // category. Preserve it without rendering server-controlled text.
            bufferInboundResponse("AUTHENTICATE result <redacted>")
        case .authenticationFrame:
            // During active authentication and terminal quarantine, every
            // server-controlled frame is opaque. This includes untagged status,
            // unexpected responses, and other protocol frames.
            bufferInboundResponse("AUTHENTICATE response <redacted>")
        case .status(let kind):
            // Human-readable status and fatal text is arbitrary server input
            // and has no diagnostic need to be rendered verbatim. Redact it
            // even outside an auth exchange so an untagged late auth frame
            // cannot leak after a subsequent command releases quarantine.
            bufferInboundResponse("IMAP \(kind) <redacted>")
        case .ordinary:
            bufferInboundResponse(String(describing: response))
        }
        
        // Forward the response to the next handler
        context.fireChannelRead(data)
    }

    override func channelInactive(context: ChannelHandlerContext) {
        lock.withLock {
            authenticationState.activeTag = nil
            authenticationState.isTerminalQuarantineActive = false
        }
        context.fireChannelInactive()
    }

    private enum AuthenticationLoggingDisposition {
        case challenge
        case authenticationResult
        case authenticationFrame
        case status(String)
        case ordinary
    }

    private func beginOrdinaryCommand() {
        lock.withLock {
            guard authenticationState.activeTag == nil else { return }
            authenticationState.isTerminalQuarantineActive = false
        }
    }

    private func authenticationLoggingDisposition(for response: Response) -> AuthenticationLoggingDisposition {
        if case .authenticationChallenge = response {
            return .challenge
        }

        if case .fatal = response {
            return .status("FATAL")
        }

        if case .untagged(.conditionalState(let status)) = response {
            switch status {
            case .ok: return .status("OK")
            case .no: return .status("NO")
            case .bad: return .status("BAD")
            case .preauth: return .status("PREAUTH")
            case .bye: return .status("BYE")
            }
        }

        return lock.withLock {
            if case .tagged(let taggedResponse) = response {
                if authenticationState.sensitiveTags.contains(taggedResponse.tag) {
                    if authenticationState.activeTag == taggedResponse.tag {
                        authenticationState.activeTag = nil
                        authenticationState.isTerminalQuarantineActive = true
                    }
                    return .authenticationResult
                }

                if authenticationState.activeTag != nil || authenticationState.isTerminalQuarantineActive {
                    return .authenticationResult
                }
                return .ordinary
            }

            if authenticationState.activeTag != nil || authenticationState.isTerminalQuarantineActive {
                return .authenticationFrame
            }
            return .ordinary
        }
    }
}
