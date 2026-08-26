import Foundation
import Logging
@preconcurrency import NIOIMAP
import NIOIMAPCore
import NIO
import NIOConcurrencyHelpers

/// Structural privacy boundary for responses that survive beyond their
/// command handler. Human-readable status text and response-code payloads are
/// arbitrary server input and must not be retained, logged, or published.
private enum BufferedResponsePrivacy {
    static let fixedStatusText = "Server status details unavailable."
    static let fixedTerminationText = "Server closed the connection."

    static func sanitized(_ response: Response) -> Response {
        switch response {
        case .untagged(.conditionalState(let status)):
            return .untagged(.conditionalState(sanitized(status)))
        case .fatal:
            return .fatal(ResponseText(text: fixedTerminationText))
        default:
            return response
        }
    }

    static func diagnosticKind(for response: Response) -> String {
        switch response {
        case .untagged(.conditionalState(let status)):
            return "conditional \(statusKind(status))"
        case .untagged(.mailboxData):
            return "mailbox-data"
        case .untagged(.messageData):
            return "message-data"
        case .untagged(.capabilityData):
            return "capability-data"
        case .untagged:
            return "untagged"
        case .fetch:
            return "fetch"
        case .fatal:
            return "fatal"
        case .tagged:
            return "tagged"
        case .authenticationChallenge:
            return "authentication-challenge"
        case .idleStarted:
            return "idle-started"
        }
    }

    private static func sanitized(_ status: UntaggedStatus) -> UntaggedStatus {
        switch status {
        case .ok(let text):
            return .ok(sanitized(text, fixedText: fixedStatusText))
        case .no(let text):
            return .no(sanitized(text, fixedText: fixedStatusText))
        case .bad(let text):
            return .bad(sanitized(text, fixedText: fixedStatusText))
        case .preauth(let text):
            return .preauth(sanitized(text, fixedText: fixedStatusText))
        case .bye(let text):
            return .bye(sanitized(text, fixedText: fixedTerminationText))
        }
    }

    private static func sanitized(_ text: ResponseText, fixedText: String) -> ResponseText {
        // ALERT is the only buffered response code whose typed meaning is used
        // by the event bridge. Every other code can carry server-controlled
        // strings, URLs, mailbox identifiers, or capability data.
        let safeCode: ResponseTextCode? = text.code == .alert ? .alert : nil
        return ResponseText(code: safeCode, text: fixedText)
    }

    private static func statusKind(_ status: UntaggedStatus) -> String {
        switch status {
        case .ok: return "OK"
        case .no: return "NO"
        case .bad: return "BAD"
        case .preauth: return "PREAUTH"
        case .bye: return "BYE"
        }
    }
}

/// A persistent NIO pipeline handler that buffers untagged IMAP responses
/// when no transient command handler is active.
///
/// IMAP servers can send untagged responses (EXISTS, EXPUNGE, FETCH, etc.) at any time.
/// During the gap between command handlers — for example between an IDLE cycle's DONE/NOOP
/// completing and the next IDLE starting — these responses would normally be parsed by
/// `IMAPClientHandler` but silently dropped at the pipeline tail.
///
/// This handler sits at the end of the pipeline permanently. When a command handler is active,
/// it simply passes responses through. When no command handler is active, it captures untagged
/// responses in a buffer that can be drained when the next command starts.
final class UntaggedResponseBuffer: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = Response
    typealias InboundOut = Response

    private let lock = NIOLock()
    private var buffer: [Response] = []
    private var _hasActiveHandler: Bool = false
    private let logger: Logger

    init(logger: Logger = Logger(label: "com.cocoanetics.SwiftMail.UntaggedResponseBuffer")) {
        self.logger = logger
    }

    /// Whether a transient command handler is currently active in the pipeline.
    var hasActiveHandler: Bool {
        get { lock.withLock { _hasActiveHandler } }
        set { lock.withLock { _hasActiveHandler = newValue } }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = unwrapInboundIn(data)

        let sanitizedResponse = BufferedResponsePrivacy.sanitized(response)
        let shouldBuffer = lock.withLock { () -> Bool in
            guard !_hasActiveHandler else { return false }

            switch response {
            case .untagged:
                buffer.append(sanitizedResponse)
                return true
            case .fetch:
                buffer.append(sanitizedResponse)
                return true
            case .fatal:
                buffer.append(sanitizedResponse)
                return true
            case .tagged:
                // Tagged responses should not arrive when no handler is active,
                // but don't buffer them — let them flow.
                return false
            default:
                return false
            }
        }

        if shouldBuffer {
            logger.debug("Buffered response with no active handler: \(BufferedResponsePrivacy.diagnosticKind(for: sanitizedResponse))")
        }

        // Always forward. If buffering was necessary, forward the same sanitized
        // value retained by the buffer so the pipeline tail is not a bypass.
        if shouldBuffer {
            context.fireChannelRead(wrapInboundOut(sanitizedResponse))
        } else {
            context.fireChannelRead(data)
        }
    }

    /// Drain all buffered responses, returning them in order.
    ///
    /// Call this when adding a new command handler to process any responses
    /// that arrived during the gap between handlers.
    func drainBuffer() -> [Response] {
        lock.withLock {
            defer { buffer.removeAll(keepingCapacity: true) }
            return buffer
        }
    }

    /// Number of currently buffered responses.
    var bufferedCount: Int {
        lock.withLock { buffer.count }
    }

    /// Drain buffered responses through the privacy-safe server-event bridge.
    /// Diagnostics report only structural kinds, never response payloads.
    func drainServerEvents(logger: Logger) -> [IMAPServerEvent] {
        let responses = drainBuffer()
        guard !responses.isEmpty else { return [] }

        logger.debug("Draining \(responses.count) buffered response(s)")
        var events: [IMAPServerEvent] = []

        for rawResponse in responses {
            // Defense in depth for responses buffered by an older in-memory
            // implementation before this privacy boundary was installed.
            let response = BufferedResponsePrivacy.sanitized(rawResponse)

            switch response {
            case .untagged(let payload):
                switch payload {
                case .mailboxData(let data):
                    switch data {
                    case .exists(let count):
                        events.append(.exists(Int(count)))
                    case .recent(let count):
                        events.append(.recent(Int(count)))
                    case .flags(let flags):
                        events.append(.flags(flags.map { Flag(nio: $0) }))
                    default:
                        logger.debug("Skipping buffered mailbox-data response")
                    }
                case .messageData(let data):
                    switch data {
                    case .expunge(let seq):
                        events.append(.expunge(SequenceNumber(seq.rawValue)))
                    default:
                        logger.debug("Skipping buffered message-data response")
                    }
                case .conditionalState(let status):
                    switch status {
                    case .ok(let text):
                        if text.code == .alert {
                            events.append(.alert(text.text))
                        }
                    case .bye(let text):
                        events.append(.bye(text.text))
                    default:
                        break
                    }
                case .capabilityData(let capabilities):
                    events.append(.capability(capabilities.map { String($0) }))
                default:
                    logger.debug("Skipping buffered \(BufferedResponsePrivacy.diagnosticKind(for: response)) response")
                }
            case .fetch:
                logger.debug("Skipping buffered fetch response")
            case .fatal(let text):
                events.append(.bye(text.text))
            default:
                logger.debug("Skipping buffered \(BufferedResponsePrivacy.diagnosticKind(for: response)) response")
            }
        }

        return events
    }
}
