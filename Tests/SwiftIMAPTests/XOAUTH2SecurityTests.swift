import Foundation
import Logging
import NIO
import NIOEmbedded
@preconcurrency import NIOIMAP
@preconcurrency import NIOIMAPCore
import Testing
@testable import SwiftMail

struct XOAUTH2SecurityTests {
    @Test
    func saslIRChallengeAndTaggedNOExposeOnlyFixedFailure() async throws {
        let challengeSentinel = "decoded-sasl-ir-challenge-sentinel"
        try await verifyFailureIsRedacted(
            expectsChallenge: false,
            challenges: [.base64(challengeSentinel)],
            taggedStatus: "NO",
            taggedSentinel: "tagged-no-sentinel"
        )
    }

    @Test
    func fallbackAndTwoChallengesNeverLogCredentialOrServerText() async throws {
        try await verifyFailureIsRedacted(
            expectsChallenge: true,
            challenges: [
                .empty,
                .base64("decoded-second-challenge-sentinel"),
            ],
            taggedStatus: "BAD",
            taggedSentinel: "tagged-bad-sentinel"
        )
    }

    @Test
    func emptyLargeAndMalformedChallengesRemainOpaque() async throws {
        try await verifyFailureIsRedacted(
            expectsChallenge: false,
            challenges: [.empty],
            taggedStatus: "NO",
            taggedSentinel: "empty-challenge-tagged-sentinel"
        )

        let largeSentinel = "large-challenge-sentinel-" + String(repeating: "x", count: 4_096)
        try await verifyFailureIsRedacted(
            expectsChallenge: false,
            challenges: [.base64(largeSentinel)],
            taggedStatus: "NO",
            taggedSentinel: "large-challenge-tagged-sentinel"
        )

        try await verifyFailureIsRedacted(
            expectsChallenge: false,
            challenges: [.malformed("malformed-challenge-wire-sentinel")],
            taggedStatus: "BAD",
            taggedSentinel: "malformed-challenge-tagged-sentinel"
        )
    }

    @Test
    func nonAuthenticationResponsesRemainVisibleAndInactiveClearsAuthState() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.non-auth", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel()
        try await channel.pipeline.addHandlers([IMAPClientHandler(), imapLogger])

        let noop = TaggedCommand(tag: "N001", command: .noop)
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(noop)))
        _ = try channel.readOutbound(as: ByteBuffer.self)

        var ordinaryResponse = channel.allocator.buffer(capacity: 0)
        ordinaryResponse.writeString("N001 NO ordinary-non-auth-sentinel\r\n")
        try channel.writeInbound(ordinaryResponse)
        imapLogger.flushInboundBuffer()
        #expect(capture.joinedMessages.contains("ordinary-non-auth-sentinel"))

        let command = TaggedCommand(
            tag: "A900",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        #expect(imapLogger.isAuthenticationRedactionActive)

        try await channel.close().get()
        #expect(!imapLogger.isAuthenticationRedactionActive)
        _ = try? channel.finish(acceptAlreadyClosed: true)
    }

    @Test
    func continuationIsRedactedWithoutAuthenticationState() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.stateless-continuation", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel(handler: imapLogger)
        let sentinel = "stateless-continuation-credential-sentinel"
        var credential = channel.allocator.buffer(capacity: sentinel.utf8.count)
        credential.writeString(sentinel)

        try await channel.writeAndFlush(
            IMAPClientHandler.OutboundIn.part(.continuationResponse(credential))
        )
        #expect(capture.joinedMessages.contains("AUTHENTICATE continuation <redacted>"))
        #expect(!capture.joinedMessages.contains(sentinel))

        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        _ = try? channel.finish()
    }

    @Test
    func unexpectedTaggedResponseDuringAuthenticationIsRedactedWithoutClearingExpectedTag() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.mismatched-tag", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel(handler: imapLogger)

        let command = TaggedCommand(
            tag: "A900",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

        let mismatch = Response.tagged(TaggedResponse(
            tag: "Z999",
            state: .no(ResponseText(text: "mismatched-auth-tag-sentinel"))
        ))
        try channel.writeInbound(mismatch)
        _ = try channel.readInbound(as: Response.self)
        imapLogger.flushInboundBuffer()
        #expect(capture.joinedMessages.contains("AUTHENTICATE result <redacted>"))
        #expect(!capture.joinedMessages.contains("mismatched-auth-tag-sentinel"))
        #expect(imapLogger.isAuthenticationRedactionActive)

        let expected = Response.tagged(TaggedResponse(
            tag: "A900",
            state: .no(ResponseText(text: "expected-auth-tag-sentinel"))
        ))
        try channel.writeInbound(expected)
        _ = try channel.readInbound(as: Response.self)
        imapLogger.flushInboundBuffer()
        #expect(!capture.joinedMessages.contains("expected-auth-tag-sentinel"))
        #expect(!imapLogger.isAuthenticationRedactionActive)

        _ = try? channel.finish()
    }
}

private enum AuthenticationChallengeFixture {
    case empty
    case base64(String)
    case malformed(String)

    var wirePayload: String {
        switch self {
        case .empty:
            return ""
        case .base64(let decoded):
            return Data(decoded.utf8).base64EncodedString()
        case .malformed(let sentinel):
            return "%%%\(sentinel)%%%"
        }
    }

    var forbiddenValues: [String] {
        switch self {
        case .empty:
            return []
        case .base64(let decoded):
            return [decoded, wirePayload]
        case .malformed(let sentinel):
            return [sentinel, wirePayload]
        }
    }
}

private func verifyFailureIsRedacted(
    expectsChallenge: Bool,
    challenges: [AuthenticationChallengeFixture],
    taggedStatus: String,
    taggedSentinel: String
) async throws {
    let capture = LogCapture()
    let logger = makeCaptureLogger(label: "test.imap.security.auth", capture: capture)
    let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
    let channel = EmbeddedChannel()
    try await channel.pipeline.addHandlers([IMAPClientHandler(), imapLogger])

    let tag = "A777"
    let promise = channel.eventLoop.makePromise(of: [Capability].self)
    let credentials = makeCredentialBuffer(using: channel.allocator)
    let handler = XOAUTH2AuthenticationHandler(
        commandTag: tag,
        promise: promise,
        credentials: credentials,
        expectsChallenge: expectsChallenge,
        logger: logger
    )
    try await channel.pipeline.addHandler(handler)

    let initialResponse = expectsChallenge ? nil : InitialResponse(credentials)
    let command = TaggedCommand(
        tag: tag,
        command: .authenticate(
            mechanism: AuthenticationMechanism("XOAUTH2"),
            initialResponse: initialResponse
        )
    )
    try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))

    guard var outboundCommand = try channel.readOutbound(as: ByteBuffer.self) else {
        Issue.record("Expected AUTHENTICATE wire command")
        _ = try? channel.finish()
        return
    }
    let outboundCommandString = outboundCommand.readString(length: outboundCommand.readableBytes) ?? ""
    #expect(outboundCommandString.contains("AUTHENTICATE XOAUTH2"))

    for (challengeIndex, challenge) in challenges.enumerated() {
        var challengeBuffer = channel.allocator.buffer(capacity: challenge.wirePayload.utf8.count + 4)
        challengeBuffer.writeString("+ \(challenge.wirePayload)\r\n")
        try channel.writeInbound(challengeBuffer)

        guard var continuation = try channel.readOutbound(as: ByteBuffer.self) else {
            Issue.record("Expected XOAUTH2 continuation response")
            _ = try? channel.finish()
            return
        }
        let continuationString = continuation.readString(length: continuation.readableBytes) ?? ""
        if expectsChallenge, challengeIndex == 0 {
            #expect(continuationString == "\(credentialWireBase64())\r\n")
        } else {
            #expect(continuationString == "\r\n")
        }
    }

    var taggedBuffer = channel.allocator.buffer(capacity: taggedSentinel.utf8.count + 32)
    taggedBuffer.writeString("\(tag) \(taggedStatus) \(taggedSentinel)\r\n")
    try channel.writeInbound(taggedBuffer)

    let propagatedError: IMAPError
    do {
        _ = try await promise.futureResult.get()
        Issue.record("Expected fixed XOAUTH2 authentication failure")
        _ = try? channel.finish()
        return
    } catch let error as IMAPError {
        propagatedError = error
    } catch {
        Issue.record("Unexpected XOAUTH2 error type")
        _ = try? channel.finish()
        return
    }

    imapLogger.flushInboundBuffer()
    let logs = capture.joinedMessages
    let errorSurfaces = [
        String(describing: propagatedError),
        propagatedError.localizedDescription,
        propagatedError.failureReason ?? "",
    ].joined(separator: " ")

    if case .authFailed(let reason) = propagatedError {
        #expect(reason == IMAPError.xoauth2AuthenticationFailureReason)
    } else {
        Issue.record("Expected authFailed category")
    }

    let forbidden = challenges.flatMap(\.forbiddenValues) + [
        taggedSentinel,
        credentialWireBase64(),
        "fixture-credential-wire-sentinel",
    ]
    for value in forbidden where !value.isEmpty {
        #expect(!logs.contains(value))
        #expect(!errorSurfaces.contains(value))
    }

    #expect(logs.contains("AUTHENTICATE command <redacted>"))
    #expect(logs.contains("AUTHENTICATE result <redacted>"))
    if !challenges.isEmpty {
        #expect(logs.contains("AUTHENTICATE challenge <redacted>"))
    }
    if expectsChallenge {
        #expect(logs.contains("AUTHENTICATE continuation <redacted>"))
    }
    #expect(!imapLogger.isAuthenticationRedactionActive)
    #expect(handler.untaggedResponses.allSatisfy { response in
        if case .authenticationChallenge = response { return false }
        return true
    })

    _ = try? channel.finish()
}

private func makeCredentialBuffer(using allocator: ByteBufferAllocator) -> ByteBuffer {
    var buffer = allocator.buffer(capacity: 96)
    buffer.writeString("user=fixture-user")
    buffer.writeInteger(UInt8(0x01))
    buffer.writeString("auth=Bearer fixture-credential-wire-sentinel")
    buffer.writeInteger(UInt8(0x01))
    buffer.writeInteger(UInt8(0x01))
    return buffer
}

private func credentialWireBase64() -> String {
    let raw = "user=fixture-user\u{01}auth=Bearer fixture-credential-wire-sentinel\u{01}\u{01}"
    return Data(raw.utf8).base64EncodedString()
}

private final class LogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    var joinedMessages: String {
        lock.lock()
        defer { lock.unlock() }
        return messages.joined(separator: "\n")
    }

    func append(_ message: String) {
        lock.lock()
        messages.append(message)
        lock.unlock()
    }
}

private struct CaptureLogHandler: LogHandler {
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace
    var metadataProvider: Logger.MetadataProvider?
    let capture: LogCapture

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        capture.append(message.description)
    }
}

private func makeCaptureLogger(label: String, capture: LogCapture) -> Logger {
    var logger = Logger(label: label) { _ in
        CaptureLogHandler(capture: capture)
    }
    logger.logLevel = .trace
    return logger
}
