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

    @Test
    func terminalQuarantineRedactsLateAuthenticationFramesAndReleasesForOrdinaryCommands() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.terminal-quarantine", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel(handler: imapLogger)

        let authCommand = TaggedCommand(
            tag: "A900",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(authCommand)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

        let expected = Response.tagged(TaggedResponse(
            tag: "A900",
            state: .no(ResponseText(text: "terminal-auth-sentinel"))
        ))
        try channel.writeInbound(expected)
        _ = try channel.readInbound(as: Response.self)
        #expect(!imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.isAuthenticationTerminalQuarantineActive)

        for sentinel in ["duplicate-auth-sentinel-one", "duplicate-auth-sentinel-two"] {
            let duplicate = Response.tagged(TaggedResponse(
                tag: "A900",
                state: .bad(ResponseText(text: sentinel))
            ))
            try channel.writeInbound(duplicate)
            _ = try channel.readInbound(as: Response.self)
        }

        let ordinaryCommand = TaggedCommand(tag: "N901", command: .noop)
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(ordinaryCommand)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(!imapLogger.isAuthenticationTerminalQuarantineActive)

        let ordinary = Response.tagged(TaggedResponse(
            tag: "N901",
            state: .no(ResponseText(text: "ordinary-after-auth-sentinel"))
        ))
        try channel.writeInbound(ordinary)
        _ = try channel.readInbound(as: Response.self)

        let arbitrarilyLate = Response.tagged(TaggedResponse(
            tag: "A900",
            state: .bad(ResponseText(text: "late-auth-after-next-command-sentinel"))
        ))
        try channel.writeInbound(arbitrarilyLate)
        _ = try channel.readInbound(as: Response.self)

        let lateBye = Response.untagged(.conditionalState(
            .bye(ResponseText(text: "late-bye-after-next-command-sentinel"))
        ))
        try channel.writeInbound(lateBye)
        _ = try channel.readInbound(as: Response.self)

        imapLogger.flushInboundBuffer()
        let logs = capture.joinedMessages
        #expect(logs.contains("ordinary-after-auth-sentinel"))
        #expect(logs.contains("IMAP BYE <redacted>"))
        for forbidden in [
            "terminal-auth-sentinel",
            "duplicate-auth-sentinel-one",
            "duplicate-auth-sentinel-two",
            "late-auth-after-next-command-sentinel",
            "late-bye-after-next-command-sentinel",
        ] {
            #expect(!logs.contains(forbidden))
        }

        _ = try? channel.finish()
    }

    @Test
    func authTimeStatusAndFatalTextAreSuppressedFromHandlerAndEveryErrorSurface() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.auth-status", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: [Capability].self)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: "A777",
            promise: promise,
            credentials: makeCredentialBuffer(using: channel.allocator),
            expectsChallenge: false,
            logger: logger,
            authenticationLogger: imapLogger
        )
        try await channel.pipeline.addHandlers([imapLogger, handler])

        let command = TaggedCommand(
            tag: "A777",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

        let warning = Response.untagged(.conditionalState(
            .no(ResponseText(text: "auth-time-status-sentinel"))
        ))
        try channel.writeInbound(warning)
        _ = try channel.readInbound(as: Response.self)

        let bye = Response.untagged(.conditionalState(
            .bye(ResponseText(text: "auth-time-bye-sentinel"))
        ))
        try channel.writeInbound(bye)
        _ = try channel.readInbound(as: Response.self)

        let error = await fixedXOAUTH2Failure(from: promise.futureResult)
        imapLogger.flushInboundBuffer()
        let surfaces = errorSurfaces(error)
        for forbidden in ["auth-time-status-sentinel", "auth-time-bye-sentinel"] {
            #expect(!capture.joinedMessages.contains(forbidden))
            #expect(!surfaces.contains(forbidden))
        }
        #expect(capture.joinedMessages.contains("IMAP NO <redacted>"))
        #expect(capture.joinedMessages.contains("IMAP BYE <redacted>"))
        #expect(handler.untaggedResponses.isEmpty)
        #expect(handler.observedConnectionTermination)
        #expect(!imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.isAuthenticationTerminalQuarantineActive)

        // A subsequent structurally typed command ends broad quarantine, while
        // status/BYE text remains unconditionally non-renderable.
        let next = TaggedCommand(tag: "N902", command: .noop)
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(next)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(!imapLogger.isAuthenticationTerminalQuarantineActive)

        _ = try? channel.finish()
    }

    @Test
    func authTimeFatalTextIsSuppressedAndConvertedToFixedFailure() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.auth-fatal", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: [Capability].self)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: "A779",
            promise: promise,
            credentials: makeCredentialBuffer(using: channel.allocator),
            expectsChallenge: false,
            logger: logger,
            authenticationLogger: imapLogger
        )
        try await channel.pipeline.addHandlers([imapLogger, handler])

        let command = TaggedCommand(
            tag: "A779",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

        let sentinel = "auth-time-fatal-sentinel"
        try channel.writeInbound(Response.fatal(ResponseText(text: sentinel)))
        _ = try channel.readInbound(as: Response.self)

        let error = await fixedXOAUTH2Failure(from: promise.futureResult)
        imapLogger.flushInboundBuffer()
        #expect(capture.joinedMessages.contains("IMAP FATAL <redacted>"))
        #expect(!capture.joinedMessages.contains(sentinel))
        #expect(!errorSurfaces(error).contains(sentinel))
        #expect(handler.untaggedResponses.isEmpty)
        #expect(handler.observedConnectionTermination)
        #expect(!imapLogger.isAuthenticationRedactionActive)

        _ = try? channel.finish()
    }

    @Test
    func malformedParserBufferFailsOpaquelyAndClosesTransport() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.parser-error", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: [Capability].self)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: "A777",
            promise: promise,
            credentials: makeCredentialBuffer(using: channel.allocator),
            expectsChallenge: false,
            logger: logger,
            authenticationLogger: imapLogger
        )
        try await channel.pipeline.addHandlers([IMAPClientHandler(), imapLogger, handler])

        let command = TaggedCommand(
            tag: "A777",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        _ = try channel.readOutbound(as: ByteBuffer.self)

        let sentinel = "malformed-parser-buffer-sentinel"
        var malformed = channel.allocator.buffer(capacity: sentinel.utf8.count + 4)
        // OOPS is not a tagged response state. This complete line makes pinned
        // NIOIMAP wrap the original wire buffer in IMAPDecoderError.
        malformed.writeString("A777 OOPS \(sentinel)\r\n")
        try channel.writeInbound(malformed)

        guard handler.isCompleted else {
            Issue.record("Expected malformed response to fail the auth handler")
            try await channel.close().get()
            _ = try? channel.finish(acceptAlreadyClosed: true)
            return
        }

        let error = await fixedXOAUTH2Failure(from: promise.futureResult)
        #expect(!channel.isActive)
        _ = try? channel.finish(acceptAlreadyClosed: true)
        #expect(await boundedFutureResult(channel.closeFuture) != nil)
        imapLogger.flushInboundBuffer()
        #expect(handler.requiresTransportClose)
        #expect(!capture.joinedMessages.contains(sentinel))
        #expect(!errorSurfaces(error).contains(sentinel))
    }

    @Test
    func pipelineErrorAndHandlerRemovalBothFailOpaquelyAndRetireTransport() async throws {
        for (tag, removeHandler) in [("A810", false), ("A811", true)] {
            let capture = LogCapture()
            let logger = makeCaptureLogger(label: "test.imap.security.terminal-path", capture: capture)
            let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
            let channel = EmbeddedChannel()
            let promise = channel.eventLoop.makePromise(of: [Capability].self)
            let handler = XOAUTH2AuthenticationHandler(
                commandTag: tag,
                promise: promise,
                credentials: makeCredentialBuffer(using: channel.allocator),
                expectsChallenge: false,
                logger: logger,
                authenticationLogger: imapLogger
            )
            try await channel.pipeline.addHandlers([imapLogger, handler])

            let command = TaggedCommand(
                tag: tag,
                command: .authenticate(
                    mechanism: AuthenticationMechanism("XOAUTH2"),
                    initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
                )
            )
            try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
            _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

            let sentinel = "terminal-path-wire-sentinel-\(tag)"
            if removeHandler {
                try await channel.pipeline.removeHandler(handler).get()
            } else {
                channel.pipeline.fireErrorCaught(SensitivePipelineError(sentinel: sentinel))
            }

            let error = await fixedXOAUTH2Failure(from: promise.futureResult)
            #expect(!channel.isActive)
            _ = try? channel.finish(acceptAlreadyClosed: true)
            #expect(await boundedFutureResult(channel.closeFuture) != nil)
            imapLogger.flushInboundBuffer()
            #expect(handler.requiresTransportClose)
            #expect(!imapLogger.isAuthenticationRedactionActive)
            #expect(!imapLogger.isAuthenticationTerminalQuarantineActive)
            #expect(!capture.joinedMessages.contains(sentinel))
            #expect(!errorSurfaces(error).contains(sentinel))
        }
    }

    @Test
    func continuationWriteFailurePublishesFixedFailureAndClosesTransport() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.continuation-write", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let failer = SecondByteBufferWriteFailer(
            error: SensitivePipelineError(sentinel: "continuation-write-error-sentinel")
        )
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: [Capability].self)
        let handler = XOAUTH2AuthenticationHandler(
            commandTag: "A812",
            promise: promise,
            credentials: makeCredentialBuffer(using: channel.allocator),
            expectsChallenge: true,
            logger: logger,
            authenticationLogger: imapLogger
        )
        try await channel.pipeline.addHandlers([failer, IMAPClientHandler(), imapLogger, handler])

        let command = TaggedCommand(
            tag: "A812",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: nil
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(command)))
        _ = try channel.readOutbound(as: ByteBuffer.self)

        var challenge = channel.allocator.buffer(capacity: 4)
        challenge.writeString("+ \r\n")
        try channel.writeInbound(challenge)

        let error = await fixedXOAUTH2Failure(from: promise.futureResult)
        #expect(!channel.isActive)
        _ = try? channel.finish(acceptAlreadyClosed: true)
        #expect(await boundedFutureResult(channel.closeFuture) != nil)
        imapLogger.flushInboundBuffer()
        #expect(failer.writeCount == 2)
        #expect(failer.failedWriteCount == 1)
        #expect(handler.requiresTransportClose)
        #expect(capture.joinedMessages.contains("AUTHENTICATE continuation <redacted>"))
        #expect(!capture.joinedMessages.contains("continuation-write-error-sentinel"))
        #expect(!errorSurfaces(error).contains("continuation-write-error-sentinel"))
    }

    @Test
    func lateStatusBufferAndDrainedEventsNeverExposeServerText() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.response-buffer", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        let responseBuffer = UntaggedResponseBuffer(logger: logger)
        let channel = EmbeddedChannel()
        try await channel.pipeline.addHandlers([imapLogger, responseBuffer])

        let authCommand = TaggedCommand(
            tag: "A950",
            command: .authenticate(
                mechanism: AuthenticationMechanism("XOAUTH2"),
                initialResponse: InitialResponse(makeCredentialBuffer(using: channel.allocator))
            )
        )
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(authCommand)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)

        try channel.writeInbound(Response.tagged(TaggedResponse(
            tag: "A950",
            state: .no(ResponseText(text: "completed-auth-buffer-sentinel"))
        )))
        _ = try channel.readInbound(as: Response.self)
        #expect(!imapLogger.isAuthenticationRedactionActive)

        // Release broad terminal quarantine exactly as a subsequent real
        // command does. Status text still has its unconditional privacy rule.
        let ordinaryCommand = TaggedCommand(tag: "N951", command: .noop)
        try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(ordinaryCommand)))
        _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(!imapLogger.isAuthenticationTerminalQuarantineActive)
        responseBuffer.hasActiveHandler = false

        let markers = [
            "late-conditional-text-sentinel",
            "late-conditional-code-sentinel",
            "late-alert-sentinel",
            "late-bye-sentinel",
            "late-fatal-sentinel",
        ]
        let lateResponses: [Response] = [
            .untagged(.conditionalState(.no(ResponseText(
                code: .other(markers[1], markers[0]),
                text: markers[0]
            )))),
            .untagged(.conditionalState(.ok(ResponseText(code: .alert, text: markers[2])))),
            .untagged(.conditionalState(.bye(ResponseText(text: markers[3])))),
            .fatal(ResponseText(code: .other(markers[4], nil), text: markers[4])),
        ]

        for response in lateResponses {
            try channel.writeInbound(response)
            let forwarded = try channel.readInbound(as: Response.self)
            #expect(forwarded != nil)
            if let forwarded {
                for marker in markers {
                    #expect(!String(describing: forwarded).contains(marker))
                }
            }
        }

        let stored = responseBuffer.drainBuffer()
        #expect(stored.count == lateResponses.count)
        for marker in markers {
            #expect(!String(describing: stored).contains(marker))
        }

        // Re-enter through the production pipeline and exercise the exact
        // production drain/event bridge used by IMAPConnection.
        for response in lateResponses {
            try channel.writeInbound(response)
            _ = try channel.readInbound(as: Response.self)
        }
        let events = responseBuffer.drainServerEvents(logger: logger)

        var alertTexts: [String] = []
        var byeTexts: [String] = []
        for event in events {
            switch event {
            case .alert(let text):
                alertTexts.append(text)
            case .bye(let text):
                if let text { byeTexts.append(text) }
            default:
                break
            }
        }
        #expect(alertTexts == ["Server status details unavailable."])
        #expect(byeTexts == [
            "Server closed the connection.",
            "Server closed the connection.",
        ])

        imapLogger.flushInboundBuffer()
        let allSurfaces = capture.joinedMessages
            + String(describing: stored)
            + String(describing: alertTexts)
            + String(describing: byeTexts)
        #expect(allSurfaces.contains("IMAP BYE <redacted>"))
        #expect(allSurfaces.contains("Buffered response with no active handler: fatal"))
        for marker in markers + ["completed-auth-buffer-sentinel"] {
            #expect(!allSurfaces.contains(marker))
        }

        _ = try? channel.finish()
    }

    @Test
    func authenticationTagsAreBoundedToCurrentTransportGeneration() async throws {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.security.transport-generation", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)

        let oldChannel = EmbeddedChannel(handler: imapLogger)
        let oldPromise = oldChannel.eventLoop.makePromise(of: [Capability].self)
        let oldHandler = XOAUTH2AuthenticationHandler(
            commandTag: "AOLD",
            promise: oldPromise,
            credentials: makeCredentialBuffer(using: oldChannel.allocator),
            expectsChallenge: false,
            logger: logger,
            authenticationLogger: imapLogger
        )
        try await oldChannel.pipeline.addHandler(oldHandler)
        try await oldChannel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(
            makeAuthenticationCommand(tag: "AOLD", using: oldChannel.allocator)
        )))
        _ = try oldChannel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(imapLogger.authenticationSensitiveTagCount == 1)

        // Rebinding the intentionally shared logger creates a new generation
        // and atomically discards all old transport authentication state.
        let currentChannel = EmbeddedChannel(handler: imapLogger)
        try await currentChannel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(
            makeAuthenticationCommand(tag: "ANEW", using: currentChannel.allocator)
        )))
        _ = try currentChannel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.authenticationSensitiveTagCount == 1)

        // A delayed terminal callback and inactive/removal callbacks from the
        // old pipeline must not add tags or clear the new generation.
        oldHandler.failAuthentication()
        #expect(imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.authenticationSensitiveTagCount == 1)
        try await oldChannel.close().get()
        _ = try? oldChannel.finish(acceptAlreadyClosed: true)
        #expect(imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.authenticationSensitiveTagCount == 1)

        try currentChannel.writeInbound(Response.tagged(TaggedResponse(
            tag: "ANEW",
            state: .no(ResponseText(text: "current-generation-terminal-sentinel"))
        )))
        _ = try currentChannel.readInbound(as: Response.self)
        #expect(!imapLogger.isAuthenticationRedactionActive)
        #expect(imapLogger.authenticationSensitiveTagCount == 1)
        try await currentChannel.close().get()
        _ = try? currentChannel.finish(acceptAlreadyClosed: true)
        #expect(imapLogger.authenticationSensitiveTagCount == 0)

        // Repeated reconnect/auth cycles remain bounded to exactly one tag
        // while live and return to zero at transport retirement.
        for index in 0..<32 {
            let channel = EmbeddedChannel(handler: imapLogger)
            let tag = "R\(index)"
            try await channel.writeAndFlush(IMAPClientHandler.OutboundIn.part(.tagged(
                makeAuthenticationCommand(tag: tag, using: channel.allocator)
            )))
            _ = try channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
            #expect(imapLogger.authenticationSensitiveTagCount == 1)

            try channel.writeInbound(Response.tagged(TaggedResponse(
                tag: tag,
                state: .no(ResponseText(text: "reconnect-auth-terminal-sentinel"))
            )))
            _ = try channel.readInbound(as: Response.self)
            #expect(imapLogger.authenticationSensitiveTagCount == 1)

            try await channel.close().get()
            _ = try? channel.finish(acceptAlreadyClosed: true)
            #expect(imapLogger.authenticationSensitiveTagCount == 0)
        }

        imapLogger.flushInboundBuffer()
        #expect(!capture.joinedMessages.contains("current-generation-terminal-sentinel"))
        #expect(!capture.joinedMessages.contains("reconnect-auth-terminal-sentinel"))
    }

    @Test
    func adoptedCandidateOwnsAuthenticationAndOrdinaryLoggingInBothInitializationOrders() async throws {
        for order in CandidateInitializationOrder.allCases {
            try await verifyAdoptedCandidateLoggerAuthority(order: order)
        }
    }

    @Test
    func connectOverridePublishesOnlyAdoptedCandidateLoggerInBothOrders() async throws {
        for order in CandidateInitializationOrder.allCases {
            try await verifyConnectOverrideCandidateLoggerAuthority(order: order)
        }
    }

    @Test
    func candidateLoggerAuthorityRemainsBoundedAcrossRepeatedReconnects() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let registry = CandidateLoggerRegistry()
        let connection = makeCandidateLoggerConnection(group: group, registry: registry)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)

        for index in 0..<32 {
            let eventLoop = NIOAsyncTestingEventLoop()
            let winner = NIOAsyncTestingChannel(loop: eventLoop)
            let loser = NIOAsyncTestingChannel(loop: eventLoop)
            try await winner.connect(to: address).get()
            try await loser.connect(to: address).get()

            if index.isMultiple(of: 2) {
                _ = try await connection.prepareCandidateChannel(loser)
                let preparedWinner = try await connection.prepareCandidateChannel(winner)
                try await connection.prepareEstablishedChannel(
                    winner,
                    capabilities: candidateAuthenticationCapabilities
                )
                #expect(registry.logger(for: winner) === preparedWinner)
            } else {
                let preparedWinner = try await connection.prepareCandidateChannel(winner)
                try await connection.prepareEstablishedChannel(
                    winner,
                    capabilities: candidateAuthenticationCapabilities
                )
                #expect(registry.logger(for: winner) === preparedWinner)
            }

            let winnerLogger = try #require(registry.logger(for: winner))
            let auth = Task {
                try await connection.authenticateXOAUTH2(
                    email: "fixture@example.invalid",
                    accessToken: "fixture-access-token"
                )
            }
            let authCommand = try await nextTaggedCommand(on: winner)
            try await waitForCandidateCondition { winnerLogger.isAuthenticationRedactionActive }

            if !index.isMultiple(of: 2) {
                _ = try await connection.prepareCandidateChannel(loser)
            }
            let loserLogger = try #require(registry.logger(for: loser))
            let winnerBuffer = try #require(registry.responseBuffer(for: winner))
            let loserBuffer = try #require(registry.responseBuffer(for: loser))
            #expect(winnerLogger !== loserLogger)
            #expect(winnerBuffer !== loserBuffer)
            #expect(await pipelineContains(responseBuffer: winnerBuffer, on: winner))
            #expect(!(await pipelineContains(responseBuffer: loserBuffer, on: loser)))
            #expect(winnerLogger.isAuthenticationRedactionActive)
            #expect(!loserLogger.isAuthenticationRedactionActive)
            #expect(winnerLogger.authenticationSensitiveTagCount == 1)
            #expect(loserLogger.authenticationSensitiveTagCount == 0)
            #expect(connection.pendingGreetingCount == 1)
            #expect(await connection.hasInstalledGreetingHandler(on: loser))

            try await loser.close().get()
            #expect(winnerLogger.isAuthenticationRedactionActive)
            #expect(winnerLogger.authenticationSensitiveTagCount == 1)
            #expect(loserLogger.authenticationSensitiveTagCount == 0)
            #expect(connection.pendingGreetingCount == 0)

            _ = try await winner.writeInbound(authenticationSuccess(tag: authCommand.tag))
            _ = try? await winner.readInbound(as: Response.self)
            try await auth.value

            try await connection.disconnect()
            #expect(connection.ownedTransportCount == 0)
            #expect(winnerLogger.authenticationSensitiveTagCount == 0)
            #expect(loserLogger.authenticationSensitiveTagCount == 0)
            #expect(!winnerBuffer.hasActiveHandler)
            #expect(!loserBuffer.hasActiveHandler)
            #expect(winnerBuffer.bufferedCount == 0)
            #expect(loserBuffer.bufferedCount == 0)
            #expect(!winner.isActive)
            #expect(!loser.isActive)
            #expect(connection.pendingGreetingCount == 0)

            _ = try? await loser.finish(acceptAlreadyClosed: true)
            _ = try? await winner.finish(acceptAlreadyClosed: true)
        }

        #expect(registry.creationCount == 64)
        #expect(registry.responseBufferCreationCount == 64)
        try await group.shutdownGracefully()
    }

    @Test
    func concurrentCandidatePreparationAndAdoptionInstallFactoriesAndBufferOnce() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let registry = CandidateLoggerRegistry()
        let connection = makeCandidateLoggerConnection(group: group, registry: registry)
        let channel = NIOAsyncTestingChannel()
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()

        try await withThrowingTaskGroup(of: IMAPLogger.self) { preparations in
            for _ in 0..<32 {
                preparations.addTask {
                    try await connection.prepareCandidateChannel(channel)
                }
            }
            for try await logger in preparations {
                #expect(logger === registry.logger(for: channel))
            }
        }

        let preparedCapabilitySets: [Set<Capability>] = [[.idle], [.id]]
        try await withThrowingTaskGroup(of: Void.self) { adoptionsAndReaders in
            for index in 0..<32 {
                let capabilitySet = preparedCapabilitySets[index % preparedCapabilitySets.count]
                adoptionsAndReaders.addTask {
                    try await connection.prepareEstablishedChannel(
                        channel,
                        capabilities: capabilitySet
                    )
                }
            }
            for _ in 0..<32 {
                adoptionsAndReaders.addTask {
                    for _ in 0..<128 {
                        let snapshot = connection.capabilitiesSnapshot
                        #expect(snapshot.isEmpty || preparedCapabilitySets.contains(snapshot))
                        _ = connection.supportsCapability { $0 == .idle }
                        _ = connection.supportsCapability { $0 == .id }
                        await Task.yield()
                    }
                }
            }
            try await adoptionsAndReaders.waitForAll()
        }

        let responseBuffer = try #require(registry.responseBuffer(for: channel))
        #expect(registry.creationCount == 1)
        #expect(registry.responseBufferCreationCount == 1)
        #expect(await pipelineContains(responseBuffer: responseBuffer, on: channel))

        _ = try await channel.writeInbound(Response.untagged(.mailboxData(.exists(71))))
        _ = try? await channel.readInbound(as: Response.self)
        let events = connection.drainBufferedEvents()
        #expect(events.count == 1)
        if case .some(.exists(let count)) = events.first {
            #expect(count == 71)
        } else {
            Issue.record("Expected one buffered EXISTS event")
        }

        try await connection.disconnect()
        #expect(connection.ownedTransportCount == 0)
        #expect(!responseBuffer.hasActiveHandler)
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func duplicateConnectOverrideRegistrationSharesOneCandidateSetup() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let registry = CandidateLoggerRegistry()
        let channel = NIOAsyncTestingChannel()
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()

        let connection = IMAPConnection(
            host: "invalid.invalid",
            port: 993,
            group: group,
            loggerLabel: "test.imap.duplicate-candidate",
            outboundLabel: "test.imap.duplicate-candidate.out",
            inboundLabel: "test.imap.duplicate-candidate.in",
            connectOverride: { registerChannel in
                let registrations = (0..<32).map { _ in registerChannel(channel) }
                return EventLoopFuture.andAllSucceed(registrations, on: channel.eventLoop).map { channel }
            },
            candidateLoggerFactory: { candidate in registry.makeLogger(for: candidate) },
            candidateResponseBufferFactory: { candidate in registry.makeResponseBuffer(for: candidate) }
        )

        let connect = Task { try await connection.connect() }
        try await waitForCandidateCondition {
            connection.isConnected && connection.hasActiveResponseHandler
        }
        _ = try await channel.writeInbound(Response.untagged(.conditionalState(.ok(.init(
            code: .capability([.imap4rev1]),
            text: "candidate-ready"
        )))))
        _ = try? await channel.readInbound(as: Response.self)
        try await connect.value

        let responseBuffer = try #require(registry.responseBuffer(for: channel))
        #expect(registry.creationCount == 1)
        #expect(registry.responseBufferCreationCount == 1)
        #expect(await pipelineContains(responseBuffer: responseBuffer, on: channel))

        try await connection.disconnect()
        #expect(connection.ownedTransportCount == 0)
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func closedCandidateSetupFailureRetiresFactoriesAndTransport() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let registry = CandidateLoggerRegistry()
        let channel = NIOAsyncTestingChannel()
        try await channel.close().get()

        let connection = IMAPConnection(
            host: "invalid.invalid",
            port: 993,
            group: group,
            loggerLabel: "test.imap.failed-candidate",
            outboundLabel: "test.imap.failed-candidate.out",
            inboundLabel: "test.imap.failed-candidate.in",
            connectOverride: { registerChannel in
                registerChannel(channel).map { channel }
            },
            candidateLoggerFactory: { candidate in registry.makeLogger(for: candidate) },
            candidateResponseBufferFactory: { candidate in registry.makeResponseBuffer(for: candidate) }
        )

        do {
            try await connection.connect()
            Issue.record("Expected closed candidate pipeline setup to fail")
        } catch {
            // The precise NIO setup category is intentionally not public API.
        }

        try await waitForCandidateCondition { connection.ownedTransportCount == 0 }
        #expect(registry.creationCount == 1)
        #expect(registry.responseBufferCreationCount == 1)
        #expect(!connection.hasActiveResponseHandler)
        #expect(connection.pendingGreetingCount == 0)
        #expect(!(await connection.hasInstalledGreetingHandler(on: channel)))
        #expect(connection.drainBufferedEvents().isEmpty)
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func earlyCandidateGreetingsAreIsolatedAndWinnerPlainGreetingRefreshesInBothOrders() async throws {
        for order in CandidateInitializationOrder.allCases {
            try await verifyEarlyCandidateGreetingAuthority(order: order)
        }
    }

    @Test
    func xoauthSuccessWithoutCapabilitiesRefreshesWithinItsQueueLease() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let channel = NIOAsyncTestingChannel()
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let connection = IMAPConnection(
            host: "invalid.invalid",
            port: 993,
            group: group,
            loggerLabel: "test.imap.xoauth-refresh",
            outboundLabel: "test.imap.xoauth-refresh.out",
            inboundLabel: "test.imap.xoauth-refresh.in"
        )
        try await connection.prepareEstablishedChannel(
            channel,
            capabilities: candidateAuthenticationCapabilities
        )

        let auth = Task {
            try await connection.authenticateXOAUTH2(
                email: "fixture@example.invalid",
                accessToken: "fixture-access-token"
            )
        }
        let authCommand = try await nextTaggedCommand(on: channel)
        _ = try await channel.writeInbound(Response.tagged(.init(
            tag: authCommand.tag,
            state: .ok(.init(text: "authentication-complete"))
        )))
        _ = try? await channel.readInbound(as: Response.self)

        let capability = try await nextTaggedCommand(on: channel)
        #expect(capability.command == .capability)
        _ = try await channel.writeInbound(Response.untagged(.capabilityData([.imap4rev1])))
        _ = try await channel.writeInbound(Response.tagged(.init(
            tag: capability.tag,
            state: .ok(.init(text: "capability-complete"))
        )))
        _ = try? await channel.readInbound(as: Response.self)
        try await auth.value

        #expect(connection.capabilitiesSnapshot == [.imap4rev1])
        #expect(connection.pendingGreetingCount == 0)
        try await connection.disconnect()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func xoauthReconnectUsesNewGenerationSASLIRCapability() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let oldChannel = NIOAsyncTestingChannel()
        let newChannel = NIOAsyncTestingChannel()
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await oldChannel.connect(to: address).get()
        try await newChannel.connect(to: address).get()
        let newCapabilities: [Capability] = [
            .imap4rev1,
            .authenticate(AuthenticationMechanism("XOAUTH2")),
        ]
        let connection = IMAPConnection(
            host: "invalid.invalid",
            port: 993,
            group: group,
            loggerLabel: "test.imap.xoauth-generation",
            outboundLabel: "test.imap.xoauth-generation.out",
            inboundLabel: "test.imap.xoauth-generation.in",
            connectOverride: { registerChannel in
                registerChannel(newChannel).map { newChannel }
            }
        )
        try await connection.prepareEstablishedChannel(
            oldChannel,
            capabilities: candidateAuthenticationCapabilities
        )
        try await oldChannel.close().get()

        let auth = Task {
            try await connection.authenticateXOAUTH2(
                email: "fixture@example.invalid",
                accessToken: "fixture-access-token"
            )
        }
        try await waitForCandidateCondition {
            connection.isConnected && connection.hasActiveResponseHandler
        }
        _ = try await newChannel.writeInbound(Response.untagged(.conditionalState(.ok(.init(
            code: .capability(newCapabilities),
            text: "new-generation-ready"
        )))))
        _ = try? await newChannel.readInbound(as: Response.self)

        let authCommand = try await nextTaggedCommand(on: newChannel)
        guard case .authenticate(_, let initialResponse) = authCommand.command else {
            Issue.record("Expected XOAUTH2 AUTHENTICATE command")
            await connection.hardAbort()
            _ = await auth.result
            _ = try? await oldChannel.finish(acceptAlreadyClosed: true)
            _ = try? await newChannel.finish(acceptAlreadyClosed: true)
            try await group.shutdownGracefully()
            return
        }
        // The retired generation advertised SASL-IR; the new one does not.
        // Credentials must therefore wait for a challenge on this transport.
        #expect(initialResponse == nil)

        _ = try await newChannel.writeInbound(Response.authenticationChallenge(ByteBuffer()))
        let continuation = try await newChannel.waitForOutboundWrite(as: IMAPClientHandler.OutboundIn.self)
        guard case .part(.continuationResponse) = continuation else {
            Issue.record("Expected challenge-driven XOAUTH2 continuation")
            await connection.hardAbort()
            _ = await auth.result
            _ = try? await oldChannel.finish(acceptAlreadyClosed: true)
            _ = try? await newChannel.finish(acceptAlreadyClosed: true)
            try await group.shutdownGracefully()
            return
        }

        _ = try await newChannel.writeInbound(Response.tagged(.init(
            tag: authCommand.tag,
            state: .ok(.init(code: .capability(newCapabilities), text: "authentication-complete"))
        )))
        _ = try? await newChannel.readInbound(as: Response.self)
        try await auth.value
        #expect(!connection.capabilitiesSnapshot.contains(.saslIR))

        try await connection.disconnect()
        _ = try? await oldChannel.finish(acceptAlreadyClosed: true)
        _ = try? await newChannel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func reconnectWaitsForOldHandlerRemovalAndNeverReplaysItsBuffer() async throws {
        for trigger in CandidateReconnectTrigger.allCases {
            try await verifyOldGenerationBufferIsolation(trigger: trigger)
        }
    }
}

private enum CandidateInitializationOrder: CaseIterable, Sendable {
    case loserBeforeWinner
    case winnerBeforeLateLoser
}

private enum CandidateReconnectTrigger: CaseIterable, Sendable {
    case directConnect
    case noopAutomaticReconnect
}

private let candidateAuthenticationCapabilities: Set<Capability> = [
    .imap4rev1,
    .authenticate(AuthenticationMechanism("XOAUTH2")),
    .saslIR,
]

private func verifyEarlyCandidateGreetingAuthority(
    order: CandidateInitializationOrder
) async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let eventLoop = NIOAsyncTestingEventLoop()
    let winner = NIOAsyncTestingChannel(loop: eventLoop)
    let loser = NIOAsyncTestingChannel(loop: eventLoop)
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await winner.connect(to: address).get()
    try await loser.connect(to: address).get()
    let adoptionPromise = group.next().makePromise(of: Channel.self)
    let registry = CandidateLoggerRegistry()

    let connection = IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.imap.early-greeting",
        outboundLabel: "test.imap.early-greeting.out",
        inboundLabel: "test.imap.early-greeting.in",
        connectOverride: { registerChannel in
            let registrations: EventLoopFuture<Void>
            switch order {
            case .loserBeforeWinner:
                registrations = registerChannel(loser).flatMap { registerChannel(winner) }
            case .winnerBeforeLateLoser:
                registrations = registerChannel(winner).flatMap { registerChannel(loser) }
            }
            registrations.whenFailure { adoptionPromise.fail($0) }
            return adoptionPromise.futureResult
        },
        candidateLoggerFactory: { channel in registry.makeLogger(for: channel) },
        candidateResponseBufferFactory: { channel in registry.makeResponseBuffer(for: channel) }
    )

    let connect = Task { try await connection.connect() }
    try await waitForCandidateCondition {
        registry.creationCount == 2 && connection.pendingGreetingCount == 2
    }
    try await waitForCandidateCondition {
        let winnerInstalled = await connection.hasInstalledGreetingHandler(on: winner)
        let loserInstalled = await connection.hasInstalledGreetingHandler(on: loser)
        return winnerInstalled && loserInstalled
    }
    #expect(await connection.hasInstalledGreetingHandler(on: winner))
    #expect(await connection.hasInstalledGreetingHandler(on: loser))

    // The loser advertises IDLE while the winner greeting is deliberately plain.
    // If candidate promises are shared, the loser can incorrectly suppress the
    // winner's mandatory CAPABILITY command after adoption.
    _ = try await loser.writeInbound(Response.untagged(.conditionalState(.ok(.init(
        code: .capability([.idle]),
        text: "loser-ready"
    )))))
    _ = try? await loser.readInbound(as: Response.self)
    _ = try await winner.writeInbound(Response.untagged(.conditionalState(.ok(.init(
        text: "winner-ready"
    )))))
    _ = try? await winner.readInbound(as: Response.self)
    #expect(connection.pendingGreetingCount == 0)

    adoptionPromise.succeed(winner)
    let capability = try await nextTaggedCommand(on: winner)
    #expect(capability.command == .capability)
    _ = try await winner.writeInbound(Response.untagged(.capabilityData([.imap4rev1])))
    _ = try await winner.writeInbound(Response.tagged(.init(
        tag: capability.tag,
        state: .ok(.init(text: "winner-capability-complete"))
    )))
    _ = try? await winner.readInbound(as: Response.self)
    try await connect.value

    #expect(connection.capabilitiesSnapshot == [.imap4rev1])
    #expect(!connection.capabilitiesSnapshot.contains(.idle))
    #expect(!(await connection.hasInstalledGreetingHandler(on: winner)))
    #expect(!(await connection.hasInstalledGreetingHandler(on: loser)))
    let winnerBuffer = try #require(registry.responseBuffer(for: winner))
    let loserBuffer = try #require(registry.responseBuffer(for: loser))
    #expect(await pipelineContains(responseBuffer: winnerBuffer, on: winner))
    #expect(!(await pipelineContains(responseBuffer: loserBuffer, on: loser)))

    try await connection.disconnect()
    #expect(connection.pendingGreetingCount == 0)
    #expect(connection.ownedTransportCount == 0)
    _ = try? await loser.finish(acceptAlreadyClosed: true)
    _ = try? await winner.finish(acceptAlreadyClosed: true)
    try await group.shutdownGracefully()
}

private func verifyOldGenerationBufferIsolation(
    trigger: CandidateReconnectTrigger
) async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let oldEventLoop = NIOAsyncTestingEventLoop()
    let newEventLoop = NIOAsyncTestingEventLoop()
    let inactiveBlocker = BlockingChannelInactiveHandler()
    let oldChannel = await NIOAsyncTestingChannel(handler: inactiveBlocker, loop: oldEventLoop)
    let newChannel = NIOAsyncTestingChannel(loop: newEventLoop)
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await oldChannel.connect(to: address).get()
    try await newChannel.connect(to: address).get()

    let registry = CandidateLoggerRegistry()
    let connection = IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.imap.buffer-generation",
        outboundLabel: "test.imap.buffer-generation.out",
        inboundLabel: "test.imap.buffer-generation.in",
        connectOverride: { registerChannel in
            registerChannel(newChannel).map { newChannel }
        },
        candidateLoggerFactory: { channel in registry.makeLogger(for: channel) },
        candidateResponseBufferFactory: { channel in registry.makeResponseBuffer(for: channel) }
    )
    try await connection.prepareEstablishedChannel(oldChannel)

    let oldBuffer = try #require(registry.responseBuffer(for: oldChannel))
    #expect(await pipelineContains(responseBuffer: oldBuffer, on: oldChannel))
    let staleResponses: [Response] = [
        .untagged(.mailboxData(.exists(41))),
        .untagged(.conditionalState(.ok(.init(code: .alert, text: "old-alert-marker")))),
        .untagged(.conditionalState(.bye(.init(text: "old-bye-marker")))),
        .fatal(.init(text: "old-fatal-marker")),
    ]
    for response in staleResponses {
        _ = try await oldChannel.writeInbound(response)
        _ = try? await oldChannel.readInbound(as: Response.self)
    }
    #expect(oldBuffer.bufferedCount == staleResponses.count)

    let oldClose = Task { try await oldChannel.close().get() }
    try await waitForCandidateCondition { inactiveBlocker.hasEntered }
    #expect(!oldChannel.isActive)

    let operation = Task { () throws -> [IMAPServerEvent]? in
        switch trigger {
        case .directConnect:
            try await connection.connect()
            return nil
        case .noopAutomaticReconnect:
            return try await connection.noop()
        }
    }

    // Neither direct connect nor the automatic NOOP reconnect may publish a
    // new generation until old channelInactive/handler removal/closeFuture is joined.
    try await Task.sleep(nanoseconds: 25_000_000)
    #expect(registry.creationCount == 1)
    #expect(registry.responseBufferCreationCount == 1)
    #expect(connection.ownedTransportCount == 1)
    #expect(connection.drainBufferedEvents().isEmpty)

    inactiveBlocker.release()
    try await oldClose.value
    try await waitForCandidateCondition {
        connection.isConnected && connection.hasActiveResponseHandler
    }
    _ = try await newChannel.writeInbound(Response.untagged(.conditionalState(.ok(.init(
        code: .capability([.imap4rev1]),
        text: "new-generation-ready"
    )))))
    _ = try? await newChannel.readInbound(as: Response.self)

    if trigger == .noopAutomaticReconnect {
        let noopCommand = try await nextTaggedCommand(on: newChannel)
        _ = try await newChannel.writeInbound(Response.tagged(.init(
            tag: noopCommand.tag,
            state: .ok(.init(text: "new-generation-noop-complete"))
        )))
        _ = try? await newChannel.readInbound(as: Response.self)
    }
    let operationEvents = try await operation.value
    #expect(operationEvents?.isEmpty ?? true)

    let newBuffer = try #require(registry.responseBuffer(for: newChannel))
    #expect(registry.creationCount == 2)
    #expect(registry.responseBufferCreationCount == 2)
    #expect(oldBuffer !== newBuffer)
    #expect(oldBuffer.bufferedCount == 0)
    #expect(!oldBuffer.hasActiveHandler)
    #expect(await pipelineContains(responseBuffer: newBuffer, on: newChannel))
    #expect(!(await pipelineContains(responseBuffer: oldBuffer, on: newChannel)))
    #expect(connection.drainBufferedEvents().isEmpty)

    _ = try await newChannel.writeInbound(Response.untagged(.mailboxData(.exists(99))))
    _ = try? await newChannel.readInbound(as: Response.self)
    let newEvents = connection.drainBufferedEvents()
    #expect(newEvents.count == 1)
    if case .some(.exists(let count)) = newEvents.first {
        #expect(count == 99)
    } else {
        Issue.record("Expected only the new generation EXISTS event")
    }

    try await connection.disconnect()
    #expect(connection.ownedTransportCount == 0)
    _ = try? await oldChannel.finish(acceptAlreadyClosed: true)
    _ = try? await newChannel.finish(acceptAlreadyClosed: true)
    try await group.shutdownGracefully()
}

private func verifyConnectOverrideCandidateLoggerAuthority(
    order: CandidateInitializationOrder
) async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let eventLoop = NIOAsyncTestingEventLoop()
    let winner = NIOAsyncTestingChannel(loop: eventLoop)
    let loser = NIOAsyncTestingChannel(loop: eventLoop)
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await winner.connect(to: address).get()
    try await loser.connect(to: address).get()

    let registry = CandidateLoggerRegistry()
    let connection = IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.imap.candidate.connect",
        outboundLabel: "test.imap.candidate.connect.out",
        inboundLabel: "test.imap.candidate.connect.in",
        connectOverride: { registerChannel in
            let registrations: EventLoopFuture<Void>
            switch order {
            case .loserBeforeWinner:
                registrations = registerChannel(loser).flatMap { registerChannel(winner) }
            case .winnerBeforeLateLoser:
                registrations = registerChannel(winner).flatMap { registerChannel(loser) }
            }
            return registrations.map { winner }
        },
        candidateLoggerFactory: { channel in registry.makeLogger(for: channel) },
        candidateResponseBufferFactory: { channel in registry.makeResponseBuffer(for: channel) }
    )

    let connect = Task { try await connection.connect() }
    try await waitForCandidateCondition {
        connection.isConnected && connection.hasActiveResponseHandler
    }
    _ = try await winner.writeInbound(Response.untagged(.conditionalState(.ok(.init(
        code: .capability(Array(candidateAuthenticationCapabilities)),
        text: "candidate-ready"
    )))))
    _ = try? await winner.readInbound(as: Response.self)
    try await connect.value

    let winnerLogger = try #require(registry.logger(for: winner))
    let loserLogger = try #require(registry.logger(for: loser))
    #expect(registry.entryCount == 2)
    #expect(winnerLogger !== loserLogger)

    let auth = Task {
        try await connection.authenticateXOAUTH2(
            email: "fixture@example.invalid",
            accessToken: "fixture-access-token"
        )
    }
    let authCommand = try await nextTaggedCommand(on: winner)
    try await waitForCandidateCondition { winnerLogger.isAuthenticationRedactionActive }
    #expect(!loserLogger.isAuthenticationRedactionActive)

    // A losing candidate may close after the winner has been adopted and AUTH
    // has begun. Its callbacks must remain local to its own logger instance.
    try await loser.close().get()
    #expect(winnerLogger.isAuthenticationRedactionActive)
    #expect(winnerLogger.authenticationSensitiveTagCount == 1)
    #expect(loserLogger.authenticationSensitiveTagCount == 0)

    _ = try await winner.writeInbound(authenticationSuccess(tag: authCommand.tag))
    _ = try? await winner.readInbound(as: Response.self)
    try await auth.value

    try await connection.disconnect()
    #expect(connection.ownedTransportCount == 0)
    #expect(winnerLogger.authenticationSensitiveTagCount == 0)
    #expect(loserLogger.authenticationSensitiveTagCount == 0)
    _ = try? await loser.finish(acceptAlreadyClosed: true)
    _ = try? await winner.finish(acceptAlreadyClosed: true)
    try await group.shutdownGracefully()
}

private func verifyAdoptedCandidateLoggerAuthority(
    order: CandidateInitializationOrder
) async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let eventLoop = NIOAsyncTestingEventLoop()
    let winner = NIOAsyncTestingChannel(loop: eventLoop)
    let loser = NIOAsyncTestingChannel(loop: eventLoop)
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await winner.connect(to: address).get()
    try await loser.connect(to: address).get()

    let registry = CandidateLoggerRegistry()
    let connection = makeCandidateLoggerConnection(group: group, registry: registry)

    switch order {
    case .loserBeforeWinner:
        _ = try await connection.prepareCandidateChannel(loser)
        let preparedWinner = try await connection.prepareCandidateChannel(winner)
        try await connection.prepareEstablishedChannel(
            winner,
            capabilities: candidateAuthenticationCapabilities
        )
        #expect(registry.logger(for: winner) === preparedWinner)
    case .winnerBeforeLateLoser:
        let preparedWinner = try await connection.prepareCandidateChannel(winner)
        try await connection.prepareEstablishedChannel(
            winner,
            capabilities: candidateAuthenticationCapabilities
        )
        #expect(registry.logger(for: winner) === preparedWinner)
    }

    let winnerLogger = try #require(registry.logger(for: winner))
    let winnerCapture = try #require(registry.capture(for: winner))
    let auth = Task {
        try await connection.authenticateXOAUTH2(
            email: "fixture@example.invalid",
            accessToken: "fixture-access-token"
        )
    }
    let authCommand = try await nextTaggedCommand(on: winner)
    try await waitForCandidateCondition { winnerLogger.isAuthenticationRedactionActive }

    if order == .winnerBeforeLateLoser {
        _ = try await connection.prepareCandidateChannel(loser)
    }
    let loserLogger = try #require(registry.logger(for: loser))
    let loserCapture = try #require(registry.capture(for: loser))
    #expect(registry.entryCount == 2)
    #expect(winnerLogger !== loserLogger)
    #expect(winnerLogger.isAuthenticationRedactionActive)
    #expect(!loserLogger.isAuthenticationRedactionActive)
    #expect(winnerLogger.authenticationSensitiveTagCount == 1)
    #expect(loserLogger.authenticationSensitiveTagCount == 0)

    if order == .winnerBeforeLateLoser {
        // The exact reproduced order: winner AUTH is live before a losing
        // candidate's handlerAdded/inactive/removed callbacks run.
        try await loser.close().get()
        #expect(winnerLogger.isAuthenticationRedactionActive)
        #expect(winnerLogger.authenticationSensitiveTagCount == 1)
    }

    _ = try await winner.writeInbound(authenticationSuccess(tag: authCommand.tag))
    _ = try? await winner.readInbound(as: Response.self)
    try await auth.value
    #expect(!winnerCapture.joinedMessages.contains("candidate-auth-terminal-sentinel"))

    if order == .loserBeforeWinner {
        try await loser.close().get()
    }
    #expect(winnerLogger.authenticationSensitiveTagCount == 1)
    #expect(loserLogger.authenticationSensitiveTagCount == 0)

    let ordinary = Task { try await connection.noop() }
    let ordinaryCommand = try await nextTaggedCommand(on: winner)
    _ = try await winner.writeInbound(Response.tagged(.init(
        tag: ordinaryCommand.tag,
        state: .ok(.init(text: "winner-ordinary-response-sentinel"))
    )))
    _ = try? await winner.readInbound(as: Response.self)
    _ = try await ordinary.value

    #expect(winnerCapture.joinedMessages.contains("winner-ordinary-response-sentinel"))
    #expect(!loserCapture.joinedMessages.contains("winner-ordinary-response-sentinel"))
    #expect(!loserCapture.joinedMessages.contains("candidate-auth-terminal-sentinel"))

    try await connection.disconnect()
    #expect(connection.ownedTransportCount == 0)
    #expect(winnerLogger.authenticationSensitiveTagCount == 0)
    #expect(loserLogger.authenticationSensitiveTagCount == 0)
    _ = try? await loser.finish(acceptAlreadyClosed: true)
    _ = try? await winner.finish(acceptAlreadyClosed: true)
    try await group.shutdownGracefully()
}

private func makeCandidateLoggerConnection(
    group: EventLoopGroup,
    registry: CandidateLoggerRegistry
) -> IMAPConnection {
    IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.imap.candidate.connection",
        outboundLabel: "test.imap.candidate.out",
        inboundLabel: "test.imap.candidate.in",
        candidateLoggerFactory: { channel in registry.makeLogger(for: channel) },
        candidateResponseBufferFactory: { channel in registry.makeResponseBuffer(for: channel) }
    )
}

private func nextTaggedCommand(on channel: NIOAsyncTestingChannel) async throws -> TaggedCommand {
    let outbound = try await channel.waitForOutboundWrite(as: IMAPClientHandler.OutboundIn.self)
    guard case .part(.tagged(let command)) = outbound else {
        Issue.record("Expected a tagged candidate-channel command")
        throw IMAPError.commandFailed("Expected tagged test command")
    }
    return command
}

private func authenticationSuccess(tag: String) -> Response {
    .tagged(.init(
        tag: tag,
        state: .ok(.init(
            code: .capability(Array(candidateAuthenticationCapabilities)),
            text: "candidate-auth-terminal-sentinel"
        ))
    ))
}

private func waitForCandidateCondition(
    timeoutNanoseconds: UInt64 = 2_000_000_000,
    condition: () async -> Bool
) async throws {
    let deadline = ContinuousClock().now.advanced(by: .nanoseconds(Int64(timeoutNanoseconds)))
    while !(await condition()) {
        if ContinuousClock().now >= deadline {
            throw IMAPError.timeout
        }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
}

private func pipelineContains(
    responseBuffer: UntaggedResponseBuffer,
    on channel: Channel
) async -> Bool {
    (try? await channel.eventLoop.submit {
        do {
            _ = try channel.pipeline.syncOperations.context(handler: responseBuffer)
            return true
        } catch {
            return false
        }
    }.get()) ?? false
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
        logger: logger,
        authenticationLogger: imapLogger
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

private func makeAuthenticationCommand(tag: String, using allocator: ByteBufferAllocator) -> TaggedCommand {
    TaggedCommand(
        tag: tag,
        command: .authenticate(
            mechanism: AuthenticationMechanism("XOAUTH2"),
            initialResponse: InitialResponse(makeCredentialBuffer(using: allocator))
        )
    )
}

private func credentialWireBase64() -> String {
    let raw = "user=fixture-user\u{01}auth=Bearer fixture-credential-wire-sentinel\u{01}\u{01}"
    return Data(raw.utf8).base64EncodedString()
}

private func fixedXOAUTH2Failure(
    from future: EventLoopFuture<[Capability]>
) async -> IMAPError {
    guard let result = await boundedFutureResult(future) else {
        Issue.record("Timed out waiting for fixed XOAUTH2 authentication failure")
        return .xoauth2AuthenticationFailed
    }

    do {
        _ = try result.get()
        Issue.record("Expected fixed XOAUTH2 authentication failure")
    } catch let error as IMAPError {
        if case .authFailed(let reason) = error {
            #expect(reason == IMAPError.xoauth2AuthenticationFailureReason)
        } else {
            Issue.record("Expected authFailed category")
        }
        return error
    } catch {
        Issue.record("Unexpected XOAUTH2 error type")
    }
    return .xoauth2AuthenticationFailed
}

private func boundedFutureResult<Value: Sendable>(
    _ future: EventLoopFuture<Value>,
    timeoutNanoseconds: UInt64 = 2_000_000_000
) async -> Result<Value, Error>? {
    await withCheckedContinuation { continuation in
        let box = BoundedResultBox<Value>(continuation: continuation)
        future.whenComplete { result in
            box.complete(result)
        }
        Task {
            try? await Task.sleep(nanoseconds: timeoutNanoseconds)
            box.complete(nil)
        }
    }
}

private final class BoundedResultBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<Value, Error>?, Never>?

    init(continuation: CheckedContinuation<Result<Value, Error>?, Never>) {
        self.continuation = continuation
    }

    func complete(_ result: Result<Value, Error>?) {
        let continuation = lock.withLock { () -> CheckedContinuation<Result<Value, Error>?, Never>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: result)
    }
}

private func errorSurfaces(_ error: Error) -> String {
    let nsError = error as NSError
    return [
        String(describing: error),
        String(reflecting: error),
        error.localizedDescription,
        nsError.localizedDescription,
        nsError.localizedFailureReason ?? "",
        String(describing: nsError),
        String(reflecting: nsError),
    ].joined(separator: " ")
}

private struct SensitivePipelineError: Error, LocalizedError, CustomStringConvertible, Sendable {
    let sentinel: String

    var description: String { sentinel }
    var errorDescription: String? { sentinel }
    var failureReason: String? { sentinel }
}

private final class SecondByteBufferWriteFailer: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let error: SensitivePipelineError
    private(set) var writeCount = 0
    private(set) var failedWriteCount = 0

    init(error: SensitivePipelineError) {
        self.error = error
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeCount += 1
        if writeCount == 2 {
            failedWriteCount += 1
            promise?.fail(error)
            return
        }
        context.write(data, promise: promise)
    }
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

private final class CandidateLoggerRegistry: @unchecked Sendable {
    private struct Entry {
        var logger: IMAPLogger? = nil
        var capture: LogCapture? = nil
        var responseBuffer: UntaggedResponseBuffer? = nil
    }

    private let lock = NSLock()
    private var entries: [ObjectIdentifier: Entry] = [:]
    private var storedCreationCount = 0
    private var storedResponseBufferCreationCount = 0

    var entryCount: Int {
        lock.withLock { entries.count }
    }

    var creationCount: Int {
        lock.withLock { storedCreationCount }
    }

    var responseBufferCreationCount: Int {
        lock.withLock { storedResponseBufferCreationCount }
    }

    func makeLogger(for channel: Channel) -> IMAPLogger {
        let capture = LogCapture()
        let logger = makeCaptureLogger(label: "test.imap.candidate.transport", capture: capture)
        let imapLogger = IMAPLogger(outboundLogger: logger, inboundLogger: logger)
        lock.withLock {
            storedCreationCount += 1
            let identifier = ObjectIdentifier(channel)
            var entry = entries[identifier] ?? Entry()
            entry.logger = imapLogger
            entry.capture = capture
            entries[identifier] = entry
        }
        return imapLogger
    }

    func makeResponseBuffer(for channel: Channel) -> UntaggedResponseBuffer {
        let responseBuffer = UntaggedResponseBuffer()
        lock.withLock {
            storedResponseBufferCreationCount += 1
            let identifier = ObjectIdentifier(channel)
            var entry = entries[identifier] ?? Entry()
            entry.responseBuffer = responseBuffer
            entries[identifier] = entry
        }
        return responseBuffer
    }

    func logger(for channel: Channel) -> IMAPLogger? {
        lock.withLock { entries[ObjectIdentifier(channel)]?.logger }
    }

    func capture(for channel: Channel) -> LogCapture? {
        lock.withLock { entries[ObjectIdentifier(channel)]?.capture }
    }

    func responseBuffer(for channel: Channel) -> UntaggedResponseBuffer? {
        lock.withLock { entries[ObjectIdentifier(channel)]?.responseBuffer }
    }
}

private final class BlockingChannelInactiveHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Response

    private let lock = NSLock()
    private let releaseSemaphore = DispatchSemaphore(value: 0)
    private var entered = false

    var hasEntered: Bool {
        lock.withLock { entered }
    }

    func channelInactive(context: ChannelHandlerContext) {
        lock.withLock { entered = true }
        releaseSemaphore.wait()
        context.fireChannelInactive()
    }

    func release() {
        releaseSemaphore.signal()
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
