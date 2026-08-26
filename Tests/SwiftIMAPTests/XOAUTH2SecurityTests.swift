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
