import Foundation
import NIO
import NIOEmbedded
@preconcurrency import NIOIMAP
import NIOIMAPCore
import Testing
@testable import SwiftMail

@Suite(.serialized)
struct MessageTransferTests {
    @Test
    func publicTypesAreSendableAndHugeMappingsStayCompact() throws {
        requireSendable(UIDMapping.self)
        requireSendable(MessageTransferResult.self)
        requireSendable(IMAPMutationFailure.self)

        let request = MessageIdentifierSet<SwiftMail.UID>(
            1...Int(UInt32.max)
        )
        let response = MessageTransferCommandResponse(
            copyUID: makeCOPYUID(
                validity: 91,
                source: [(1, 4_000_000_000), (4_000_000_001, UInt32.max)],
                destination: [(1, 2_000_000_000), (2_000_000_001, UInt32.max)]
            ),
            hasConflictingCopyUID: false
        )

        guard case .completed(let mapping) = MessageTransferResult.make(
            from: response,
            requested: request
        ) else {
            Issue.record("Expected a compact, valid mapping")
            return
        }

        #expect(mapping.destinationUIDValidity == UIDValidity(91))
        #expect(mapping.sourceRanges.count == 2)
        #expect(mapping.destinationRanges.count == 2)
        #expect(mapping.messageCount == UInt64(UInt32.max))
    }

    @Test
    func mappingRequiresExactUIDSourceButAcceptsEquivalentSegmentation() {
        let request = MessageIdentifierSet<SwiftMail.UID>(ranges: 1...3, 5...6)
        let equivalent = transferResponse(
            source: [(1, 2), (3, 3), (5, 6)],
            destination: [(101, 102), (103, 103), (200, 201)]
        )
        guard case .completed(let mapping) = MessageTransferResult.make(
            from: equivalent,
            requested: request
        ) else {
            Issue.record("Equivalent compact source segmentation should validate")
            return
        }
        #expect(mapping.sourceRanges.count == 3)
        #expect(mapping.messageCount == 5)

        let mismatch = transferResponse(
            source: [(1, 3), (5, 7)],
            destination: [(101, 103), (200, 202)]
        )
        #expect(
            MessageTransferResult.make(from: mismatch, requested: request)
                == .completedRequiringReconciliation(.requestedSourceMismatch)
        )
    }

    @Test
    func invalidCOPYUIDMatricesRequireReconciliation() {
        let request = MessageIdentifierSet<SwiftMail.UID>(1...3)

        #expect(
            MessageTransferResult.make(
                from: .init(copyUID: nil, hasConflictingCopyUID: false),
                requested: request
            ) == .completedRequiringReconciliation(.mappingUnavailable)
        )
        #expect(
            MessageTransferResult.make(
                from: transferResponse(source: [(1, 3)], destination: [(10, 11)]),
                requested: request
            ) == .completedRequiringReconciliation(.mappingMalformed)
        )
        #expect(
            MessageTransferResult.make(
                from: transferResponse(
                    source: [(1, 2), (2, 3)],
                    destination: [(10, 11), (12, 13)]
                ),
                requested: request
            ) == .completedRequiringReconciliation(.mappingMalformed)
        )
        #expect(
            MessageTransferResult.make(
                from: transferResponse(
                    source: [(3, 3), (1, 2)],
                    destination: [(10, 10), (11, 12)]
                ),
                requested: request
            ) == .completedRequiringReconciliation(.mappingMalformed)
        )
        #expect(
            MessageTransferResult.make(
                from: .init(
                    copyUID: makeCOPYUID(validity: 7, source: [(1, 3)], destination: [(10, 12)]),
                    hasConflictingCopyUID: true
                ),
                requested: request
            ) == .completedRequiringReconciliation(.conflictingMappings)
        )
    }

    @Test
    func sequenceRequestNeverClaimsUIDMapping() {
        let request = MessageIdentifierSet<SwiftMail.SequenceNumber>(1...2)
        let response = transferResponse(source: [(1, 2)], destination: [(20, 21)])
        #expect(
            MessageTransferResult.make(from: response, requested: request)
                == .completedRequiringReconciliation(.sourceIdentityUnprovable)
        )
    }

    @Test
    func handlerCollectsTaggedAndUntaggedCOPYUIDAndAcceptsIdenticalDuplicate() async throws {
        let code = makeCOPYUID(validity: 44, source: [(1, 2)], destination: [(11, 12)])
        let eventLoop = EmbeddedEventLoop()
        let promise = eventLoop.makePromise(of: MessageTransferCommandResponse.self)
        let handler = CopyHandler(commandTag: "A1", promise: promise)
        let channel = EmbeddedChannel(handler: handler, loop: eventLoop)

        try channel.writeInbound(untaggedOK(code))
        _ = try? channel.readInbound(as: Response.self)
        try channel.writeInbound(taggedOK(tag: "A1", code: code))
        _ = try? channel.readInbound(as: Response.self)

        let response = try await promise.futureResult.get()
        #expect(response.copyUID == code)
        #expect(!response.hasConflictingCopyUID)
        _ = try? channel.finish(acceptAlreadyClosed: true)
    }

    @Test
    func handlerRejectsConflictingTaggedAndUntaggedCOPYUID() async throws {
        let first = makeCOPYUID(validity: 44, source: [(1, 2)], destination: [(11, 12)])
        let second = makeCOPYUID(validity: 44, source: [(1, 2)], destination: [(21, 22)])
        let eventLoop = EmbeddedEventLoop()
        let promise = eventLoop.makePromise(of: MessageTransferCommandResponse.self)
        let handler = MoveHandler(commandTag: "A2", promise: promise)
        let channel = EmbeddedChannel(handler: handler, loop: eventLoop)

        try channel.writeInbound(untaggedOK(first))
        _ = try? channel.readInbound(as: Response.self)
        try channel.writeInbound(taggedOK(tag: "A2", code: second))
        _ = try? channel.readInbound(as: Response.self)

        let response = try await promise.futureResult.get()
        #expect(response.copyUID == first)
        #expect(response.hasConflictingCopyUID)
        _ = try? channel.finish(acceptAlreadyClosed: true)
    }

    @Test
    func copyResultAcceptsUntaggedCOPYUIDAndVoidWrapperDiscardsResult() async throws {
        let result = try await runTransfer(
            capabilities: [],
            operation: { server in
                try await server.copyWithResult(
                    messages: MessageIdentifierSet<SwiftMail.UID>(1...2),
                    to: "Destination"
                )
            },
            responses: { tag in
                let code = makeCOPYUID(validity: 33, source: [(1, 2)], destination: [(51, 52)])
                return [untaggedOK(code), taggedOK(tag: tag, code: nil)]
            }
        )
        #expect(result.result == .completed(UIDMapping(
            destinationUIDValidity: UIDValidity(33),
            sourceRanges: [UIDMapping.Range(lowerBound: .init(1), upperBound: .init(2))],
            destinationRanges: [UIDMapping.Range(lowerBound: .init(51), upperBound: .init(52))],
            messageCount: 2
        )))
        guard case .uidCopy = result.command.command else {
            Issue.record("Expected UID COPY")
            return
        }

        _ = try await runTransfer(
            capabilities: [],
            operation: { server in
                try await server.copy(
                    messages: MessageIdentifierSet<SwiftMail.UID>(9),
                    to: "Destination"
                )
                return .completedRequiringReconciliation(.mappingUnavailable)
            },
            responses: { tag in [taggedOK(tag: tag, code: nil)] }
        )
    }

    @Test
    func nativeUIDMoveNeedsMOVEButNotUIDPLUS() async throws {
        let result = try await runTransfer(
            capabilities: [.move],
            operation: { server in
                try await server.moveWithResult(
                    messages: MessageIdentifierSet<SwiftMail.UID>(7),
                    to: "Archive"
                )
            },
            responses: { tag in
                [taggedOK(
                    tag: tag,
                    code: makeCOPYUID(validity: 8, source: [(7, 7)], destination: [(70, 70)])
                )]
            }
        )
        guard case .uidMove = result.command.command else {
            Issue.record("Expected native UID MOVE without requiring UIDPLUS")
            return
        }
        guard case .completed(let mapping) = result.result else {
            Issue.record("Expected proven native MOVE mapping")
            return
        }
        #expect(mapping.destinationUIDValidity == UIDValidity(8))
        #expect(mapping.destinationRanges.first?.lowerBound == SwiftMail.UID(70))
    }

    @Test
    func moveWithoutExtensionAndInvalidCopyAreDefinitelyNotApplied() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = NIOAsyncTestingChannel(loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
        try await server.preparePrimaryEstablishedChannel(channel, capabilities: [])
        do {
            _ = try await server.moveWithResult(
                messages: MessageIdentifierSet<SwiftMail.UID>(1),
                to: "Archive"
            )
            Issue.record("Expected unsupported native MOVE refusal")
        } catch let failure as IMAPMutationFailure {
            #expect(failure.operation == .move)
            #expect(failure.phase == .validation)
            #expect(failure.certainty == .definitelyNotApplied)
            #expect(failure.reason == .unsupportedOperation)
        }

        do {
            _ = try await server.copyWithResult(
                messages: MessageIdentifierSet<SwiftMail.UID>(),
                to: "Archive"
            )
            Issue.record("Expected empty request rejection")
        } catch let failure as IMAPMutationFailure {
            #expect(failure.operation == .copy)
            #expect(failure.phase == .validation)
            #expect(failure.certainty == .definitelyNotApplied)
            #expect(failure.reason == .invalidRequest)
        }
        let unexpectedWrite = try await channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(unexpectedWrite == nil)
        await server.hardAbort()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func taggedRejectionAfterSingleWriteIsOutcomeUnknownAndNeverRetried() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = NIOAsyncTestingChannel(loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
        try await server.preparePrimaryEstablishedChannel(channel)

        let operation = Task {
            try await server.copyWithResult(
                messages: MessageIdentifierSet<SwiftMail.UID>(1),
                to: "Destination"
            )
        }
        let command = try await nextTransferCommand(on: channel)
        _ = try await channel.writeInbound(Response.tagged(.init(
            tag: command.tag,
            state: .no(.init(text: "fixed-test-rejection"))
        )))
        _ = try? await channel.readInbound(as: Response.self)

        do {
            _ = try await operation.value
            Issue.record("Expected tagged rejection")
        } catch let failure as IMAPMutationFailure {
            #expect(failure.phase == .response)
            #expect(failure.certainty == .outcomeUnknown)
            #expect(failure.reason == .serverRejected)
        }
        let unexpectedWrite = try await channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(unexpectedWrite == nil)

        await server.hardAbort()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func writeFailureAfterDispatchAttemptIsOutcomeUnknownAndNeverRetried() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let failureHandler = TransferWriteFailureHandler()
        let channel = await NIOAsyncTestingChannel(handler: failureHandler, loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
        try await server.preparePrimaryEstablishedChannel(channel)

        do {
            _ = try await server.copyWithResult(
                messages: MessageIdentifierSet<SwiftMail.UID>(4),
                to: "Destination"
            )
            Issue.record("Expected transfer write failure")
        } catch let failure as IMAPMutationFailure {
            #expect(failure.operation == .copy)
            #expect(failure.phase == .dispatch)
            #expect(failure.certainty == .outcomeUnknown)
        }
        #expect(failureHandler.transferWriteCount == 1)

        await server.hardAbort()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func retiredConnectionRefusalBeforeWriteIsDefinitelyNotApplied() async throws {
        let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
        await server.hardAbort()

        do {
            _ = try await server.copyWithResult(
                messages: MessageIdentifierSet<SwiftMail.UID>(4),
                to: "Destination"
            )
            Issue.record("Expected retired connection refusal")
        } catch let failure as IMAPMutationFailure {
            #expect(failure.operation == .copy)
            #expect(failure.phase == .dispatch)
            #expect(failure.certainty == .definitelyNotApplied)
            #expect(failure.reason == .transportFailure)
        }
    }

    @Test
    func connectionRevalidatesMOVEImmediatelyBeforeDispatch() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = NIOAsyncTestingChannel(loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let connection = IMAPConnection(
            host: "invalid.invalid",
            port: 993,
            group: group,
            loggerLabel: "test.transfer.connection",
            outboundLabel: "test.transfer.out",
            inboundLabel: "test.transfer.in"
        )
        try await connection.prepareEstablishedChannel(channel, capabilities: [])
        let command = MoveCommand(
            identifierSet: MessageIdentifierSet<SwiftMail.UID>(1),
            destinationMailbox: "Archive"
        )

        do {
            _ = try await connection.executeCommand(command)
            Issue.record("Expected exact-transport MOVE capability refusal")
        } catch let error as MessageTransferCommandError {
            guard case .unsupportedOperation = error else {
                Issue.record("Unexpected transfer command error")
                return
            }
        }
        #expect(command.dispatchTracker.state == .notStarted)
        let unexpectedWrite = try await channel.readOutbound(as: IMAPClientHandler.OutboundIn.self)
        #expect(unexpectedWrite == nil)

        await connection.hardAbort()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }
}

private struct ExpectedTransferWriteFailure: Error {}

private final class TransferWriteFailureHandler: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = IMAPClientHandler.OutboundIn

    private let lock = NSLock()
    private var storedTransferWriteCount = 0

    var transferWriteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedTransferWriteCount
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let outbound = unwrapOutboundIn(data)
        guard case .part(.tagged(let tagged)) = outbound else {
            context.write(data, promise: promise)
            return
        }
        switch tagged.command {
        case .copy, .uidCopy, .move, .uidMove:
            lock.lock()
            storedTransferWriteCount += 1
            lock.unlock()
            promise?.fail(ExpectedTransferWriteFailure())
        default:
            context.write(data, promise: promise)
        }
    }
}

private func requireSendable<T: Sendable>(_ type: T.Type) {}

private func transferResponse(
    validity: UInt32 = 5,
    source: [(UInt32, UInt32)],
    destination: [(UInt32, UInt32)]
) -> MessageTransferCommandResponse {
    .init(
        copyUID: makeCOPYUID(validity: validity, source: source, destination: destination),
        hasConflictingCopyUID: false
    )
}

private func makeCOPYUID(
    validity: UInt32,
    source: [(UInt32, UInt32)],
    destination: [(UInt32, UInt32)]
) -> ResponseCodeCopy {
    ResponseCodeCopy(
        destinationUIDValidity: NIOIMAPCore.UIDValidity(exactly: validity)!,
        sourceUIDs: source.map { bounds in
            NIOIMAPCore.UIDRange(
                NIOIMAPCore.UID(rawValue: bounds.0)...NIOIMAPCore.UID(rawValue: bounds.1)
            )
        },
        destinationUIDs: destination.map { bounds in
            NIOIMAPCore.UIDRange(
                NIOIMAPCore.UID(rawValue: bounds.0)...NIOIMAPCore.UID(rawValue: bounds.1)
            )
        }
    )
}

private func untaggedOK(_ code: ResponseCodeCopy) -> Response {
    .untagged(.conditionalState(.ok(.init(code: .uidCopy(code), text: "completed"))))
}

private func taggedOK(tag: String, code: ResponseCodeCopy?) -> Response {
    .tagged(.init(
        tag: tag,
        state: .ok(.init(code: code.map(ResponseTextCode.uidCopy), text: "completed"))
    ))
}

private func nextTransferCommand(on channel: NIOAsyncTestingChannel) async throws -> TaggedCommand {
    let outbound = try await channel.waitForOutboundWrite(as: IMAPClientHandler.OutboundIn.self)
    guard case .part(.tagged(let command)) = outbound else {
        throw IMAPError.commandFailed("Expected tagged test command")
    }
    return command
}

private func runTransfer(
    capabilities: Set<NIOIMAPCore.Capability>,
    operation: @escaping @Sendable (SwiftMail.IMAPServer) async throws -> MessageTransferResult,
    responses: @escaping @Sendable (String) -> [Response]
) async throws -> (result: MessageTransferResult, command: TaggedCommand) {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let eventLoop = NIOAsyncTestingEventLoop()
    let channel = NIOAsyncTestingChannel(loop: eventLoop)
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await channel.connect(to: address).get()
    let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
    try await server.preparePrimaryEstablishedChannel(channel, capabilities: capabilities)

    let task = Task { try await operation(server) }
    let command = try await nextTransferCommand(on: channel)
    for response in responses(command.tag) {
        _ = try await channel.writeInbound(response)
        _ = try? await channel.readInbound(as: Response.self)
    }
    let result = try await task.value

    await server.hardAbort()
    _ = try? await channel.finish(acceptAlreadyClosed: true)
    try await group.shutdownGracefully()
    return (result, command)
}
