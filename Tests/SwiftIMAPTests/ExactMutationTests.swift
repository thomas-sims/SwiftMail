import Foundation
import NIO
import NIOEmbedded
@preconcurrency import NIOIMAP
import NIOIMAPCore
import Testing
@testable import SwiftMail

@Suite(.serialized)
struct ExactMutationTests {
    @Test
    func silentStoreExtendsPublicAPIWithoutChangingDefault() async throws {
        let fixture = try await makeServerFixture(capabilities: [])

        let ordinary = Task {
            try await fixture.server.store(
                flags: [.seen],
                on: UIDSet(UID(3)),
                operation: .add
            )
        }
        let ordinaryCommand = try await nextExactTaggedCommand(on: fixture.channel)
        let ordinaryFlags = try #require(storeFlags(from: ordinaryCommand.command))
        #expect(!ordinaryFlags.silent)
        try await respondOK(to: ordinaryCommand, on: fixture.channel)
        try await ordinary.value

        let silent = Task {
            try await fixture.server.store(
                flags: [.deleted],
                on: UIDSet(UID(4)),
                operation: .add,
                silent: true
            )
        }
        let silentCommand = try await nextExactTaggedCommand(on: fixture.channel)
        let silentFlags = try #require(storeFlags(from: silentCommand.command))
        #expect(silentFlags.operation == .add)
        #expect(silentFlags.silent)
        #expect(silentFlags.flags == [.deleted])
        try await respondOK(to: silentCommand, on: fixture.channel)
        try await silent.value

        await cleanup(fixture)
    }

    @Test
    func uidPlusFallbackUsesExactWireOrderAndReturnsCOPYUID() async throws {
        let fixture = try await makeServerFixture(capabilities: [.uidPlus])
        let requested = UIDSet(ranges: 2...3, 9...9)
        let operation = Task {
            try await fixture.server.moveWithResult(messages: requested, to: "Archive")
        }

        let copy = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidCopy(let copySet, _) = copy.command else {
            Issue.record("Expected UID COPY as the first fallback phase")
            return
        }
        #expect(uidBounds(copySet) == [UIDBounds(2, 3), UIDBounds(9, 9)])
        try await respondOK(
            to: copy,
            code: makeExactCOPYUID(
                validity: 81,
                source: [(2, 3), (9, 9)],
                destination: [(20, 21), (90, 90)]
            ),
            on: fixture.channel
        )

        let store = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidStore(let storeSet, _, _) = store.command else {
            Issue.record("Expected silent UID STORE as the second fallback phase")
            return
        }
        #expect(uidBounds(storeSet) == [UIDBounds(2, 3), UIDBounds(9, 9)])
        let flags = try #require(storeFlags(from: store.command))
        #expect(flags.operation == .add)
        #expect(flags.silent)
        #expect(flags.flags == [.deleted])
        try await respondOK(to: store, on: fixture.channel)

        let expunge = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidExpunge(let expungeSet) = expunge.command else {
            Issue.record("Expected exact UID EXPUNGE as the final fallback phase")
            return
        }
        #expect(uidBounds(expungeSet) == [UIDBounds(2, 3), UIDBounds(9, 9)])
        try await respondOK(to: expunge, on: fixture.channel)

        guard case .completed(let mapping) = try await operation.value else {
            Issue.record("Expected the fallback COPYUID mapping")
            return
        }
        #expect(mapping.destinationUIDValidity == UIDValidity(81))
        #expect(mapping.destinationRanges.map {
            UIDBounds($0.lowerBound.value, $0.upperBound.value)
        } == [UIDBounds(20, 21), UIDBounds(90, 90)])
        #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)

        await cleanup(fixture)
    }

    @Test
    func fallbackPreservesReconciliationAndVoidCompatibility() async throws {
        let fixture = try await makeServerFixture(capabilities: [.uidPlus])

        let typed = Task {
            try await fixture.server.moveWithResult(
                messages: UIDSet(UID(11)),
                to: "Archive"
            )
        }
        for _ in 0..<3 {
            let command = try await nextExactTaggedCommand(on: fixture.channel)
            try await respondOK(to: command, on: fixture.channel)
        }
        #expect(try await typed.value == .completedRequiringReconciliation(.mappingUnavailable))

        let legacy = Task {
            try await fixture.server.move(messages: UIDSet(UID(12)), to: "Archive")
        }
        for _ in 0..<3 {
            let command = try await nextExactTaggedCommand(on: fixture.channel)
            try await respondOK(to: command, on: fixture.channel)
        }
        try await legacy.value

        await cleanup(fixture)
    }

    @Test
    func nativeMOVEPrecedesUIDPlusFallback() async throws {
        let fixture = try await makeServerFixture(capabilities: [.move, .uidPlus])
        let operation = Task {
            try await fixture.server.moveWithResult(
                messages: UIDSet(UID(17)),
                to: "Archive"
            )
        }
        let command = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidMove = command.command else {
            Issue.record("Expected native UID MOVE")
            return
        }
        try await respondOK(
            to: command,
            code: makeExactCOPYUID(
                validity: 9,
                source: [(17, 17)],
                destination: [(117, 117)]
            ),
            on: fixture.channel
        )
        guard case .completed = try await operation.value else {
            Issue.record("Expected native MOVE completion")
            return
        }
        #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)

        await cleanup(fixture)
    }

    @Test
    func unsafeFallbacksRefuseBeforeAnyMutationWrite() async throws {
        let fixture = try await makeServerFixture(capabilities: [.uidPlus])
        let sequenceFailure = await mutationFailure {
            try await fixture.server.moveWithResult(
                messages: SequenceNumberSet(SequenceNumber(1)),
                to: "Archive"
            )
        }
        #expect(sequenceFailure?.operation == .move)
        #expect(sequenceFailure?.phase == .validation)
        #expect(sequenceFailure?.certainty == .definitelyNotApplied)
        #expect(sequenceFailure?.reason == .unsupportedOperation)
        #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
        await cleanup(fixture)

        let noCapabilities = try await makeServerFixture(capabilities: [])
        let moveFailure = await mutationFailure {
            try await noCapabilities.server.moveWithResult(
                messages: UIDSet(UID(2)),
                to: "Archive"
            )
        }
        let expungeFailure = await mutationFailure {
            try await noCapabilities.server.uidExpunge(message: UID(2))
        }
        let deleteFailure = await mutationFailure {
            try await noCapabilities.server.deletePermanently(message: UID(2))
        }
        for failure in [moveFailure, expungeFailure, deleteFailure] {
            #expect(failure?.phase == .validation)
            #expect(failure?.certainty == .definitelyNotApplied)
            #expect(failure?.reason == .unsupportedOperation)
        }

        let invalidDelete = await mutationFailure {
            try await noCapabilities.server.deletePermanently(message: UID(0))
        }
        #expect(invalidDelete?.operation == .permanentDelete)
        #expect(invalidDelete?.phase == .validation)
        #expect(invalidDelete?.certainty == .definitelyNotApplied)
        #expect(invalidDelete?.reason == .invalidRequest)
        #expect(try await noCapabilities.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
        await cleanup(noCapabilities)
    }

    @Test
    func publicUIDExpungeAndPermanentDeleteNeverUseGlobalEXPUNGE() async throws {
        let fixture = try await makeServerFixture(capabilities: [.uidPlus])

        let exactExpunge = Task {
            try await fixture.server.uidExpunge(messages: UIDSet(ranges: 4...5, 19...19))
        }
        let first = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidExpunge(let exactSet) = first.command else {
            Issue.record("Expected exact public UID EXPUNGE")
            return
        }
        #expect(uidBounds(exactSet) == [UIDBounds(4, 5), UIDBounds(19, 19)])
        try await respondOK(to: first, on: fixture.channel)
        try await exactExpunge.value

        let permanentDelete = Task {
            try await fixture.server.deletePermanently(message: UID(23))
        }
        let store = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidStore(let storeSet, _, _) = store.command else {
            Issue.record("Expected exact UID STORE")
            return
        }
        #expect(uidBounds(storeSet) == [UIDBounds(23, 23)])
        let flags = try #require(storeFlags(from: store.command))
        #expect(flags.silent)
        #expect(flags.flags == [.deleted])
        try await respondOK(to: store, on: fixture.channel)

        let expunge = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidExpunge(let deleteSet) = expunge.command else {
            Issue.record("Expected exact UID EXPUNGE")
            return
        }
        #expect(uidBounds(deleteSet) == [UIDBounds(23, 23)])
        try await respondOK(to: expunge, on: fixture.channel)
        try await permanentDelete.value
        #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)

        await cleanup(fixture)
    }

    @Test
    func exactDeleteFailuresAreCategoricalUnknownAndNeverRetried() async throws {
        let expungeFixture = try await makeServerFixture(capabilities: [.uidPlus])
        let exactExpunge = Task {
            try await expungeFixture.server.uidExpunge(message: UID(24))
        }
        let expungeCommand = try await nextExactTaggedCommand(on: expungeFixture.channel)
        try await respondNO(
            to: expungeCommand,
            text: "hostile-expunge-marker",
            on: expungeFixture.channel
        )
        let expungeFailure = try #require(await taskMutationFailure(exactExpunge))
        #expect(expungeFailure.operation == .uidExpunge)
        #expect(expungeFailure.phase == .uidExpunge)
        #expect(expungeFailure.certainty == .outcomeUnknown)
        #expect(expungeFailure.reason == .serverRejected)
        #expect(!String(describing: expungeFailure).contains("hostile-expunge-marker"))
        #expect(try await expungeFixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
        await cleanup(expungeFixture)

        for rejectedPhase in 1...2 {
            let fixture = try await makeServerFixture(capabilities: [.uidPlus])
            let operation = Task {
                try await fixture.server.deletePermanently(message: UID(25))
            }
            let store = try await nextExactTaggedCommand(on: fixture.channel)
            if rejectedPhase == 1 {
                try await respondNO(
                    to: store,
                    text: "hostile-store-marker",
                    on: fixture.channel
                )
            } else {
                try await respondOK(to: store, on: fixture.channel)
                let expunge = try await nextExactTaggedCommand(on: fixture.channel)
                try await respondNO(
                    to: expunge,
                    text: "hostile-delete-marker",
                    on: fixture.channel
                )
            }

            let failure = try #require(await taskMutationFailure(operation))
            #expect(failure.operation == .permanentDelete)
            #expect(failure.phase == (rejectedPhase == 1 ? .markDeleted : .uidExpunge))
            #expect(failure.certainty == .outcomeUnknown)
            #expect(failure.reason == .serverRejected)
            #expect(!String(describing: failure).contains("hostile"))
            #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
            await cleanup(fixture)
        }
    }

    @Test
    func fallbackFailureTimeoutAndCloseAtEveryPhaseAreUnknownAndNeverRetried() async throws {
        for mode in ExactFailureMode.allCases {
            for ordinal in 1...3 {
                let result = try await runFallbackFailure(at: ordinal, mode: mode)
                #expect(result.failure.operation == .move)
                #expect(result.failure.phase == expectedPhase(for: ordinal))
                #expect(result.failure.certainty == .outcomeUnknown)
                #expect(result.failure.reason == mode.expectedReason)
                #expect(result.commands.count == ordinal)
                #expect(!result.commands.contains(where: { if case .expunge = $0.command { true } else { false } }))
            }
        }
    }

    @Test
    func cancellationBeforeAndBetweenFallbackPhasesStopsWithoutCleanup() async throws {
        let preflight = try await makeConnectionFixture(capabilities: [.uidPlus])
        let cancelledBeforeLease = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await preflight.connection.executeMoveWithFallback(
                messages: UIDSet(UID(31)),
                to: "Archive"
            )
        }
        let preflightFailure = await taskMutationFailure(cancelledBeforeLease)
        #expect(preflightFailure?.phase == .dispatch)
        #expect(preflightFailure?.certainty == .definitelyNotApplied)
        #expect(preflightFailure?.reason == .cancelled)
        #expect(try await preflight.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
        await cleanup(preflight)

        let afterCopy = try await cancellationBoundary(afterPhase: 1)
        #expect(afterCopy.failure.phase == .markDeleted)
        #expect(afterCopy.failure.certainty == .outcomeUnknown)
        #expect(afterCopy.commands.count == 1)

        let afterStore = try await cancellationBoundary(afterPhase: 2)
        #expect(afterStore.failure.phase == .uidExpunge)
        #expect(afterStore.failure.certainty == .outcomeUnknown)
        #expect(afterStore.commands.count == 2)
    }

    @Test
    func transportLossAfterCopyCannotReconnectOrContinueFallback() async throws {
        let factoryCalls = LockedInt()
        let fixture = try await makeConnectionFixture(
            capabilities: [.uidPlus],
            connectOverride: { _ in
                factoryCalls.increment()
                return MultiThreadedEventLoopGroup.singleton.next().makeFailedFuture(
                    IMAPConnectionError.disconnected
                )
            }
        )
        let operation = Task {
            try await fixture.connection.executeMoveWithFallback(
                messages: UIDSet(UID(41)),
                to: "Archive"
            )
        }
        let copy = try await nextExactTaggedCommand(on: fixture.channel)
        try await respondOK(to: copy, on: fixture.channel)
        let store = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidStore = store.command else {
            Issue.record("Expected STORE before transport loss")
            return
        }
        try await fixture.channel.close().get()

        let failure = await taskMutationFailure(operation)
        #expect(failure?.phase == .markDeleted)
        #expect(failure?.certainty == .outcomeUnknown)
        #expect(factoryCalls.value == 0)
        await cleanup(fixture)
    }

    @Test
    func concurrentNOOPCannotInterleaveFallbackLease() async throws {
        let fixture = try await makeServerFixture(capabilities: [.uidPlus])
        let move = Task {
            try await fixture.server.moveWithResult(
                messages: UIDSet(UID(51)),
                to: "Archive"
            )
        }
        let copy = try await nextExactTaggedCommand(on: fixture.channel)

        let noop = Task { try await fixture.server.noop() }
        try await respondOK(to: copy, on: fixture.channel)
        let store = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidStore = store.command else {
            Issue.record("NOOP interleaved before fallback STORE")
            return
        }
        try await respondOK(to: store, on: fixture.channel)
        let expunge = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .uidExpunge = expunge.command else {
            Issue.record("NOOP interleaved before exact UID EXPUNGE")
            return
        }
        try await respondOK(to: expunge, on: fixture.channel)
        _ = try await move.value

        let noopCommand = try await nextExactTaggedCommand(on: fixture.channel)
        guard case .noop = noopCommand.command else {
            Issue.record("Expected queued NOOP after the complete fallback")
            return
        }
        try await respondOK(to: noopCommand, on: fixture.channel)
        _ = try await noop.value

        await cleanup(fixture)
    }
}

private enum ExactFailureMode: CaseIterable, Equatable {
    case taggedFailure
    case timeout
    case close

    var expectedReason: IMAPMutationFailure.Reason {
        switch self {
        case .taggedFailure: return .serverRejected
        case .timeout: return .timedOut
        case .close: return .transportFailure
        }
    }
}

private struct ServerFixture {
    let server: SwiftMail.IMAPServer
    let channel: NIOAsyncTestingChannel
}

private struct ConnectionFixture {
    let connection: IMAPConnection
    let channel: NIOAsyncTestingChannel
    let group: MultiThreadedEventLoopGroup
}

private struct FallbackFailureResult {
    let failure: IMAPMutationFailure
    let commands: [TaggedCommand]
}

private func makeServerFixture(capabilities: Set<Capability>) async throws -> ServerFixture {
    let channel = NIOAsyncTestingChannel()
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await channel.connect(to: address).get()
    let server = SwiftMail.IMAPServer(host: "invalid.invalid", port: 993)
    try await server.preparePrimaryEstablishedChannel(channel, capabilities: capabilities)
    return ServerFixture(server: server, channel: channel)
}

private func makeConnectionFixture(
    capabilities: Set<Capability>,
    timeoutSeconds: Int = 5,
    connectOverride: IMAPConnection.ConnectOverride? = nil
) async throws -> ConnectionFixture {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let channel = NIOAsyncTestingChannel()
    let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
    try await channel.connect(to: address).get()
    let connection = IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.exact.connection",
        outboundLabel: "test.exact.out",
        inboundLabel: "test.exact.in",
        connectOverride: connectOverride,
        mutationTimeoutSeconds: timeoutSeconds
    )
    try await connection.prepareEstablishedChannel(channel, capabilities: capabilities)
    return ConnectionFixture(connection: connection, channel: channel, group: group)
}

private func cleanup(_ fixture: ServerFixture) async {
    await fixture.server.hardAbort()
    _ = try? await fixture.channel.finish(acceptAlreadyClosed: true)
}

private func cleanup(_ fixture: ConnectionFixture) async {
    await fixture.connection.hardAbort()
    _ = try? await fixture.channel.finish(acceptAlreadyClosed: true)
    try? await fixture.group.shutdownGracefully()
}

private func runFallbackFailure(
    at ordinal: Int,
    mode: ExactFailureMode
) async throws -> FallbackFailureResult {
    let fixture = try await makeConnectionFixture(
        capabilities: [.uidPlus],
        timeoutSeconds: mode == .timeout ? 1 : 5
    )
    let operation = Task {
        try await fixture.connection.executeMoveWithFallback(
            messages: UIDSet(UID(61)),
            to: "Archive"
        )
    }
    var commands: [TaggedCommand] = []
    for phase in 1...ordinal {
        let command = try await nextExactTaggedCommand(on: fixture.channel)
        commands.append(command)
        if phase < ordinal {
            if phase == 1 {
                try await respondOK(
                    to: command,
                    code: makeExactCOPYUID(
                        validity: 4,
                        source: [(61, 61)],
                        destination: [(161, 161)]
                    ),
                    on: fixture.channel
                )
            } else {
                try await respondOK(to: command, on: fixture.channel)
            }
            continue
        }

        switch mode {
        case .taggedFailure:
            try await respondNO(to: command, on: fixture.channel)
        case .timeout:
            break
        case .close:
            try await fixture.channel.close().get()
        }
    }

    let failure = try #require(await taskMutationFailure(operation))
    #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
    await cleanup(fixture)
    return FallbackFailureResult(failure: failure, commands: commands)
}

private func cancellationBoundary(afterPhase ordinal: Int) async throws -> FallbackFailureResult {
    let fixture = try await makeConnectionFixture(capabilities: [.uidPlus])
    let operation = Task {
        try await fixture.connection.executeMoveWithFallback(
            messages: UIDSet(UID(71)),
            to: "Archive"
        )
    }
    var commands: [TaggedCommand] = []
    for phase in 1...ordinal {
        let command = try await nextExactTaggedCommand(on: fixture.channel)
        commands.append(command)
        if phase == ordinal {
            operation.cancel()
        }
        if phase == 1 {
            try await respondOK(
                to: command,
                code: makeExactCOPYUID(
                    validity: 5,
                    source: [(71, 71)],
                    destination: [(171, 171)]
                ),
                on: fixture.channel
            )
        } else {
            try await respondOK(to: command, on: fixture.channel)
        }
    }
    let failure = try #require(await taskMutationFailure(operation))
    #expect(failure.reason == .cancelled)
    #expect(try await fixture.channel.readOutbound(as: IMAPClientHandler.OutboundIn.self) == nil)
    await cleanup(fixture)
    return FallbackFailureResult(failure: failure, commands: commands)
}

private func nextExactTaggedCommand(on channel: NIOAsyncTestingChannel) async throws -> TaggedCommand {
    let outbound = try await channel.waitForOutboundWrite(as: IMAPClientHandler.OutboundIn.self)
    guard case .part(.tagged(let command)) = outbound else {
        throw IMAPError.commandFailed("Expected tagged test command")
    }
    return command
}

private func respondOK(
    to command: TaggedCommand,
    code: ResponseCodeCopy? = nil,
    on channel: NIOAsyncTestingChannel
) async throws {
    let response = Response.tagged(.init(
        tag: command.tag,
        state: .ok(.init(code: code.map(ResponseTextCode.uidCopy), text: "fixed-ok"))
    ))
    _ = try await channel.writeInbound(response)
}

private func respondNO(
    to command: TaggedCommand,
    text: String = "fixed-no",
    on channel: NIOAsyncTestingChannel
) async throws {
    _ = try await channel.writeInbound(
        Response.tagged(.init(
            tag: command.tag,
            state: .no(.init(text: text))
        ))
    )
}

private func makeExactCOPYUID(
    validity: UInt32,
    source: [(UInt32, UInt32)],
    destination: [(UInt32, UInt32)]
) -> ResponseCodeCopy {
    ResponseCodeCopy(
        destinationUIDValidity: NIOIMAPCore.UIDValidity(exactly: validity)!,
        sourceUIDs: source.map {
            NIOIMAPCore.UIDRange(
                NIOIMAPCore.UID(rawValue: $0.0)...NIOIMAPCore.UID(rawValue: $0.1)
            )
        },
        destinationUIDs: destination.map {
            NIOIMAPCore.UIDRange(
                NIOIMAPCore.UID(rawValue: $0.0)...NIOIMAPCore.UID(rawValue: $0.1)
            )
        }
    )
}

private struct UIDBounds: Equatable {
    let lower: UInt32
    let upper: UInt32

    init(_ lower: UInt32, _ upper: UInt32) {
        self.lower = lower
        self.upper = upper
    }
}

private func uidBounds(_ set: LastCommandSet<NIOIMAPCore.UID>) -> [UIDBounds] {
    guard case .set(let identifiers) = set else { return [] }
    return identifiers.set.ranges.map {
        UIDBounds($0.range.lowerBound.rawValue, $0.range.upperBound.rawValue)
    }
}

private func storeFlags(from command: Command) -> NIOIMAPCore.StoreFlags? {
    let data: NIOIMAPCore.StoreData
    switch command {
    case .uidStore(_, _, let storeData), .store(_, _, let storeData):
        data = storeData
    default:
        return nil
    }
    guard case .flags(let flags) = data else { return nil }
    return flags
}

private func expectedPhase(for ordinal: Int) -> IMAPMutationFailure.Phase {
    switch ordinal {
    case 1: return .fallbackCopy
    case 2: return .markDeleted
    default: return .uidExpunge
    }
}

private func mutationFailure<T>(
    _ operation: () async throws -> T
) async -> IMAPMutationFailure? {
    do {
        _ = try await operation()
        Issue.record("Expected mutation failure")
        return nil
    } catch let failure as IMAPMutationFailure {
        return failure
    } catch {
        Issue.record("Expected typed IMAPMutationFailure")
        return nil
    }
}

private func taskMutationFailure<T>(_ task: Task<T, Error>) async -> IMAPMutationFailure? {
    await mutationFailure { try await task.value }
}

private final class LockedInt: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func increment() {
        lock.lock()
        storedValue += 1
        lock.unlock()
    }
}
