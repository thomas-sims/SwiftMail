import Foundation
import NIO
import NIOEmbedded
@preconcurrency import NIOIMAP
import Testing
@testable import SwiftMail

struct IMAPAbortTests {
    @Test
    func cancelledQueuedCommandNeverExecutes() async throws {
        let queue = IMAPCommandQueue()
        let activeStarted = AsyncGate()
        let releaseActive = AsyncGate()
        let entries = EntryCounter()

        let active = Task<Void, Error> {
            try await queue.run {
                await activeStarted.open()
                await releaseActive.wait()
            }
        }
        await activeStarted.wait()

        let cancelled = Task<Void, Error> {
            try await queue.run {
                await entries.recordEntry()
            }
        }
        let survivor = Task<Void, Error> {
            try await queue.run {
                await entries.recordEntry()
            }
        }
        try await waitUntil { await queue.pendingCount == 2 }

        cancelled.cancel()
        do {
            try await cancelled.value
            Issue.record("Expected the queued command to be cancelled")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected queued-command error: \(error)")
        }

        #expect(await entries.count == 0)
        #expect(await queue.pendingCount == 1)

        await releaseActive.open()
        try await active.value
        try await survivor.value
        #expect(await entries.count == 1)
        #expect(await queue.pendingCount == 0)
    }

    @Test
    func abortDrainsActiveHandlerAndQueuedCommands() async throws {
        let queue = IMAPCommandQueue()
        let eventLoop = NIOAsyncTestingEventLoop()
        let activeStarted = AsyncGate()
        let entries = EntryCounter()
        let promise = eventLoop.makePromise(of: [IMAPServerEvent].self)
        let handler = NoopHandler(commandTag: "A001", promise: promise)
        let channel = await NIOAsyncTestingChannel(handler: handler, loop: eventLoop)

        let active = Task<[IMAPServerEvent], Error> {
            try await queue.run {
                await activeStarted.open()
                return try await promise.futureResult.get()
            }
        }
        await activeStarted.wait()

        let queued = (0..<16).map { _ in
            Task<Void, Error> {
                try await queue.run {
                    await entries.recordEntry()
                }
            }
        }
        try await waitUntil { await queue.pendingCount == queued.count }

        await queue.abort()
        _ = try await channel.finish()

        do {
            _ = try await active.value
            Issue.record("Expected channel closure to fail the active command")
        } catch is IMAPConnectionError {
            // Expected.
        } catch {
            Issue.record("Unexpected active-command error: \(error)")
        }

        for task in queued {
            do {
                try await task.value
                Issue.record("Expected abort to fail every queued command")
            } catch let error as IMAPError {
                if case .connectionFailed(let reason) = error {
                    #expect(reason == "Connection was aborted")
                } else {
                    Issue.record("Unexpected queued IMAP error: \(error)")
                }
            } catch {
                Issue.record("Unexpected queued-command error: \(error)")
            }
        }

        #expect(await entries.count == 0)
        #expect(await queue.pendingCount == 0)
        #expect(handler.isCompleted)
    }

    @Test
    func idleStreamFinishesPromptlyWhenChannelCloses() async throws {
        let eventLoop = NIOAsyncTestingEventLoop()
        let promise = eventLoop.makePromise(of: Void.self)
        var continuationReference: AsyncStream<IMAPServerEvent>.Continuation?
        let stream = AsyncStream<IMAPServerEvent> { continuation in
            continuationReference = continuation
        }
        let continuation = try #require(continuationReference)
        let handler = IdleHandler(commandTag: "A001", promise: promise, continuation: continuation)
        let channel = await NIOAsyncTestingChannel(handler: handler, loop: eventLoop)

        let consumer = Task { () -> [IMAPServerEvent] in
            var events: [IMAPServerEvent] = []
            for await event in stream {
                events.append(event)
            }
            return events
        }

        let clock = ContinuousClock()
        let start = clock.now
        _ = try await channel.finish()
        let events = await consumer.value
        let elapsed = start.duration(to: clock.now)

        #expect(elapsed < .milliseconds(250))
        #expect(events.contains { event in
            if case .bye = event { return true }
            return false
        })

        do {
            try await promise.futureResult.get()
            Issue.record("Expected IDLE promise to fail when its channel closed")
        } catch is IMAPConnectionError {
            // Expected.
        } catch {
            Issue.record("Unexpected IDLE error: \(error)")
        }
    }

    @Test
    func hardAbortedServerCannotReconnect() async {
        let server = IMAPServer(host: "invalid.invalid", port: 993)
        await server.hardAbort()

        do {
            try await server.connect()
            Issue.record("Expected a hard-aborted server to reject reconnect")
        } catch let error as IMAPError {
            if case .connectionFailed(let reason) = error {
                #expect(reason == "Connection was aborted")
            } else {
                Issue.record("Unexpected reconnect IMAP error: \(error)")
            }
        } catch {
            Issue.record("Unexpected reconnect error: \(error)")
        }
    }

    @Test
    func hardAbortInterruptsActiveConnectionPromptly() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let listener = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()

        do {
            let port = try #require(listener.localAddress?.port)
            let server = IMAPServer(host: "localhost", port: port)
            let connection = Task {
                try await server.connect()
            }

            try await waitUntil { await server.isConnected }

            let clock = ContinuousClock()
            let start = clock.now
            await server.hardAbort()
            let elapsed = start.duration(to: clock.now)

            #expect(elapsed < .milliseconds(500))
            #expect(await !server.isConnected)

            do {
                try await connection.value
                Issue.record("Expected hard abort to interrupt the active connection")
            } catch {
                // Expected.
            }

            do {
                try await server.connect()
                Issue.record("Expected the retired server to reject reconnect")
            } catch let error as IMAPError {
                if case .connectionFailed(let reason) = error {
                    #expect(reason == "Connection was aborted")
                } else {
                    Issue.record("Unexpected reconnect IMAP error: \(error)")
                }
            } catch {
                Issue.record("Unexpected reconnect error: \(error)")
            }

            try await listener.close().get()
            try await group.shutdownGracefully()
        } catch {
            try? await listener.close().get()
            try? await group.shutdownGracefully()
            throw error
        }
    }

    @Test
    func repeatedAbortRemainsResourceBounded() async throws {
        let queue = IMAPCommandQueue()
        let activeStarted = AsyncGate()
        let releaseActive = AsyncGate()
        let entries = EntryCounter()

        let active = Task<Void, Error> {
            try await queue.run {
                await activeStarted.open()
                await releaseActive.wait()
            }
        }
        await activeStarted.wait()

        let queued = (0..<128).map { _ in
            Task<Void, Error> {
                try await queue.run {
                    await entries.recordEntry()
                }
            }
        }
        try await waitUntil { await queue.pendingCount == queued.count }

        for _ in 0..<32 {
            await queue.abort()
        }

        for task in queued {
            _ = await task.result
        }
        #expect(await queue.pendingCount == 0)
        #expect(await entries.count == 0)

        await releaseActive.open()
        try await active.value

        for _ in 0..<128 {
            do {
                try await queue.run {
                    await entries.recordEntry()
                }
                Issue.record("Expected a retired queue to reject new work")
            } catch {
                // Expected.
            }
        }

        #expect(await queue.pendingCount == 0)
        #expect(await entries.count == 0)
    }

    @Test
    func hardAbortOwnsGracefullyClosingIdleConnectionAndCycleTask() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = NIOAsyncTestingChannel(loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()

        let connection = makeConnection(group: group)
        try await connection.prepareEstablishedChannel(channel, capabilities: [.idle])

        var continuationReference: AsyncStream<IMAPServerEvent>.Continuation?
        let stream = AsyncStream<IMAPServerEvent> { continuation in
            continuationReference = continuation
        }
        let continuation = try #require(continuationReference)
        try await connection.startIdleSession(continuation: continuation)

        let cycleTask = Task<Void, Never> {
            for await _ in stream {}
        }
        let server = IMAPServer(host: "invalid.invalid", port: 993)
        let sessionID = UUID()
        await server.trackIdleConnection(id: sessionID, mailbox: "INBOX", connection: connection)
        try await server.attachIdleRuntime(
            id: sessionID,
            matching: connection,
            cycleTask: cycleTask,
            continuation: continuation
        )

        let gracefulClose = Task {
            try await server.endIdleSession(id: sessionID)
        }
        try await waitUntil {
            await server.gracefullyClosingIdleConnectionCount == 1
        }

        #expect(await server.trackedIdleConnectionCount == 1)
        #expect(await server.trackedIdleTaskCount == 1)
        #expect(connection.ownedTransportCount == 1)

        let clock = ContinuousClock()
        let start = clock.now
        await withTaskGroup(of: Void.self) { aborts in
            for _ in 0..<8 {
                aborts.addTask { await server.hardAbort() }
            }
        }
        let elapsed = start.duration(to: clock.now)

        #expect(elapsed < .milliseconds(500))
        #expect(connection.ownedTransportCount == 0)
        #expect(await server.trackedIdleConnectionCount == 0)
        #expect(await server.trackedIdleTaskCount == 0)
        #expect(!channel.isActive)
        _ = await gracefulClose.result
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func hardAbortInterruptsConcurrentServerDisconnectWaitingForDone() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = NIOAsyncTestingChannel(loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()

        let connection = makeConnection(group: group)
        try await connection.prepareEstablishedChannel(channel, capabilities: [.idle])

        var continuationReference: AsyncStream<IMAPServerEvent>.Continuation?
        let stream = AsyncStream<IMAPServerEvent> { continuation in
            continuationReference = continuation
        }
        let continuation = try #require(continuationReference)
        try await connection.startIdleSession(continuation: continuation)
        let cycleTask = Task<Void, Never> {
            for await _ in stream {}
        }

        let server = IMAPServer(host: "invalid.invalid", port: 993)
        let sessionID = UUID()
        await server.trackIdleConnection(id: sessionID, mailbox: "INBOX", connection: connection)
        try await server.attachIdleRuntime(
            id: sessionID,
            matching: connection,
            cycleTask: cycleTask,
            continuation: continuation
        )

        let gracefulDisconnect = Task {
            try await server.disconnect()
        }
        try await waitUntil {
            await server.gracefullyClosingIdleConnectionCount == 1
        }

        await server.hardAbort()
        _ = await gracefulDisconnect.result

        #expect(connection.ownedTransportCount == 0)
        #expect(await server.trackedIdleConnectionCount == 0)
        #expect(await server.trackedIdleTaskCount == 0)
        #expect(!channel.isActive)
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func gracefulDisconnectRejectsNewPrimaryCommand() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let idleEventLoop = NIOAsyncTestingEventLoop()
        let idleChannel = NIOAsyncTestingChannel(loop: idleEventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await idleChannel.connect(to: address).get()

        let idleConnection = makeConnection(group: group)
        try await idleConnection.prepareEstablishedChannel(idleChannel, capabilities: [.idle])

        var continuationReference: AsyncStream<IMAPServerEvent>.Continuation?
        let stream = AsyncStream<IMAPServerEvent> { continuation in
            continuationReference = continuation
        }
        let continuation = try #require(continuationReference)
        try await idleConnection.startIdleSession(continuation: continuation)
        let cycleTask = Task<Void, Never> {
            for await _ in stream {}
        }

        let writeCounter = RejectOutboundWritesHandler()
        let primaryEventLoop = NIOAsyncTestingEventLoop()
        let primaryChannel = await NIOAsyncTestingChannel(handler: writeCounter, loop: primaryEventLoop)
        try await primaryChannel.connect(to: address).get()

        let server = IMAPServer(host: "invalid.invalid", port: 993)
        try await server.preparePrimaryEstablishedChannel(primaryChannel)
        let sessionID = UUID()
        await server.trackIdleConnection(id: sessionID, mailbox: "INBOX", connection: idleConnection)
        try await server.attachIdleRuntime(
            id: sessionID,
            matching: idleConnection,
            cycleTask: cycleTask,
            continuation: continuation
        )

        let gracefulDisconnect = Task {
            try await server.disconnect()
        }
        try await waitUntil {
            await server.gracefullyClosingIdleConnectionCount == 1
        }

        do {
            _ = try await server.noop()
            Issue.record("Expected teardown to reject a new primary command")
        } catch let error as IMAPError {
            if case .connectionFailed(let reason) = error {
                #expect(reason == "Connection teardown in progress")
            } else {
                Issue.record("Unexpected teardown IMAP error: \(error)")
            }
        } catch {
            Issue.record("Unexpected teardown error: \(error)")
        }
        #expect(writeCounter.writeCount == 0)

        await server.hardAbort()
        _ = await gracefulDisconnect.result
        _ = try? await idleChannel.finish(acceptAlreadyClosed: true)
        _ = try? await primaryChannel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }

    @Test
    func abortAwaitsLateConnectCandidateClosure() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

        for _ in 0..<16 {
            let eventLoop = NIOAsyncTestingEventLoop()
            let channel = NIOAsyncTestingChannel(loop: eventLoop)
            let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
            try await channel.connect(to: address).get()
            let transportPromise = group.next().makePromise(of: Channel.self)

            let connection = IMAPConnection(
                host: "invalid.invalid",
                port: 993,
                group: group,
                loggerLabel: "test.imap.connection",
                outboundLabel: "test.imap.out",
                inboundLabel: "test.imap.in",
                connectOverride: { registerChannel in
                    group.next().scheduleTask(in: .milliseconds(10)) {
                        registerChannel(channel)
                        transportPromise.succeed(channel)
                    }
                    return transportPromise.futureResult
                }
            )

            let connectTask = Task {
                try await connection.connect()
            }
            try await waitUntil { connection.hasPendingTransportConnect }

            let start = ContinuousClock().now
            await connection.hardAbort()
            let elapsed = start.duration(to: ContinuousClock().now)

            #expect(elapsed < .milliseconds(250))
            #expect(connection.ownedTransportCount == 0)
            #expect(!connection.hasPendingTransportConnect)
            #expect(!channel.isActive)
            _ = await connectTask.result
            _ = try? await channel.finish(acceptAlreadyClosed: true)
        }

        try await group.shutdownGracefully()
    }

    @Test
    func abortJoinsTransportCreationBeforeItReturns() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

        for _ in 0..<16 {
            let eventLoop = NIOAsyncTestingEventLoop()
            let channel = NIOAsyncTestingChannel(loop: eventLoop)
            let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
            try await channel.connect(to: address).get()

            let releaseFactory = DispatchSemaphore(value: 0)
            let transportPromise = group.next().makePromise(of: Channel.self)
            let factoryCalls = LockedCounter()
            let abortStarted = LockedFlag()
            let abortCompleted = LockedFlag()

            let connection = IMAPConnection(
                host: "invalid.invalid",
                port: 993,
                group: group,
                loggerLabel: "test.imap.connection",
                outboundLabel: "test.imap.out",
                inboundLabel: "test.imap.in",
                connectOverride: { registerChannel in
                    factoryCalls.increment()
                    releaseFactory.wait()
                    registerChannel(channel)
                    transportPromise.succeed(channel)
                    return transportPromise.futureResult
                }
            )

            let connectTask = Task {
                try await connection.connect()
            }
            try await waitUntil { factoryCalls.value == 1 }
            #expect(connection.hasPendingTransportConnect)

            do {
                try await connection.connect()
                Issue.record("Expected the reserved creation slot to reject a second connect")
            } catch let error as IMAPError {
                if case .connectionFailed(let reason) = error {
                    #expect(reason == "Connection attempt already in progress")
                } else {
                    Issue.record("Unexpected concurrent-connect IMAP error: \(error)")
                }
            } catch {
                Issue.record("Unexpected concurrent-connect error: \(error)")
            }
            #expect(factoryCalls.value == 1)

            let abortTask = Task {
                abortStarted.set()
                await connection.hardAbort()
                abortCompleted.set()
            }
            try await waitUntil { abortStarted.value }
            try await Task.sleep(nanoseconds: 25_000_000)
            #expect(!abortCompleted.value)

            releaseFactory.signal()
            try await waitUntil { abortCompleted.value }
            await abortTask.value

            do {
                try await connectTask.value
                Issue.record("Expected connect to fail after hard abort")
            } catch let error as IMAPError {
                if case .connectionFailed(let reason) = error {
                    #expect(reason == "Connection was aborted")
                } else {
                    Issue.record("Unexpected aborted-connect IMAP error: \(error)")
                }
            } catch {
                Issue.record("Unexpected aborted-connect error: \(error)")
            }

            #expect(!connection.hasPendingTransportConnect)
            #expect(connection.ownedTransportCount == 0)
            #expect(!channel.isActive)
            _ = try? await channel.finish(acceptAlreadyClosed: true)
        }

        try await group.shutdownGracefully()
    }

    @Test
    func idleWriteFailureRestoresPipelineStateAcrossRetries() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let eventLoop = NIOAsyncTestingEventLoop()
        let channel = await NIOAsyncTestingChannel(handler: RejectOutboundWritesHandler(), loop: eventLoop)
        let address = try SocketAddress(ipAddress: "127.0.0.1", port: 993)
        try await channel.connect(to: address).get()
        let connection = makeConnection(group: group)
        try await connection.prepareEstablishedChannel(channel, capabilities: [.idle])

        for _ in 0..<16 {
            var continuationReference: AsyncStream<IMAPServerEvent>.Continuation?
            let stream = AsyncStream<IMAPServerEvent> { continuation in
                continuationReference = continuation
            }
            let continuation = try #require(continuationReference)
            let consumer = Task<Void, Never> {
                for await _ in stream {}
            }

            do {
                try await connection.startIdleSession(continuation: continuation)
                Issue.record("Expected the IDLE command write to fail")
            } catch is ExpectedWriteFailure {
                // Expected.
            } catch {
                Issue.record("Unexpected IDLE setup error: \(error)")
            }

            await consumer.value
            #expect(!connection.hasIdleHandler)
            #expect(!connection.hasActiveResponseHandler)
            #expect(await !connection.hasInstalledIdleHandler())
        }

        await connection.hardAbort()
        _ = try? await channel.finish(acceptAlreadyClosed: true)
        try await group.shutdownGracefully()
    }
}

private struct ExpectedWriteFailure: Error {}

private final class RejectOutboundWritesHandler: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = IMAPClientHandler.OutboundIn

    private let writeCountLock = NSLock()
    private var storedWriteCount = 0

    var writeCount: Int {
        writeCountLock.lock()
        defer { writeCountLock.unlock() }
        return storedWriteCount
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeCountLock.lock()
        storedWriteCount += 1
        writeCountLock.unlock()
        promise?.fail(ExpectedWriteFailure())
    }
}

private func makeConnection(group: EventLoopGroup) -> IMAPConnection {
    IMAPConnection(
        host: "invalid.invalid",
        port: 993,
        group: group,
        loggerLabel: "test.imap.connection",
        outboundLabel: "test.imap.out",
        inboundLabel: "test.imap.in"
    )
}

private actor AsyncGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let suspended = waiters
        waiters.removeAll(keepingCapacity: false)
        for waiter in suspended {
            waiter.resume()
        }
    }
}

private actor EntryCounter {
    private(set) var count = 0

    func recordEntry() {
        count += 1
    }
}

private final class LockedCounter: @unchecked Sendable {
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

private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var isSet = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isSet
    }

    func set() {
        lock.lock()
        isSet = true
        lock.unlock()
    }
}

private func waitUntil(
    timeoutNanoseconds: UInt64 = 1_000_000_000,
    condition: () async -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .nanoseconds(Int64(timeoutNanoseconds)))

    while !(await condition()) {
        if clock.now >= deadline {
            throw IMAPError.timeout
        }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
}
