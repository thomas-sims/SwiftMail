import Foundation
import NIO
import NIOEmbedded
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
