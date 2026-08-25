//
//  IMAPCommandQueue.swift
//  SwiftMail
//
//  Created by Oliver Drobnik on 16.01.26.
//

import Foundation

actor IMAPCommandQueue {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private var isRunning = false
    private var waiters: [Waiter] = []
    private var isAborted = false

    func run<T>(_ op: () async throws -> T) async throws -> T {
        try Task.checkCancellation()
        try await acquire()
        defer { release() }

        // Cancellation can race the handoff from the previous command. Checking
        // again while holding the queue lease guarantees that a cancelled waiter
        // releases its lease without ever entering the command body.
        try Task.checkCancellation()
        return try await op()
    }

    func abort() {
        guard !isAborted else { return }

        isAborted = true
        let queued = waiters
        waiters.removeAll(keepingCapacity: false)

        for waiter in queued {
            waiter.continuation.resume(throwing: Self.abortedError)
        }
    }

    var pendingCount: Int {
        waiters.count
    }

    private func acquire() async throws {
        guard !isAborted else {
            throw Self.abortedError
        }

        if !isRunning {
            isRunning = true
            return
        }

        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else if isAborted {
                    continuation.resume(throwing: Self.abortedError)
                } else {
                    waiters.append(Waiter(id: waiterID, continuation: continuation))
                }
            }
        } onCancel: {
            Task {
                await self.cancelWaiter(id: waiterID)
            }
        }
    }

    private func release() {
        guard !isAborted else {
            isRunning = false
            return
        }

        guard !waiters.isEmpty else {
            isRunning = false
            return
        }

        let waiter = waiters.removeFirst()
        waiter.continuation.resume()
    }

    private func cancelWaiter(id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else {
            return
        }

        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
    }

    private static var abortedError: IMAPError {
        IMAPError.connectionFailed("Connection was aborted")
    }
}
