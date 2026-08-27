import NIOEmbedded
@preconcurrency import NIOIMAP
import NIOIMAPCore
import OrderedCollections
import Testing
@testable import SwiftMail

@Suite
struct FetchStructureHandlerTests {
    @Test
    func taggedOKWithBodyCompletesAfterReleasingStateLock() async throws {
        let eventLoop = EmbeddedEventLoop()
        let promise = eventLoop.makePromise(of: [MessagePart].self)
        let handler = FetchStructureHandler(commandTag: "A001", promise: promise)
        let structure = BodyStructure.singlepart(.init(
            kind: .basic(.init(topLevel: "application", sub: "pdf")),
            fields: .init(
                parameters: ["name": "proof.pdf"],
                id: nil,
                contentDescription: nil,
                encoding: .base64,
                octetCount: 512
            )
        ))

        #expect(!handler.processResponse(.fetch(.simpleAttribute(
            .body(.valid(structure), hasExtensionData: true)
        ))))
        handler.handleTaggedOKResponse(.init(
            tag: "A001",
            state: .ok(.init(text: "FETCH completed"))
        ))

        let parts = try await promise.futureResult.get()
        #expect(handler.isCompleted)
        #expect(parts.count == 1)
        #expect(parts.first?.filename == "proof.pdf")
        #expect(parts.first?.octetCount == 512)
    }

    @Test
    func taggedOKWithoutBodyCompletesAfterReleasingStateLock() async throws {
        let eventLoop = EmbeddedEventLoop()
        let promise = eventLoop.makePromise(of: [MessagePart].self)
        let handler = FetchStructureHandler(commandTag: "A001", promise: promise)

        handler.handleTaggedOKResponse(.init(
            tag: "A001",
            state: .ok(.init(text: "FETCH completed"))
        ))

        #expect(handler.isCompleted)
        do {
            _ = try await promise.futureResult.get()
            Issue.record("Expected a missing BODYSTRUCTURE failure")
        } catch let error as IMAPError {
            guard case .fetchFailed(let reason) = error else {
                Issue.record("Expected fetchFailed, received \(error)")
                return
            }
            #expect(reason == "No body structure received")
        } catch {
            Issue.record("Expected IMAPError.fetchFailed, received \(error)")
        }
    }
}
