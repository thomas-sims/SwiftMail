import Foundation
import NIO
import NIOSSL
import NIOTLS
import Testing
@testable import SwiftMail

struct IMAPTLSConnectionTests {
    @Test
    func strictNumericHostClassificationAndBracketNormalization() throws {
        let rawNumericCases: [(String, String)] = [
            ("0.0.0.0", "0.0.0.0"),
            ("127.0.0.1", "127.0.0.1"),
            ("255.255.255.255", "255.255.255.255"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
        ]

        for (host, expectedConnectionHost) in rawNumericCases {
            let target = try IMAPConnection.connectionTarget(for: host)
            #expect(target.connectionHost == expectedConnectionHost)
            #expect(target.tlsServerHostname == nil)
        }

        let bracketedCases: [(String, String)] = [
            ("[::1]", "::1"),
            ("[2001:0db8:0:0:0:0:0:1]", "2001:0db8:0:0:0:0:0:1"),
        ]

        for (host, expectedConnectionHost) in bracketedCases {
            let target = try IMAPConnection.connectionTarget(for: host)
            #expect(target.connectionHost == expectedConnectionHost)
            #expect(target.tlsServerHostname == nil)
        }
    }

    @Test
    func dnsNamesRetainExactSNIWithoutResolutionClassification() throws {
        let dnsCases = [
            "mail.example.test",
            "localhost",
            "192.168.1.999",
            "1.2.3",
        ]

        for host in dnsCases {
            let target = try IMAPConnection.connectionTarget(for: host)
            #expect(target.connectionHost == host)
            #expect(target.tlsServerHostname == host)
        }
    }

    @Test
    func malformedBracketAndScopedFormsAreRejected() {
        let invalidCases = [
            "[127.0.0.1]",
            "[mail.example.test]",
            "[::1",
            "::1]",
            "[[::1]]",
            "[::1]]",
            "[]",
            "fe80::1%lo0",
            "[fe80::1%lo0]",
            "mail%example.test",
            "2001:db8::not-an-ip",
            "mail.example.test:993",
        ]

        for host in invalidCases {
            do {
                _ = try IMAPConnection.connectionTarget(for: host)
                Issue.record("Expected invalid IMAP host classification for \(host)")
            } catch is IMAPError {
                // Expected typed refusal.
            } catch {
                Issue.record("Unexpected host-classification error type")
            }
        }
    }

    @Test
    func clientTLSConfigurationAlwaysUsesFullVerification() {
        let configuration = IMAPConnection.makeTLSConfiguration()
        #expect(configuration.certificateVerification == .fullVerification)
    }

    @Test
    func numericNilSNIVerifiesIPSANAndDNSIdentityRemainsEnforced() async throws {
        #expect(try await performTLSHandshake(
            certificateName: "imap-ip-san-cert",
            keyName: "imap-ip-san-key",
            serverHostname: nil
        ))

        #expect(try await !performTLSHandshake(
            certificateName: "imap-dns-san-cert",
            keyName: "imap-dns-san-key",
            serverHostname: nil
        ))

        #expect(try await performTLSHandshake(
            certificateName: "imap-dns-san-cert",
            keyName: "imap-dns-san-key",
            serverHostname: "localhost"
        ))

        #expect(try await !performTLSHandshake(
            certificateName: "imap-dns-san-cert",
            keyName: "imap-dns-san-key",
            serverHostname: "wrong-host.example.test"
        ))
    }

    @Test
    func tlsConstructorFailureFailsBootstrapWithoutCrashOrTransportLeak() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let acceptedChannels = AcceptedChannelStore()
        let server = try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                acceptedChannels.append(channel)
                return channel.eventLoop.makeSucceededFuture(())
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()

        guard let port = server.localAddress?.port else {
            Issue.record("Missing loopback server port")
            try await server.close().get()
            try await group.shutdownGracefully()
            return
        }

        let expectedFailure = ExpectedTLSSetupFailure()
        let factoryProbe = TLSFactoryProbe()
        let connection = IMAPConnection(
            host: "127.0.0.1",
            port: port,
            group: group,
            loggerLabel: "test.imap.tls.connection",
            outboundLabel: "test.imap.tls.out",
            inboundLabel: "test.imap.tls.in",
            tlsHandlerFactory: { _, serverHostname -> ChannelHandler in
                factoryProbe.record(serverHostname: serverHostname)
                throw expectedFailure
            }
        )

        do {
            try await connection.connect()
            Issue.record("Expected TLS constructor failure")
        } catch let error as ExpectedTLSSetupFailure {
            #expect(error === expectedFailure)
        } catch let error as NIOConnectionError {
            let underlying = error.connectionErrors.map(\.error)
            #expect(underlying.count == 1)
            #expect((underlying.first as? ExpectedTLSSetupFailure) === expectedFailure)
        } catch {
            Issue.record("Unexpected TLS setup error type: \(String(reflecting: type(of: error)))")
        }

        #expect(factoryProbe.invocationCount == 1)
        #expect(factoryProbe.serverHostname == nil)
        #expect(connection.ownedTransportCount == 0)

        for channel in acceptedChannels.snapshot() {
            try? await channel.close().get()
        }
        try await server.close().get()
        try await group.shutdownGracefully()
    }
}

private final class ExpectedTLSSetupFailure: Error, @unchecked Sendable {}

private final class TLSFactoryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedInvocationCount = 0
    private var storedServerHostname: String??

    var invocationCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedInvocationCount
    }

    var serverHostname: String? {
        lock.lock()
        defer { lock.unlock() }
        return storedServerHostname ?? "factory-not-invoked"
    }

    func record(serverHostname: String?) {
        lock.lock()
        storedInvocationCount += 1
        storedServerHostname = .some(serverHostname)
        lock.unlock()
    }
}

private final class AcceptedChannelStore: @unchecked Sendable {
    private let lock = NSLock()
    private var channels: [Channel] = []

    func append(_ channel: Channel) {
        lock.lock()
        channels.append(channel)
        lock.unlock()
    }

    func snapshot() -> [Channel] {
        lock.lock()
        defer { lock.unlock() }
        return channels
    }
}

private final class TLSHandshakeObserver: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<Void>
    private var isComplete = false

    init(promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            complete(.success(()))
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        complete(.failure(error))
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        complete(.failure(ChannelError.eof))
        context.fireChannelInactive()
    }

    private func complete(_ result: Result<Void, Error>) {
        guard !isComplete else { return }
        isComplete = true
        switch result {
        case .success:
            promise.succeed(())
        case .failure(let error):
            promise.fail(error)
        }
    }
}

private func performTLSHandshake(
    certificateName: String,
    keyName: String,
    serverHostname: String?
) async throws -> Bool {
    guard let certificateURL = Bundle.module.url(forResource: certificateName, withExtension: "pem"),
          let keyURL = Bundle.module.url(forResource: keyName, withExtension: "pem") else {
        throw IMAPError.commandFailed("Missing local TLS test fixture")
    }

    let certificate = try NIOSSLCertificate.fromPEMFile(certificateURL.path)[0]
    let privateKey = try NIOSSLPrivateKey(file: keyURL.path, format: .pem)

    let serverConfiguration = TLSConfiguration.makeServerConfiguration(
        certificateChain: [.certificate(certificate)],
        privateKey: .privateKey(privateKey)
    )
    let serverContext = try NIOSSLContext(configuration: serverConfiguration)

    var clientConfiguration = TLSConfiguration.makeClientConfiguration()
    clientConfiguration.certificateVerification = .fullVerification
    clientConfiguration.trustRoots = .certificates([certificate])
    let clientContext = try NIOSSLContext(configuration: clientConfiguration)

    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let acceptedChannels = AcceptedChannelStore()
    let server = try await ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { channel in
            acceptedChannels.append(channel)
            do {
                try channel.pipeline.syncOperations.addHandler(
                    NIOSSLServerHandler(context: serverContext)
                )
                return channel.eventLoop.makeSucceededFuture(())
            } catch {
                return channel.eventLoop.makeFailedFuture(error)
            }
        }
        .bind(host: "127.0.0.1", port: 0)
        .get()

    guard let address = server.localAddress else {
        try await server.close().get()
        try await group.shutdownGracefully()
        throw IMAPError.commandFailed("Missing local TLS test address")
    }

    let handshakePromise = group.next().makePromise(of: Void.self)
    var clientChannel: Channel?
    var handshakeSucceeded = false

    do {
        clientChannel = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                do {
                    let tlsHandler = try NIOSSLClientHandler(
                        context: clientContext,
                        serverHostname: serverHostname
                    )
                    try channel.pipeline.syncOperations.addHandlers([
                        tlsHandler,
                        TLSHandshakeObserver(promise: handshakePromise),
                    ])
                    return channel.eventLoop.makeSucceededFuture(())
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(to: address)
            .get()
        try await handshakePromise.futureResult.get()
        handshakeSucceeded = true
    } catch {
        handshakeSucceeded = false
    }

    if let clientChannel {
        try? await clientChannel.close().get()
    }
    for channel in acceptedChannels.snapshot() {
        try? await channel.close().get()
    }
    try await server.close().get()
    try await group.shutdownGracefully()

    return handshakeSucceeded
}
