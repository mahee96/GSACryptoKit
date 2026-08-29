//
//  SRPClientTests.swift
//  GSACryptoKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 GSACryptoKit. All rights reserved.
//

import Testing
import Foundation
import Crypto
import OpenSSL
@testable import GSACryptoKit

@Suite
struct SRPClientTests {

    // RFC 5054 2048-bit MODP Group Prime (N)
    private static let N_Hex = """
    AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
    A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
    E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8\
    55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B\
    CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748\
    544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6\
    AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
    94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
    """

    private static let N_Bytes: Data = Data(hexString: N_Hex)!
    private static let g_Val: UInt32 = 2
    private static let groupSize = 256

    private static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    @Test
    func srpClientInitialization() throws {
        let client = SRPClient()
        #expect(client != nil)
        #expect(client?.exchangeSize() == 256)
        #expect(client?.sessionKey() == nil)
    }

    @Test
    func srpAuthenticationStart() throws {
        let client = try #require(SRPClient())
        let clientPublicA = client.startAuthentication()
        let aData = try #require(clientPublicA)
        #expect(aData.count == 256)
    }

    @Test
    func fullSRP6aEndToEndExchange() throws {
        let username = "appleid@example.com"
        let password = "MySecurePassword123!"
        let salt = Data((0..<32).map { UInt8($0 + 5) })

        // Derive x = SHA256(salt || SHA256(username || ":" || password))
        let userPassDigest = Self.sha256(Data("\(username):\(password)".utf8))
        let xData = Self.sha256(salt + userPassDigest)

        // Simulated Server: Compute verifier v = g^x mod N
        let verifierV = try computeServerVerifier(x: xData)

        // 1. Client starts authentication and generates public A
        let client = try #require(SRPClient())
        let clientA = try #require(client.startAuthentication())

        // 2. Server generates private ephemeral b, public ephemeral B = (k*v + g^b) mod N
        let (serverB, serverPrivateKeyB) = try generateServerEphemeral(verifier: verifierV)

        // 3. Client processes challenge with server B -> produces M1 proof
        let clientM1 = client.processChallenge(
            username: username,
            password: xData,
            salt: salt,
            serverPublicKey: serverB
        )
        let m1Data = try #require(clientM1)
        #expect(m1Data.count == 32)

        // 4. Server computes shared secret S, session key K, and verifies M1
        let (serverM1, serverM2, serverK) = try computeServerVerification(
            username: username,
            salt: salt,
            clientA: clientA,
            serverB: serverB,
            serverPrivateB: serverPrivateKeyB,
            verifierV: verifierV
        )

        // Server confirms Client M1 matches
        #expect(m1Data == serverM1)

        // 5. Client verifies Server Proof M2
        let isServerVerified = client.verifyServerProof(serverM2)
        #expect(isServerVerified)

        // 6. Both client and server derived the identical session key K
        let clientK = try #require(client.sessionKey())
        #expect(clientK == serverK)
        #expect(clientK.count == 32)
    }

    @Test
    func srpWrongPasswordFailure() throws {
        let username = "user@test.com"
        let realPassword = "CorrectPassword"
        let wrongPassword = "WrongPassword"
        let salt = Data(repeating: 0x42, count: 32)

        let realX = Self.sha256(salt + Self.sha256(Data("\(username):\(realPassword)".utf8)))
        let wrongX = Self.sha256(salt + Self.sha256(Data("\(username):\(wrongPassword)".utf8)))

        // Server has verifier for the real password
        let verifierV = try computeServerVerifier(x: realX)

        let client = try #require(SRPClient())
        let clientA = try #require(client.startAuthentication())
        let (serverB, serverBSecret) = try generateServerEphemeral(verifier: verifierV)

        // Client uses the WRONG password to process challenge
        let clientM1 = client.processChallenge(
            username: username,
            password: wrongX,
            salt: salt,
            serverPublicKey: serverB
        )
        let clientM1Data = try #require(clientM1)

        // Server verification
        let (serverM1, serverM2, _) = try computeServerVerification(
            username: username,
            salt: salt,
            clientA: clientA,
            serverB: serverB,
            serverPrivateB: serverBSecret,
            verifierV: verifierV
        )

        // M1 must not match
        #expect(clientM1Data != serverM1)

        // Client verifying server M2 must also fail
        let verified = client.verifyServerProof(serverM2)
        #expect(!verified)
    }

    @Test
    func srpInvalidServerPublicKey() throws {
        let username = "user@test.com"
        let password = "TestPassword"
        let salt = Data(repeating: 0x11, count: 32)
        let xData = Self.sha256(salt + Self.sha256(Data("\(username):\(password)".utf8)))

        let client = try #require(SRPClient())
        _ = client.startAuthentication()

        // Server public key B = 0 (invalid modulo N)
        let invalidBZero = Data(repeating: 0, count: 256)
        let resultZero = client.processChallenge(
            username: username,
            password: xData,
            salt: salt,
            serverPublicKey: invalidBZero
        )
        #expect(resultZero == nil)
    }

    @Test
    func srpTamperedServerProofRejected() throws {
        let username = "user@test.com"
        let password = "TestPassword"
        let salt = Data(repeating: 0x77, count: 32)
        let xData = Self.sha256(salt + Self.sha256(Data("\(username):\(password)".utf8)))

        let verifierV = try computeServerVerifier(x: xData)
        let client = try #require(SRPClient())
        let clientA = try #require(client.startAuthentication())
        let (serverB, serverBSecret) = try generateServerEphemeral(verifier: verifierV)

        _ = client.processChallenge(
            username: username,
            password: xData,
            salt: salt,
            serverPublicKey: serverB
        )

        let (_, serverM2, _) = try computeServerVerification(
            username: username,
            salt: salt,
            clientA: clientA,
            serverB: serverB,
            serverPrivateB: serverBSecret,
            verifierV: verifierV
        )

        // Tamper 1 byte of server M2 proof
        var tamperedM2 = Data(serverM2)
        if let firstIdx = tamperedM2.indices.first {
            tamperedM2[firstIdx] ^= 0xFF
        }

        #expect(!client.verifyServerProof(tamperedM2))
    }

    // Helper: Compute server verifier v = g^x mod N
    @Test
    func srpCrossValidationWithOpenSSLServer() throws {
        let username = "crossval@example.com"
        let password = "SuperSecretPassword99!"
        let salt = Data((0..<32).map { UInt8($0 + 11) })

        let userPassDigest = Self.sha256(Data("\(username):\(password)".utf8))
        let xData = Self.sha256(salt + userPassDigest)

        // 1. Compute server verifier v = g^x mod N using OpenSSL
        let verifierV = try computeOpenSSLServerVerifier(x: xData)

        // 2. Pure Swift Client generates A
        let client = try #require(SRPClient())
        let clientA = try #require(client.startAuthentication())

        // 3. OpenSSL generates server ephemeral B = (k*v + g^b) mod N and private b
        let (serverB, serverPrivateKeyB) = try generateOpenSSLServerEphemeral(verifier: verifierV)

        // 4. Pure Swift Client processes challenge with OpenSSL server B -> produces M1 proof
        let clientM1 = client.processChallenge(
            username: username,
            password: xData,
            salt: salt,
            serverPublicKey: serverB
        )
        let m1Data = try #require(clientM1)

        // 5. OpenSSL Server computes shared secret S, session key K, and verifies M1
        let (serverM1, serverM2, serverK) = try computeOpenSSLServerVerification(
            username: username,
            salt: salt,
            clientA: clientA,
            serverB: serverB,
            serverPrivateB: serverPrivateKeyB,
            verifierV: verifierV
        )

        // Pure Swift Client M1 matches OpenSSL Server M1
        #expect(m1Data == serverM1)

        // Pure Swift Client verifies OpenSSL Server proof M2
        let isVerified = client.verifyServerProof(serverM2)
        #expect(isVerified)

        // Both derive the exact identical session key K
        let clientK = try #require(client.sessionKey())
        #expect(clientK == serverK)
        #expect(clientK.count == 32)
    }

    // Helper: Compute server verifier v = g^x mod N (Pure Swift)
    private func computeServerVerifier(x: Data) throws -> Data {
        let bnN = BigUInt(data: Self.N_Bytes)
        let bng = BigUInt(UInt64(Self.g_Val))
        let bnx = BigUInt(data: x)
        let bnv = bng.power(bnx, modulus: bnN)
        return bnv.serialize(paddedTo: Self.groupSize)
    }

    // Helper: Generate server ephemeral B = (k*v + g^b) mod N and private b
    private func generateServerEphemeral(verifier: Data) throws -> (Data, Data) {
        let bnN = BigUInt(data: Self.N_Bytes)
        let bng = BigUInt(UInt64(Self.g_Val))
        let bnv = BigUInt(data: verifier)

        // k = SHA256(N || pad(g))
        var gPadded = Data(repeating: 0, count: Self.groupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let kBytes = Self.sha256(Self.N_Bytes + gPadded)
        let bnk = BigUInt(data: kBytes)

        // Generate random b (256-bit)
        let bnb = BigUInt.random(bitWidth: 256)

        // gb = g^b mod N
        let bnGb = bng.power(bnb, modulus: bnN)
        let bnKv = (bnk * bnv) % bnN
        let bnB = (bnKv + bnGb) % bnN

        let bBytes = bnB.serialize(paddedTo: Self.groupSize)
        let privBBytes = bnb.serialize(paddedTo: 32)

        return (bBytes, privBBytes)
    }

    // Helper: Simulated server computation of S = (A * v^u)^b mod N, K = SHA256(S), M1, M2
    private func computeServerVerification(
        username: String,
        salt: Data,
        clientA: Data,
        serverB: Data,
        serverPrivateB: Data,
        verifierV: Data
    ) throws -> (Data, Data, Data) {
        let bnN = BigUInt(data: Self.N_Bytes)
        let bnA = BigUInt(data: clientA)
        let bnv = BigUInt(data: verifierV)
        let bnb = BigUInt(data: serverPrivateB)

        // u = SHA256(A || B)
        let uData = Self.sha256(clientA + serverB)
        let bnu = BigUInt(data: uData)

        // S = (A * v^u)^b mod N
        let bnVu = bnv.power(bnu, modulus: bnN)
        let bnBase = (bnA * bnVu) % bnN
        let bnS = bnBase.power(bnb, modulus: bnN)

        let sBytes = bnS.serialize(paddedTo: Self.groupSize)

        // K = SHA256(S)
        let serverK = Self.sha256(sBytes)

        // M1 = SHA256(H(N) ^ H(g) || H(U) || salt || A || B || K)
        let hn = Self.sha256(Self.N_Bytes)
        var gPadded = Data(repeating: 0, count: Self.groupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let hg = Self.sha256(gPadded)

        var hXor = Data(count: 32)
        for i in 0..<32 {
            hXor[i] = hn[i] ^ hg[i]
        }

        let hu = Self.sha256(Data(username.utf8))
        let m1Payload = hXor + hu + salt + clientA + serverB + serverK
        let serverM1 = Self.sha256(m1Payload)

        // M2 = SHA256(A || M1 || K)
        let m2Payload = clientA + serverM1 + serverK
        let serverM2 = Self.sha256(m2Payload)

        return (serverM1, serverM2, serverK)
    }

    // Helper: Compute server verifier v = g^x mod N using OpenSSL BIGNUM
    private func computeOpenSSLServerVerifier(x: Data) throws -> Data {
        guard let bnN = BN_new(), let bng = BN_new(), let bnx = BN_new(), let bnv = BN_new(), let ctx = BN_CTX_new() else {
            throw NSError(domain: "SRPClientTests", code: 1, userInfo: nil)
        }
        defer {
            BN_free(bnN); BN_free(bng); BN_free(bnx); BN_free(bnv); BN_CTX_free(ctx)
        }

        _ = Self.N_Bytes.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.N_Bytes.count), bnN) }
        BN_set_word(bng, UInt(Self.g_Val))
        _ = x.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(x.count), bnx) }

        guard BN_mod_exp(bnv, bng, bnx, bnN, ctx) == 1 else {
            throw NSError(domain: "SRPClientTests", code: 2, userInfo: nil)
        }

        var vBytes = Data(count: Self.groupSize)
        _ = vBytes.withUnsafeMutableBytes { BN_bn2binpad(bnv, $0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.groupSize)) }
        return vBytes
    }

    // Helper: Generate server ephemeral B = (k*v + g^b) mod N and private b using OpenSSL
    private func generateOpenSSLServerEphemeral(verifier: Data) throws -> (Data, Data) {
        guard let bnN = BN_new(), let bng = BN_new(), let bnk = BN_new(),
              let bnv = BN_new(), let bnb = BN_new(), let bnB = BN_new(),
              let ctx = BN_CTX_new() else {
            throw NSError(domain: "SRPClientTests", code: 3, userInfo: nil)
        }
        defer {
            BN_free(bnN); BN_free(bng); BN_free(bnk); BN_free(bnv); BN_free(bnb); BN_free(bnB); BN_CTX_free(ctx)
        }

        _ = Self.N_Bytes.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.N_Bytes.count), bnN) }
        BN_set_word(bng, UInt(Self.g_Val))
        _ = verifier.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(verifier.count), bnv) }

        var gPadded = Data(repeating: 0, count: Self.groupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let kBytes = Self.sha256(Self.N_Bytes + gPadded)
        _ = kBytes.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(kBytes.count), bnk) }

        BN_rand(bnb, 256, 0, 0)

        guard let bnGb = BN_new(), let bnKv = BN_new() else {
            throw NSError(domain: "SRPClientTests", code: 4, userInfo: nil)
        }
        defer { BN_free(bnGb); BN_free(bnKv) }

        BN_mod_exp(bnGb, bng, bnb, bnN, ctx)
        BN_mod_mul(bnKv, bnk, bnv, bnN, ctx)
        BN_mod_add(bnB, bnKv, bnGb, bnN, ctx)

        var bBytes = Data(count: Self.groupSize)
        _ = bBytes.withUnsafeMutableBytes { BN_bn2binpad(bnB, $0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.groupSize)) }

        var privBBytes = Data(count: 32)
        _ = privBBytes.withUnsafeMutableBytes { BN_bn2binpad(bnb, $0.bindMemory(to: UInt8.self).baseAddress, 32) }

        return (bBytes, privBBytes)
    }

    // Helper: Simulated server computation using OpenSSL
    private func computeOpenSSLServerVerification(
        username: String,
        salt: Data,
        clientA: Data,
        serverB: Data,
        serverPrivateB: Data,
        verifierV: Data
    ) throws -> (Data, Data, Data) {
        guard let bnN = BN_new(), let bng = BN_new(), let bnA = BN_new(),
              let bnv = BN_new(), let bnb = BN_new(), let bnu = BN_new(),
              let bnS = BN_new(), let ctx = BN_CTX_new() else {
            throw NSError(domain: "SRPClientTests", code: 5, userInfo: nil)
        }
        defer {
            BN_free(bnN); BN_free(bng); BN_free(bnA); BN_free(bnv); BN_free(bnb); BN_free(bnu); BN_free(bnS); BN_CTX_free(ctx)
        }

        _ = Self.N_Bytes.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.N_Bytes.count), bnN) }
        BN_set_word(bng, UInt(Self.g_Val))
        _ = clientA.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(clientA.count), bnA) }
        _ = verifierV.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(verifierV.count), bnv) }
        _ = serverPrivateB.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(serverPrivateB.count), bnb) }

        let uData = Self.sha256(clientA + serverB)
        _ = uData.withUnsafeBytes { BN_bin2bn($0.bindMemory(to: UInt8.self).baseAddress, Int32(uData.count), bnu) }

        guard let bnVu = BN_new(), let bnBase = BN_new() else {
            throw NSError(domain: "SRPClientTests", code: 6, userInfo: nil)
        }
        defer { BN_free(bnVu); BN_free(bnBase) }

        BN_mod_exp(bnVu, bnv, bnu, bnN, ctx)
        BN_mod_mul(bnBase, bnA, bnVu, bnN, ctx)
        BN_mod_exp(bnS, bnBase, bnb, bnN, ctx)

        var sBytes = Data(count: Self.groupSize)
        _ = sBytes.withUnsafeMutableBytes { BN_bn2binpad(bnS, $0.bindMemory(to: UInt8.self).baseAddress, Int32(Self.groupSize)) }

        let serverK = Self.sha256(sBytes)

        let hn = Self.sha256(Self.N_Bytes)
        var gPadded = Data(repeating: 0, count: Self.groupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let hg = Self.sha256(gPadded)

        var hXor = Data(count: 32)
        for i in 0..<32 {
            hXor[i] = hn[i] ^ hg[i]
        }

        let hu = Self.sha256(Data(username.utf8))
        let m1Payload = hXor + hu + salt + clientA + serverB + serverK
        let serverM1 = Self.sha256(m1Payload)

        let m2Payload = clientA + serverM1 + serverK
        let serverM2 = Self.sha256(m2Payload)

        return (serverM1, serverM2, serverK)
    }
}

fileprivate extension Data {
    init?(hexString: String) {
        let cleaned = hexString.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\t", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var data = Data(capacity: cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let nextIndex = cleaned.index(index, offsetBy: 2)
            let byteStr = String(cleaned[index..<nextIndex])
            guard let byte = UInt8(byteStr, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
