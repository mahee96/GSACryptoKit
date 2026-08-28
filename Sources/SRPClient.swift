//
//  SRPClient.swift
//  GSACryptoKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 GSACryptoKit. All rights reserved.
//

import Foundation
import Crypto

public final class SRPClient {

    // RFC 5054 2048-bit MODP Group Prime (N)
    private static let N_Hex = """
    AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
    A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
    E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAF829197CE9E9A8380F\
    45F0687F3550757F61F5A45E81B2AA30ED32AEE6D4570E4E0AAC5A723589B832\
    CE84731FCF08EC74E3505FA79CE9CE622F53A062D63A5B3115F626807726DC89\
    3621E283DDA383838CFD9A1DAA71E9823C497B800E02FCE0AFE3A92BEFE718F2\
    08025E37A6E54ADF263C87B7EF4277A5209EAB40D879744F4A703DF7B6406880\
    2E0257DAE2E6AFECC4036E5006653E08B6C7B4E0C347E85945CEBF57BB30ACF7
    """

    private static let N_Bytes: Data = Data(hexString: N_Hex)!
    private static let g_Val: UInt32 = 2
    public static let GroupSize: Int = 256

    private let bnN: BigUInt
    private let bng: BigUInt
    private let bnk: BigUInt
    private var bna: BigUInt? // client private ephemeral
    private var bnA: BigUInt? // client public ephemeral
    private var bnK: Data?    // session key (32 bytes)
    private var expectedM2: Data?

    private static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    public init?() {
        let n = BigUInt(data: Self.N_Bytes)
        let g = BigUInt(UInt64(Self.g_Val))
        self.bnN = n
        self.bng = g

        // Compute k = SHA256(N || pad(g))
        var gPadded = Data(repeating: 0, count: Self.GroupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let kBytes = Self.sha256(Self.N_Bytes + gPadded)
        self.bnk = BigUInt(data: kBytes)
    }

    public func exchangeSize() -> Int {
        return Self.GroupSize
    }

    public func startAuthentication() -> Data? {
        // Generate random private ephemeral a (256 bits = 32 bytes)
        let a = BigUInt.random(bitWidth: 256)
        // A = g^a mod N
        let A = bng.power(a, modulus: bnN)

        self.bna = a
        self.bnA = A

        return A.serialize(paddedTo: Self.GroupSize)
    }

    public func processChallenge(
        username: String,
        password xData: Data,
        salt: Data,
        serverPublicKey bData: Data
    ) -> Data? {
        guard let bna = bna, let bnA = bnA else { return nil }

        // 1. Load B from server
        let bnB = BigUInt(data: bData)

        // Check B % N != 0
        guard !(bnB % bnN).isZero else { return nil }

        // 2. Export A as 256-byte padded Data
        let aData = bnA.serialize(paddedTo: Self.GroupSize)

        // 3. Compute u = SHA256(A || B)
        let uData = Self.sha256(aData + bData)
        let bnu = BigUInt(data: uData)
        guard !bnu.isZero else { return nil }

        // 4. Load x
        let bnx = BigUInt(data: xData)

        // 5. v = g^x mod N
        let bnv = bng.power(bnx, modulus: bnN)

        // 6. Base = (B - k*v) mod N
        let bnkv = (bnk * bnv) % bnN
        let bnBase = bnB.modSub(bnkv, modulus: bnN)

        // 7. Exp = (a + u*x)
        let bnux = bnu * bnx
        let bnExp = bna + bnux

        // 8. S = Base^Exp mod N
        let bnS = bnBase.power(bnExp, modulus: bnN)
        let sBytes = bnS.serialize(paddedTo: Self.GroupSize)

        // 9. Session key K = SHA256(S)
        let kSessionData = Self.sha256(sBytes)
        self.bnK = kSessionData

        // 10. Compute M1 = SHA256(H(N) ^ H(g) || H(U) || salt || A || B || K)
        let hn = Self.sha256(Self.N_Bytes)
        var gPadded = Data(repeating: 0, count: Self.GroupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let hg = Self.sha256(gPadded)

        var hXor = Data(count: 32)
        for i in 0..<32 {
            hXor[i] = hn[i] ^ hg[i]
        }

        let hu = Self.sha256(Data(username.utf8))
        let m1Payload = hXor + hu + salt + aData + bData + kSessionData
        let m1Data = Self.sha256(m1Payload)

        // 11. Precompute expected M2 = SHA256(A || M1 || K)
        let m2Payload = aData + m1Data + kSessionData
        self.expectedM2 = Self.sha256(m2Payload)

        return m1Data
    }

    public func verifyServerProof(_ proof: Data) -> Bool {
        guard let expected = expectedM2 else { return false }
        return proof == expected
    }

    public func sessionKey() -> Data? {
        return bnK
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
