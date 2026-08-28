//
//  CryptoUtilitiesTests.swift
//  GSACryptoKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 GSACryptoKit. All rights reserved.
//

import Testing
import Foundation
import Crypto
import CryptoExtras
import OpenSSL
@testable import GSACryptoKit

@Suite
struct CryptoUtilitiesTests {

    @Test
    func sha256Hashing() throws {
        let testInputs = [
            "abc".data(using: .utf8)!,
            "".data(using: .utf8)!,
            Data((0..<1024).map { UInt8($0 & 0xFF) })
        ]

        for input in testInputs {
            let hash = CryptoUtilities.sha256(input)
            let hashData = try #require(hash)

            let expected = Data(SHA256.hash(data: input))
            #expect(hashData == expected)
        }

        // Test with known RFC 6234 standard test vector: SHA-256("abc")
        let abcHash = try #require(CryptoUtilities.sha256("abc".data(using: .utf8)!))
        let expectedAbcHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        #expect(abcHash.hexEncodedString() == expectedAbcHex)
    }

    @Test
    func hmacSHA256Computation() throws {
        let key = "secret-key".data(using: .utf8)!
        let strings = ["Part1", "Part2", "Part3"]
        let hmac = CryptoUtilities.hmacSHA256(key: key, strings: strings)
        let hmacData = try #require(hmac)

        // HMAC over "Part1Part2Part3"
        let fullData = "Part1Part2Part3".data(using: .utf8)!
        let expected = Data(HMAC<SHA256>.authenticationCode(for: fullData, using: SymmetricKey(data: key)))
        #expect(hmacData == expected)
    }

    @Test
    func pbkdf2SHA256KeyDerivation() throws {
        let password = "MySecurePassword".data(using: .utf8)!
        let salt = "RandomSaltValue123".data(using: .utf8)!
        let rounds = 1000
        let outputLength = 32

        let derived = CryptoUtilities.pbkdf2SHA256(
            password: password,
            salt: salt,
            rounds: rounds,
            outputLength: outputLength
        )
        let derivedData = try #require(derived)
        #expect(derivedData.count == 32)

        // Repeated derivation must be deterministic
        let derivedAgain = CryptoUtilities.pbkdf2SHA256(
            password: password,
            salt: salt,
            rounds: rounds,
            outputLength: outputLength
        )
        #expect(derivedData == derivedAgain)

        // Test with RFC 6070 PBKDF2-HMAC-SHA256 test vectors:
        // Password = "password", Salt = "salt", c = 1, dkLen = 32
        let rfcVector1 = CryptoUtilities.pbkdf2SHA256(
            password: "password".data(using: .utf8)!,
            salt: "salt".data(using: .utf8)!,
            rounds: 1,
            outputLength: 32
        )
        let rfcData1 = try #require(rfcVector1)
        #expect(rfcData1.hexEncodedString() == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")

        // Password = "password", Salt = "salt", c = 2, dkLen = 32
        let rfcVector2 = CryptoUtilities.pbkdf2SHA256(
            password: "password".data(using: .utf8)!,
            salt: "salt".data(using: .utf8)!,
            rounds: 2,
            outputLength: 32
        )
        let rfcData2 = try #require(rfcVector2)
        #expect(rfcData2.hexEncodedString() == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    @Test
    func aesCBCDecryption() throws {
        let plaintext = "Secret data encrypted with AES-256-CBC with PKCS7 padding!".data(using: .utf8)!
        let key = Data((0..<32).map { UInt8($0 + 1) })
        let iv = Data((0..<16).map { UInt8($0 + 10) })

        // Encrypt with CryptoExtras AES._CBC
        let ciphertext = try encryptAESCBC(plaintext: plaintext, key: key, iv: iv)

        // Decrypt with CryptoUtilities
        let decrypted = CryptoUtilities.aesCBCDecrypt(key: key, iv: iv, ciphertext: ciphertext)
        let decryptedData = try #require(decrypted)
        #expect(decryptedData == plaintext)
    }

    @Test
    func aesCBCDecryptionFailures() throws {
        let plaintext = "Some message".data(using: .utf8)!
        let key = Data((0..<32).map { UInt8($0 + 1) })
        let iv = Data((0..<16).map { UInt8($0 + 10) })

        let ciphertext = try encryptAESCBC(plaintext: plaintext, key: key, iv: iv)

        // Invalid IV length (e.g. 10 bytes instead of 16)
        let invalidIV = Data((0..<10).map { UInt8($0) })
        #expect(CryptoUtilities.aesCBCDecrypt(key: key, iv: invalidIV, ciphertext: ciphertext) == nil)

        // Invalid key length (e.g. 20 bytes)
        let invalidKey = Data((0..<20).map { UInt8($0) })
        #expect(CryptoUtilities.aesCBCDecrypt(key: invalidKey, iv: iv, ciphertext: ciphertext) == nil)

        // Tampered ciphertext (corrupting padding / block)
        var corruptedCipher = Data(ciphertext)
        if let lastIdx = corruptedCipher.indices.last {
            corruptedCipher[lastIdx] ^= 0xFF
        }
        #expect(CryptoUtilities.aesCBCDecrypt(key: key, iv: iv, ciphertext: corruptedCipher) == nil)
    }

    @Test
    func aesGCMDecryption() throws {
        let plaintext = "Confidential Payload to be encrypted with AES-GCM".data(using: .utf8)!
        let keyData = Data((0..<32).map { UInt8($0 + 3) })
        let nonceData = Data((0..<12).map { UInt8($0 + 7) })
        let aad = "Authenticated-Additional-Data".data(using: .utf8)!

        // Seal with Crypto AES.GCM
        let (ciphertext, tag) = try encryptAESGCM(plaintext: plaintext, key: keyData, nonce: nonceData, aad: aad)

        // Decrypt with CryptoUtilities
        let decrypted = CryptoUtilities.aesGCMDecrypt(
            key: keyData,
            nonce: nonceData,
            aad: aad,
            ciphertext: ciphertext,
            tag: tag
        )
        #expect(decrypted != nil)
        #expect(decrypted == plaintext)

        // Tampered tag failure
        var corruptedTag = Data(tag)
        if let firstIdx = corruptedTag.indices.first {
            corruptedTag[firstIdx] ^= 0xFF
        }
        let failedDecryption = CryptoUtilities.aesGCMDecrypt(
            key: keyData,
            nonce: nonceData,
            aad: aad,
            ciphertext: ciphertext,
            tag: corruptedTag
        )
        #expect(failedDecryption == nil)

        // Tampered AAD failure
        let wrongAAD = "Tampered-AAD".data(using: .utf8)!
        let aadFailedDecryption = CryptoUtilities.aesGCMDecrypt(
            key: keyData,
            nonce: nonceData,
            aad: wrongAAD,
            ciphertext: ciphertext,
            tag: tag
        )
        #expect(aadFailedDecryption == nil)
    }

    @Test
    func crossValidationWithOpenSSL() throws {
        let testData = "Cross validation between pure Swift and OpenSSL".data(using: .utf8)!
        let key = Data((0..<32).map { UInt8($0 + 5) })
        let iv = Data((0..<16).map { UInt8($0 + 2) })
        let nonce = Data((0..<12).map { UInt8($0 + 1) })
        let aad = "AAD-Header".data(using: .utf8)!

        // 1. SHA256 cross validation
        let swiftHash = try #require(CryptoUtilities.sha256(testData))
        var opensslHash = Data(count: Int(SHA256_DIGEST_LENGTH))
        _ = opensslHash.withUnsafeMutableBytes { outBuf in
            testData.withUnsafeBytes { inBuf in
                SHA256(
                    inBuf.bindMemory(to: UInt8.self).baseAddress,
                    testData.count,
                    outBuf.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        #expect(swiftHash == opensslHash)

        // 2. HMAC-SHA256 cross validation
        let strings = ["GSA", "Crypto", "Test"]
        let swiftHMAC = try #require(CryptoUtilities.hmacSHA256(key: key, strings: strings))
        let concatenated = "GSACryptoTest".data(using: .utf8)!
        var opensslHMAC = Data(count: Int(SHA256_DIGEST_LENGTH))
        var mdLen: UInt32 = 0
        _ = opensslHMAC.withUnsafeMutableBytes { mdBytes in
            key.withUnsafeBytes { keyBytes in
                concatenated.withUnsafeBytes { dataBytes in
                    HMAC(
                        EVP_sha256(),
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        Int32(key.count),
                        dataBytes.bindMemory(to: UInt8.self).baseAddress,
                        concatenated.count,
                        mdBytes.bindMemory(to: UInt8.self).baseAddress,
                        &mdLen
                    )
                }
            }
        }
        #expect(swiftHMAC == opensslHMAC)

        // 3. PBKDF2 cross validation
        let swiftPBKDF2 = try #require(CryptoUtilities.pbkdf2SHA256(password: key, salt: iv, rounds: 500, outputLength: 32))
        var opensslPBKDF2 = Data(count: 32)
        _ = opensslPBKDF2.withUnsafeMutableBytes { outBytes in
            key.withUnsafeBytes { pwdBytes in
                iv.withUnsafeBytes { saltBytes in
                    PKCS5_PBKDF2_HMAC(
                        pwdBytes.bindMemory(to: CChar.self).baseAddress,
                        Int32(key.count),
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        Int32(iv.count),
                        500,
                        EVP_sha256(),
                        32,
                        outBytes.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        #expect(swiftPBKDF2 == opensslPBKDF2)

        // 4. OpenSSL encrypted AES-CBC decrypted by pure Swift
        let opensslCipherCBC = try encryptOpenSSLAESCBC(plaintext: testData, key: key, iv: iv)
        let swiftDecryptedCBC = CryptoUtilities.aesCBCDecrypt(key: key, iv: iv, ciphertext: opensslCipherCBC)
        #expect(swiftDecryptedCBC == testData)

        // 5. OpenSSL sealed AES-GCM decrypted by pure Swift
        let (opensslCipherGCM, opensslTagGCM) = try encryptOpenSSLAESGCM(plaintext: testData, key: key, nonce: nonce, aad: aad)
        let swiftDecryptedGCM = CryptoUtilities.aesGCMDecrypt(key: key, nonce: nonce, aad: aad, ciphertext: opensslCipherGCM, tag: opensslTagGCM)
        #expect(swiftDecryptedGCM == testData)
    }

    // Helper to encrypt using CryptoExtras AES._CBC with PKCS#7 padding
    private func encryptAESCBC(plaintext: Data, key: Data, iv: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let ivObj = try AES._CBC.IV(ivBytes: iv)
        return Data(try AES._CBC.encrypt(plaintext, using: symmetricKey, iv: ivObj, noPadding: false))
    }

    // Helper to encrypt using Crypto AES.GCM
    private func encryptAESGCM(plaintext: Data, key: Data, nonce: Data, aad: Data) throws -> (ciphertext: Data, tag: Data) {
        let symmetricKey = SymmetricKey(data: key)
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce, authenticating: aad)
        return (Data(sealedBox.ciphertext), Data(sealedBox.tag))
    }

    // Helper to encrypt using OpenSSL EVP_Encrypt AES-256-CBC
    private func encryptOpenSSLAESCBC(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard let ctx = EVP_CIPHER_CTX_new() else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 1, userInfo: nil)
        }
        defer { EVP_CIPHER_CTX_free(ctx) }

        guard EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nil, nil, nil) == 1 else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 2, userInfo: nil)
        }
        guard key.withUnsafeBytes({ keyBytes in
            iv.withUnsafeBytes { ivBytes in
                EVP_EncryptInit_ex(ctx, nil, nil, keyBytes.bindMemory(to: UInt8.self).baseAddress, ivBytes.bindMemory(to: UInt8.self).baseAddress) == 1
            }
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 3, userInfo: nil)
        }

        var out = Data(count: plaintext.count + 16)
        var outLen: Int32 = 0
        guard out.withUnsafeMutableBytes({ outBytes in
            plaintext.withUnsafeBytes { inBytes in
                EVP_EncryptUpdate(ctx, outBytes.bindMemory(to: UInt8.self).baseAddress, &outLen, inBytes.bindMemory(to: UInt8.self).baseAddress, Int32(plaintext.count)) == 1
            }
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 4, userInfo: nil)
        }

        var finalLen: Int32 = 0
        guard out.withUnsafeMutableBytes({ outBytes in
            EVP_EncryptFinal_ex(ctx, outBytes.bindMemory(to: UInt8.self).baseAddress?.advanced(by: Int(outLen)), &finalLen) == 1
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 5, userInfo: nil)
        }

        return out.prefix(Int(outLen + finalLen))
    }

    // Helper to encrypt using OpenSSL EVP_Encrypt AES-256-GCM
    private func encryptOpenSSLAESGCM(plaintext: Data, key: Data, nonce: Data, aad: Data) throws -> (ciphertext: Data, tag: Data) {
        guard let ctx = EVP_CIPHER_CTX_new() else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 6, userInfo: nil)
        }
        defer { EVP_CIPHER_CTX_free(ctx) }

        guard EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil) == 1 else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 7, userInfo: nil)
        }
        guard EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, Int32(nonce.count), nil) == 1 else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 8, userInfo: nil)
        }
        guard key.withUnsafeBytes({ keyBytes in
            nonce.withUnsafeBytes { nonceBytes in
                EVP_EncryptInit_ex(ctx, nil, nil, keyBytes.bindMemory(to: UInt8.self).baseAddress, nonceBytes.bindMemory(to: UInt8.self).baseAddress) == 1
            }
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 9, userInfo: nil)
        }

        var outLen: Int32 = 0
        if !aad.isEmpty {
            guard aad.withUnsafeBytes({ aadBytes in
                EVP_EncryptUpdate(ctx, nil, &outLen, aadBytes.bindMemory(to: UInt8.self).baseAddress, Int32(aad.count)) == 1
            }) else {
                throw NSError(domain: "CryptoUtilitiesTests", code: 10, userInfo: nil)
            }
        }

        var out = Data(count: plaintext.count + 16)
        guard out.withUnsafeMutableBytes({ outBytes in
            plaintext.withUnsafeBytes { inBytes in
                EVP_EncryptUpdate(ctx, outBytes.bindMemory(to: UInt8.self).baseAddress, &outLen, inBytes.bindMemory(to: UInt8.self).baseAddress, Int32(plaintext.count)) == 1
            }
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 11, userInfo: nil)
        }

        var finalLen: Int32 = 0
        guard out.withUnsafeMutableBytes({ outBytes in
            EVP_EncryptFinal_ex(ctx, outBytes.bindMemory(to: UInt8.self).baseAddress?.advanced(by: Int(outLen)), &finalLen) == 1
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 12, userInfo: nil)
        }

        var tag = Data(count: 16)
        guard tag.withUnsafeMutableBytes({ tagBytes in
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagBytes.baseAddress) == 1
        }) else {
            throw NSError(domain: "CryptoUtilitiesTests", code: 13, userInfo: nil)
        }

        return (out.prefix(Int(outLen + finalLen)), tag)
    }
}

fileprivate extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
