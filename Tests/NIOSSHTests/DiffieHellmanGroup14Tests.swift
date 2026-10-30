//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class DiffieHellmanGroup14Tests: XCTestCase {
    private static let prime = """
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
        83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
        15728E5A8AACAA68FFFFFFFFFFFFFFFF
        """

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Expected values computed independently with Python's `pow(base, exponent, p)`.
    func testModularExponentiationMatchesKnownAnswers() {
        let group = MontgomeryModulus(hex: Self.prime)
        let exponent = Array(UInt8(1)...UInt8(64))

        let generator = MontgomeryModulus.limbs(fromBigEndian: [2], count: 64)
        XCTAssertEqual(
            self.hex(MontgomeryModulus.bytes(group.power(generator, exponent), count: 256)),
            "ca737546c70b3a25a43d745a3e31526b3fc9f28dca1b890fed9c1cc46a1d23022c597a3f9dcc6de91383f788f139e35c290558305a7935d242e1ca4d830a0b94abdc8b3f1bc6b0c43c6e8330b29a5f61ae8ac3ebddebbd69206d41fe819e975e982b4d290a93c8ecb87ec2c2e363544fe5b9f44af371e15c9f5d3c83e7904001bb9cf1667538acd767c24f2bed29ae165c5e3ad7ca009d9c801eb75febd18c50477ac0ae9562c684efd4d0c696046f8a95603d228c6c407f8d15d6aba62f433c6b023e8f2d9722cd34bd355dc2496693ee66a3cdc55d1ee1d7766554428a0b1299b5882359f9de57ca7a3ba3c3ca2d552ac6584a7ce9fd4846140888a7b411f8"
        )

        // p - 5 exercises the reduction near the top of the range.
        var primeBytes = stride(from: 0, to: 512, by: 2).map {
            UInt8(Self.prime.dropFirst($0).prefix(2), radix: 16)!
        }
        primeBytes[255] -= 5
        let nearTop = MontgomeryModulus.limbs(fromBigEndian: primeBytes, count: 64)
        XCTAssertEqual(
            self.hex(MontgomeryModulus.bytes(group.power(nearTop, exponent), count: 256)),
            "574a86d3546f11ad68e82bc479e36f9bcf2f2b718733476fcb7050dd1556fa2052fe077f0ef81fc201f93de8b62a66bd20d45e5246a37ff082f8a38a56542907d1f46d69b58386c8e8f8950f662c101f117d2cd06951fd5a6dd03189cd323f80be8726bedc6a397eeffc85b3abb2e5e57450fe34e6051ba3dfe948395e4f15ba808698f0ee740f2fdd202420668cdd58f671a1b20431e7dbce5c373865be7d0529306143c27982b6ffcf762951cbd58c2cc6c9e4a1d2dfe07956dbb35b6249eda2295afdd8134b5d0a38b480508d855ab9a6e2abfba39affc2d551ea999e848af776a4b87bac61ea4c29b7d49440b53adc024750da8e6418190a10d30ac87882"
        )
    }

    func testRejectsTrivialPeerValues() throws {
        let key = DiffieHellmanGroup14PrivateKey()
        for value: [UInt8] in [[0x01], [0x00, 0x7F]] {
            var buffer = ByteBufferAllocator().buffer(bytes: value)
            if value == [0x01] {
                let peer = try DiffieHellmanGroup14PrivateKey.PublicKey(buffer: buffer)
                XCTAssertThrowsError(try key.generatedSharedSecret(with: peer))
            } else {
                // An unnecessary leading zero byte is not a valid mpint.
                XCTAssertThrowsError(try DiffieHellmanGroup14PrivateKey.PublicKey(buffer: buffer))
            }
            buffer.clear()
        }
        // A set sign bit would be a negative mpint.
        XCTAssertThrowsError(
            try DiffieHellmanGroup14PrivateKey.PublicKey(buffer: ByteBufferAllocator().buffer(bytes: [0x80]))
        )
    }

    func testPublicKeyWritesAPositiveMPIntBody() throws {
        let key = DiffieHellmanGroup14PrivateKey()
        var buffer = ByteBufferAllocator().buffer(capacity: 257)
        key.publicKey.write(to: &buffer)
        let bytes = Array(buffer.readableBytesView)
        XCTAssertTrue(bytes[0] & 0x80 == 0)
        XCTAssertTrue(bytes[0] != 0 || bytes[1] & 0x80 != 0)
        // And it reads back to the same value.
        var again = ByteBufferAllocator().buffer(capacity: 257)
        try DiffieHellmanGroup14PrivateKey.PublicKey(buffer: buffer).write(to: &again)
        XCTAssertEqual(buffer, again)
    }

    func testShortSecretsHashAsMPIntWithFourByteLength() {
        // A 256 byte secret must be hashed with a 4 byte length of 0x00000100 (or 0x00000101 with a sign byte).
        var secret = [UInt8](repeating: 0x7F, count: 256)
        var hasher = SHA256()
        hasher.update(data: [0x00, 0x00, 0x01, 0x00] + secret)
        let expected = hasher.finalize()
        XCTAssertEqual(Array(self.mpintHash(secret)), Array(expected))

        secret[0] = 0x80
        hasher = SHA256()
        hasher.update(data: [0x00, 0x00, 0x01, 0x01, 0x00] + secret)
        XCTAssertEqual(Array(self.mpintHash(secret)), Array(hasher.finalize()))
    }

    private func mpintHash(_ secret: [UInt8]) -> SHA256.Digest {
        var hasher = SHA256()
        hasher.updateAsMPInt(sharedSecret: secret)
        return hasher.finalize()
    }
}
