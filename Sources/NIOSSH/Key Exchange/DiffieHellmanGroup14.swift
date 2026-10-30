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

/// `diffie-hellman-group14-sha256` (RFC 8268): finite field Diffie-Hellman over the 2048-bit MODP group of RFC 3526.
///
/// This exists for peers that offer no elliptic curve exchange, such as the VS Code tunnel host. It reuses the
/// elliptic curve exchange machinery: SSH_MSG_KEXDH_INIT/REPLY share their message numbers and layout with the
/// ECDH messages, and an mpint is an SSH string whose body has no superfluous leading zero bytes.
struct DiffieHellmanGroup14PrivateKey: ECDHCompatiblePrivateKey {
    typealias Hasher = SHA256

    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group14-sha256"]

    /// The private exponent. 512 bits is twice the security strength of the group (RFC 8270 § 4).
    private let exponent: [UInt8]

    let publicKey: PublicKey

    init() {
        var generator = SystemRandomNumberGenerator()
        var exponent = (0..<64).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        exponent[0] |= 0x80
        self.exponent = exponent
        self.publicKey = PublicKey(value: Self.group.power(Self.generator, exponent))
    }

    func generatedSharedSecret(with other: PublicKey) throws -> [UInt8] {
        // RFC 8268 § 4: the peer's value must lie in [2, p-2], or the secret is trivially guessable.
        guard Self.group.isValidPeerValue(other.value) else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: "diffie-hellman-group14-sha256")
        }
        return MontgomeryModulus.bytes(Self.group.power(other.value, self.exponent), count: 256)
    }

    private static let generator = MontgomeryModulus.limbs(fromBigEndian: [2], count: 64)

    /// RFC 3526 § 3, the 2048-bit MODP group.
    private static let group = MontgomeryModulus(
        hex: """
            FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
            EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
            EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
            83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
            E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
            15728E5A8AACAA68FFFFFFFFFFFFFFFF
            """
    )
}

extension DiffieHellmanGroup14PrivateKey {
    struct PublicKey: ECDHCompatiblePublicKey {
        /// Little-endian 32-bit limbs.
        fileprivate let value: [UInt32]

        fileprivate init(value: [UInt32]) {
            self.value = value
        }

        init(buffer: ByteBuffer) throws {
            let bytes = Array(buffer.readableBytesView)
            // A positive mpint: no sign bit, and at most one leading zero byte, which must be needed.
            guard bytes.first.map({ $0 & 0x80 == 0 }) ?? false, bytes.count <= 257,
                bytes.count < 2 || bytes[0] != 0 || bytes[1] & 0x80 != 0
            else {
                throw NIOSSHError.invalidSSHMessage(reason: "invalid diffie-hellman public value")
            }
            self.value = MontgomeryModulus.limbs(fromBigEndian: bytes, count: 64)
        }

        @discardableResult
        func write(to buffer: inout ByteBuffer) -> Int {
            // The body of an mpint: strip leading zeros, and add one back if the top bit would read as a sign.
            var bytes = MontgomeryModulus.bytes(self.value, count: 256)[...]
            while bytes.first == 0 { bytes = bytes.dropFirst() }
            if let first = bytes.first, first & 0x80 != 0 {
                return buffer.writeInteger(UInt8(0)) + buffer.writeBytes(bytes)
            }
            return buffer.writeBytes(bytes)
        }
    }
}

/// Modular exponentiation for an odd modulus, using Montgomery multiplication (CIOS) over 32-bit limbs.
///
/// Not constant time: the exponent is ephemeral and used for a single exchange.
struct MontgomeryModulus {
    /// Little-endian 32-bit limbs.
    private let modulus: [UInt32]
    /// -modulus⁻¹ mod 2³²
    private let inverse: UInt32
    /// R² mod modulus, with R = 2^(32 * limbs)
    private let rSquared: [UInt32]

    init(hex: String) {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(modulus: Self.limbs(fromBigEndian: bytes, count: (bytes.count + 3) / 4))
    }

    init(modulus: [UInt32]) {
        precondition(modulus[0] & 1 == 1, "Montgomery multiplication needs an odd modulus")
        self.modulus = modulus
        // Newton's iteration doubles the correct low bits each step: 1 → 2 → 4 → 8 → 16 → 32.
        var inverse: UInt32 = 1
        for _ in 0..<5 { inverse = inverse &* (2 &- modulus[0] &* inverse) }
        self.inverse = 0 &- inverse
        // R² mod m by doubling 1, 2 * 32 * limbs times.
        var value = [UInt32](repeating: 0, count: modulus.count)
        value[0] = 1
        for _ in 0..<(64 * modulus.count) {
            value = Self.addModulo(value, value, modulus)
        }
        self.rSquared = value
    }

    /// base ^ exponent mod modulus. `base` must be below the modulus; `exponent` is big-endian.
    func power(_ base: [UInt32], _ exponent: [UInt8]) -> [UInt32] {
        var one = [UInt32](repeating: 0, count: self.modulus.count)
        one[0] = 1
        let base = self.multiply(base, self.rSquared)
        var result = self.multiply(one, self.rSquared)
        for byte in exponent {
            for bit in (0..<8).reversed() {
                result = self.multiply(result, result)
                if byte >> bit & 1 == 1 { result = self.multiply(result, base) }
            }
        }
        return self.multiply(result, one)
    }

    /// Whether 2 ≤ value ≤ modulus - 2.
    func isValidPeerValue(_ value: [UInt32]) -> Bool {
        var two = [UInt32](repeating: 0, count: self.modulus.count)
        two[0] = 2
        var modulusMinusOne = self.modulus
        modulusMinusOne[0] -= 1  // The modulus is odd, so this never borrows.
        return Self.compare(value, two) >= 0 && Self.compare(value, modulusMinusOne) < 0
    }

    private func multiply(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let n = self.modulus.count
        var t = [UInt32](repeating: 0, count: n + 2)
        for i in 0..<n {
            var carry: UInt64 = 0
            for j in 0..<n {
                let sum = UInt64(t[j]) + UInt64(a[j]) * UInt64(b[i]) + carry
                t[j] = UInt32(truncatingIfNeeded: sum)
                carry = sum >> 32
            }
            var sum = UInt64(t[n]) + carry
            t[n] = UInt32(truncatingIfNeeded: sum)
            t[n + 1] = UInt32(sum >> 32)

            let m = t[0] &* self.inverse
            sum = UInt64(t[0]) + UInt64(m) * UInt64(self.modulus[0])
            carry = sum >> 32
            for j in 1..<n {
                sum = UInt64(t[j]) + UInt64(m) * UInt64(self.modulus[j]) + carry
                t[j - 1] = UInt32(truncatingIfNeeded: sum)
                carry = sum >> 32
            }
            sum = UInt64(t[n]) + carry
            t[n - 1] = UInt32(truncatingIfNeeded: sum)
            t[n] = t[n + 1] &+ UInt32(sum >> 32)
        }
        let result = Array(t[0..<n])
        if t[n] != 0 || Self.compare(result, self.modulus) >= 0 {
            return Self.subtract(result, self.modulus)
        }
        return result
    }

    private static func addModulo(_ a: [UInt32], _ b: [UInt32], _ modulus: [UInt32]) -> [UInt32] {
        var sum = [UInt32](repeating: 0, count: a.count)
        var carry: UInt64 = 0
        for i in 0..<a.count {
            let s = UInt64(a[i]) + UInt64(b[i]) + carry
            sum[i] = UInt32(truncatingIfNeeded: s)
            carry = s >> 32
        }
        if carry != 0 || compare(sum, modulus) >= 0 {
            return subtract(sum, modulus)
        }
        return sum
    }

    /// a - b, wrapping modulo R. Used where the true difference is below the modulus.
    private static func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var difference = [UInt32](repeating: 0, count: a.count)
        var borrow: UInt32 = 0
        for i in 0..<a.count {
            let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            difference[i] = d2
            borrow = (o1 || o2) ? 1 : 0
        }
        return difference
    }

    private static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        for i in (0..<a.count).reversed() where a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
        return 0
    }

    static func limbs(fromBigEndian bytes: [UInt8], count: Int) -> [UInt32] {
        var limbs = [UInt32](repeating: 0, count: count)
        for (offset, byte) in bytes.reversed().enumerated() where offset < count * 4 {
            limbs[offset / 4] |= UInt32(byte) << (8 * (offset % 4))
        }
        return limbs
    }

    static func bytes(_ limbs: [UInt32], count: Int) -> [UInt8] {
        (0..<count).reversed().map { offset in
            offset / 4 < limbs.count ? UInt8(truncatingIfNeeded: limbs[offset / 4] >> (8 * (offset % 4))) : 0
        }
    }
}
