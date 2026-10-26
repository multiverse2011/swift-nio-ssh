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
import Foundation
import NIOCore
import NIOFoundationCompat
import XCTest

@testable import NIOSSH

/// Fixtures made with `ssh-keygen -t rsa -b 2048` and `openssl dgst -sha256|-sha512 -sign` over `message`.
final class RSAHostKeyTests: XCTestCase {
    private let openSSHKey =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7+qxudJx/Igi+uzxdpvYBHJOQNNjoXBbWuWK3GyOa6Ol7BjPpMc5Sry3g2xGRiySGuxAuEhn2Oora7QcOvSgfyD/qmOupLqJqYRfQPkKkrdjhplFrXzN86/oCGH73UY955PBsSMQt5XMxsJ5Ze/MBsE5iHLetzZYnPby6esSUWm/t2wnIV3AWYYWte0TQv7LeIITCG6+0HlVTebg2SobcU1r6FSuhcABPbBQCxJr19JNO/13Eg5RFaaqwG6j5c0GgctwNawmVhi+k+zrodqjpROrqkfhf7+vMgZTJLMHv4QOwlyLxHqNGMebLTfNVXKHPT3+gvcVAuynJBghtDVFf"
    private let message = ByteBuffer(string: "exchange hash stand-in")
    private let sha256Signature =
        "Ye1wlfnC0Tcym0322TNmHGWFpruxNiTiP/zNYPDJ5nCBAQqHtdr7uKxMli3HuZBEX+8Ozwe/gnvAWN48wtYCv5rI6INyH0RTfRxT+qzd2BZyMqI/daxm9k0lSYUjKUEaogW66UAkDf9nsP+WvbABbVf9PchlaiJ1HNmkg6XUv8fHLF0Jv3dPUoJsVqWLQPN2ZQ2a/gUCt4jcXegjEUH9iprqdPOnRqEF6ZYYcj23+zun4ipAECRl7amUXEMlVd0dzDwtmX0QiEDA/O4XroMrgJIOi2QaneNXRKhE/hmjBA/6z4qSo/4VDi7RHiQDw6YFtcBxwuQBNGmT1aREhVXWWA=="
    private let sha512Signature =
        "KTadRWDgyF+TMPIs75iC1zZFBGh3XYINExE5k1PvuxrJN0ZrY+HciLakp9dn6DKYaylUhO5D9crocpilPhBXdtQPzMuTY2cMp7NUHOI1sEiilWy2e/fEz+bT41kKEByzrckLkbUTyKZ8+h5dh3y9JwTYAkZ8S4q6KoeiJWPUCWVVbMysg6vp6TLgxDkJRzfO1Gf8T+606ZN6mz0sq75KWbdhHm3f2oCYQ/qWI94IrC+MYXKXYaCHqh+yWVd/Qp6XbDRiq+159LFoiLlb4HSYxFaeJqtnXX+ptOjF+uInm1yydowk2K8p8u0W/Ikf07y0YU9fhznp3BhgIFKIa/TLKg=="

    private func signature(_ algorithm: String, _ base64: String) throws -> NIOSSHSignature {
        var buffer = ByteBuffer()
        buffer.writeSSHString(algorithm.utf8)
        buffer.writeSSHString(Data(base64Encoded: base64)!)
        return try XCTUnwrap(buffer.readSSHSignature())
    }

    func testOpenSSHKeyRoundTripsByteForByte() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: self.openSSHKey)
        XCTAssertEqual(String(openSSHPublicKey: key), self.openSSHKey)
        XCTAssertEqual(key, try NIOSSHPublicKey(openSSHPublicKey: self.openSSHKey))
    }

    func testMatchesOnlyRSASHA2Algorithms() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: self.openSSHKey)
        XCTAssertTrue(key.matchesHostKeyAlgorithm("rsa-sha2-512"))
        XCTAssertTrue(key.matchesHostKeyAlgorithm("rsa-sha2-256"))
        XCTAssertFalse(key.matchesHostKeyAlgorithm("ssh-rsa"))
        XCTAssertFalse(key.matchesHostKeyAlgorithm("ssh-ed25519"))
    }

    func testVerifiesSHA2Signatures() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: self.openSSHKey)
        XCTAssertTrue(key.isValidSignature(try self.signature("rsa-sha2-256", self.sha256Signature), for: self.message))
        XCTAssertTrue(key.isValidSignature(try self.signature("rsa-sha2-512", self.sha512Signature), for: self.message))
    }

    func testRejectsWrongHashTamperedMessageAndSHA1() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: self.openSSHKey)
        // A SHA-256 signature labelled as SHA-512 must not verify.
        XCTAssertFalse(key.isValidSignature(try self.signature("rsa-sha2-512", self.sha256Signature), for: self.message))
        XCTAssertFalse(
            key.isValidSignature(try self.signature("rsa-sha2-256", self.sha256Signature), for: ByteBuffer(string: "x"))
        )
        // SHA-1 "ssh-rsa" signatures are not accepted at all.
        var buffer = ByteBuffer()
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString(Data(base64Encoded: self.sha256Signature)!)
        XCTAssertThrowsError(try buffer.readSSHSignature())
    }

    func testSignatureRoundTrips() throws {
        let signature = try self.signature("rsa-sha2-512", self.sha512Signature)
        var buffer = ByteBuffer()
        buffer.writeSSHSignature(signature)
        XCTAssertEqual(try buffer.readSSHSignature(), signature)
    }
}
