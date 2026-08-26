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
import Dispatch
import Foundation
import NIOCore
import XCTest

@testable import NIOSSH

private enum CustomAlgorithmTestError: Error {
    case malformedKey
    case malformedSignature
}

private struct TestCustomSignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "test-custom-key"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let bytes = buffer.readSSHString() else {
            throw CustomAlgorithmTestError.malformedSignature
        }
        return Self(rawRepresentation: Data(bytes.readableBytesView))
    }
}

private struct TestCustomPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "test-custom-key"

    let rawRepresentation: Data

    func isValidSignature<D: DataProtocol>(
        _ signature: any NIOSSHSignatureProtocol,
        for data: D
    ) -> Bool {
        guard let signature = signature as? TestCustomSignature else {
            return false
        }
        return signature.rawRepresentation == Data(data)
    }

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard let bytes = buffer.readSSHString() else {
            throw CustomAlgorithmTestError.malformedKey
        }
        return Self(rawRepresentation: Data(bytes.readableBytesView))
    }
}

private struct TestCustomPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = TestCustomPublicKey.publicKeyPrefix

    let rawRepresentation: Data

    var publicKey: any NIOSSHPublicKeyProtocol {
        TestCustomPublicKey(rawRepresentation: self.rawRepresentation)
    }

    func signature<D: DataProtocol>(for data: D) throws -> any NIOSSHSignatureProtocol {
        TestCustomSignature(rawRepresentation: Data(data))
    }
}

final class CustomAlgorithmTests: XCTestCase {
    func testConcurrentRegistrationIsIdempotent() {
        DispatchQueue.concurrentPerform(iterations: 100) { _ in
            NIOSSHAlgorithms.register(
                publicKey: TestCustomPublicKey.self,
                signature: TestCustomSignature.self
            )
        }

        let matchingPublicKeys = NIOSSHAlgorithms.registeredPublicKeys.filter {
            ObjectIdentifier($0) == ObjectIdentifier(TestCustomPublicKey.self)
        }
        let matchingSignatures = NIOSSHAlgorithms.registeredSignatures.filter {
            ObjectIdentifier($0) == ObjectIdentifier(TestCustomSignature.self)
        }

        XCTAssertEqual(matchingPublicKeys.count, 1)
        XCTAssertEqual(matchingSignatures.count, 1)
    }

    func testCustomKeyAndSignatureRoundTripThroughPublicNIOSSHAPI() throws {
        NIOSSHAlgorithms.register(
            publicKey: TestCustomPublicKey.self,
            signature: TestCustomSignature.self
        )

        let privateKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(rawRepresentation: Data([0x01, 0x23, 0x45, 0x67]))
        )
        let digest = SHA256.hash(data: Data("termy-custom-key-regression".utf8))

        var publicKeyBuffer = ByteBuffer()
        privateKey.publicKey.write(to: &publicKeyBuffer)
        let decodedPublicKey = try XCTUnwrap(publicKeyBuffer.readSSHHostKey())

        let signature = try privateKey.sign(digest: digest)
        var signatureBuffer = ByteBuffer()
        signatureBuffer.writeSSHSignature(signature)
        let decodedSignature = try XCTUnwrap(signatureBuffer.readSSHSignature())

        XCTAssertEqual(decodedPublicKey, privateKey.publicKey)
        XCTAssertTrue(decodedPublicKey.isValidSignature(decodedSignature, for: digest))
        XCTAssertEqual(publicKeyBuffer.readableBytes, 0)
        XCTAssertEqual(signatureBuffer.readableBytes, 0)
    }
}
