//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A signature implementation supplied by an application embedding NIOSSH.
///
/// Implementations may bridge keys whose private material cannot be represented by
/// Swift Crypto, such as SSH-agent, Secure Enclave, PIV, or FIDO authenticators.
public protocol NIOSSHSignatureProtocol: _NIOSSHSendableMetatype {
    static var signaturePrefix: String { get }

    var rawRepresentation: Data { get }

    func write(to buffer: inout ByteBuffer) -> Int

    static func read(from buffer: inout ByteBuffer) throws -> Self
}

extension NIOSSHSignatureProtocol {
    internal var signaturePrefix: String {
        Self.signaturePrefix
    }
}

/// A public-key implementation supplied by an application embedding NIOSSH.
public protocol NIOSSHPublicKeyProtocol: _NIOSSHSendableMetatype {
    static var publicKeyPrefix: String { get }

    var rawRepresentation: Data { get }

    func isValidSignature<D: DataProtocol>(_ signature: any NIOSSHSignatureProtocol, for data: D) -> Bool

    func write(to buffer: inout ByteBuffer) -> Int

    static func read(from buffer: inout ByteBuffer) throws -> Self
}

extension NIOSSHPublicKeyProtocol {
    internal var publicKeyPrefix: String {
        Self.publicKeyPrefix
    }
}

/// A private-key implementation supplied by an application embedding NIOSSH.
public protocol NIOSSHPrivateKeyProtocol: _NIOSSHSendableMetatype {
    static var keyPrefix: String { get }

    var publicKey: any NIOSSHPublicKeyProtocol { get }

    func signature<D: DataProtocol>(for data: D) throws -> any NIOSSHSignatureProtocol
}

extension NIOSSHPrivateKeyProtocol {
    internal var keyPrefix: String {
        Self.keyPrefix
    }
}
