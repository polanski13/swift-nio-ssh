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

import NIOConcurrencyHelpers

/// Registers application-defined algorithms that NIOSSH must be able to parse from the wire.
///
/// Key-exchange and transport algorithms should additionally be placed on the relevant client or
/// server configuration. The registry is synchronized because several independent SSH clients may
/// be configured concurrently in one process.
public enum NIOSSHAlgorithms {
    public static func register(keyExchangeAlgorithm type: any NIOSSHKeyExchangeAlgorithmProtocol.Type) {
        _NIOSSHAlgorithmRegistry.shared.register(keyExchangeAlgorithm: type)
    }

    public static func register(transportProtectionScheme type: any NIOSSHTransportProtection.Type) {
        _NIOSSHAlgorithmRegistry.shared.register(transportProtectionScheme: type)
    }

    public static func register<PublicKey: NIOSSHPublicKeyProtocol, Signature: NIOSSHSignatureProtocol>(
        publicKey type: PublicKey.Type,
        signature: Signature.Type
    ) {
        _NIOSSHAlgorithmRegistry.shared.register(publicKey: type, signature: signature)
    }

    internal static var registeredKeyExchangeAlgorithms: [any NIOSSHKeyExchangeAlgorithmProtocol.Type] {
        _NIOSSHAlgorithmRegistry.shared.snapshot().keyExchangeAlgorithms
    }

    internal static var registeredTransportProtectionSchemes: [any NIOSSHTransportProtection.Type] {
        _NIOSSHAlgorithmRegistry.shared.snapshot().transportProtectionSchemes
    }

    internal static var registeredPublicKeys: [any NIOSSHPublicKeyProtocol.Type] {
        _NIOSSHAlgorithmRegistry.shared.snapshot().publicKeys
    }

    internal static var registeredSignatures: [any NIOSSHSignatureProtocol.Type] {
        _NIOSSHAlgorithmRegistry.shared.snapshot().signatures
    }

    /// Clears application algorithms. This is intentionally internal and used by the test target.
    internal static func unregisterAlgorithms() {
        _NIOSSHAlgorithmRegistry.shared.removeAll()
    }
}

private final class _NIOSSHAlgorithmRegistry: @unchecked Sendable {
    struct Snapshot {
        var keyExchangeAlgorithms: [any NIOSSHKeyExchangeAlgorithmProtocol.Type]
        var transportProtectionSchemes: [any NIOSSHTransportProtection.Type]
        var publicKeys: [any NIOSSHPublicKeyProtocol.Type]
        var signatures: [any NIOSSHSignatureProtocol.Type]
    }

    static let shared = _NIOSSHAlgorithmRegistry()

    private let lock = NIOLock()
    private var keyExchangeAlgorithms: [any NIOSSHKeyExchangeAlgorithmProtocol.Type] = []
    private var transportProtectionSchemes: [any NIOSSHTransportProtection.Type] = []
    private var publicKeys: [any NIOSSHPublicKeyProtocol.Type] = []
    private var signatures: [any NIOSSHSignatureProtocol.Type] = []

    func register(keyExchangeAlgorithm type: any NIOSSHKeyExchangeAlgorithmProtocol.Type) {
        self.lock.withLock {
            guard !self.keyExchangeAlgorithms.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) else {
                return
            }
            self.keyExchangeAlgorithms.append(type)
        }
    }

    func register(transportProtectionScheme type: any NIOSSHTransportProtection.Type) {
        self.lock.withLock {
            guard !self.transportProtectionSchemes.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) })
            else {
                return
            }
            self.transportProtectionSchemes.append(type)
        }
    }

    func register<PublicKey: NIOSSHPublicKeyProtocol, Signature: NIOSSHSignatureProtocol>(
        publicKey type: PublicKey.Type,
        signature: Signature.Type
    ) {
        self.lock.withLock {
            guard !self.publicKeys.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) else {
                return
            }
            self.publicKeys.append(type)
            self.signatures.append(signature)
        }
    }

    func snapshot() -> Snapshot {
        self.lock.withLock {
            Snapshot(
                keyExchangeAlgorithms: self.keyExchangeAlgorithms,
                transportProtectionSchemes: self.transportProtectionSchemes,
                publicKeys: self.publicKeys,
                signatures: self.signatures
            )
        }
    }

    func removeAll() {
        self.lock.withLock {
            self.keyExchangeAlgorithms.removeAll(keepingCapacity: false)
            self.transportProtectionSchemes.removeAll(keepingCapacity: false)
            self.publicKeys.removeAll(keepingCapacity: false)
            self.signatures.removeAll(keepingCapacity: false)
        }
    }
}
