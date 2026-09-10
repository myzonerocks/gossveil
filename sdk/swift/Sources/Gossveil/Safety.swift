import Foundation
import GossveilKit

public struct DisplayableFingerprint: Sendable {
    public let formatted: String
}

public struct ScannableFingerprint: Sendable {
    public let encoding: Data

    public func compare<Bytes: ContiguousBytes>(againstEncoding other: Bytes) throws -> Bool {
        let ours = encoding.octets
        let theirs = Core.octets(other)
        var ok: UInt8 = 0
        try Core.check(gv_safety_matches(ours, ours.count, theirs, theirs.count, &ok))
        return ok == 1
    }
}

public struct Fingerprint: Sendable {
    public let scannable: ScannableFingerprint
    public let displayable: DisplayableFingerprint
}

public struct NumericFingerprintGenerator: Sendable {
    private let iterations: UInt32

    public init(iterations: Int) {
        self.iterations = UInt32(iterations)
    }

    public func create<LocalBytes: ContiguousBytes, RemoteBytes: ContiguousBytes>(
        version: Int,
        localIdentifier: LocalBytes,
        localKey: PublicKey,
        remoteIdentifier: RemoteBytes,
        remoteKey: PublicKey
    ) throws -> Fingerprint {
        let local = Core.octets(localIdentifier)
        let remote = Core.octets(remoteIdentifier)
        var display = Core.cell()
        var scannable = Core.cell()
        try Core.check(gv_safety(UInt32(version), iterations, local, local.count, localKey.bytes, localKey.bytes.count, remote, remote.count, remoteKey.bytes, remoteKey.bytes.count, &display, &scannable))
        let formatted = String(decoding: Core.take(&display), as: UTF8.self)
        return Fingerprint(scannable: ScannableFingerprint(encoding: Core.take(&scannable)), displayable: DisplayableFingerprint(formatted: formatted))
    }
}
