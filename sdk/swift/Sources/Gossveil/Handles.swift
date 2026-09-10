import Foundation
import GossveilKit

public struct Username: Sendable, Hashable, CustomStringConvertible {
    public let value: String
    public let hash: Data

    public init(_ username: String) throws {
        let raw = username.octets
        var digest = Core.cell()
        try Core.check(gv_handle_hash(raw, raw.count, &digest))
        value = username
        hash = Core.take(&digest)
    }

    public init(fromParts nickname: String, discriminator: String, withValidLengthWithin range: ClosedRange<Int32> = 3 ... 32) throws {
        let nick = nickname.octets
        let disc = discriminator.octets
        var text = Core.cell()
        var digest = Core.cell()
        try Core.check(gv_handle_from_parts(nick, nick.count, disc, disc.count, UInt32(range.lowerBound), UInt32(range.upperBound), &text, &digest))
        value = String(decoding: Core.take(&text), as: UTF8.self)
        hash = Core.take(&digest)
    }

    public init<Bytes: ContiguousBytes>(fromLink encrypted: Bytes, withRandomness entropy: Bytes) throws {
        let e = Core.octets(entropy)
        let sealed = Core.octets(encrypted)
        var text = Core.cell()
        try Core.check(gv_handle_link_open(e, e.count, sealed, sealed.count, &text))
        try self.init(String(decoding: Core.take(&text), as: UTF8.self))
    }

    public var description: String { value }

    public static func candidates(from nickname: String, withValidLengthWithin range: ClosedRange<Int32> = 3 ... 32) throws -> [Username] {
        let nick = nickname.octets
        var out = Core.cell()
        try Core.check(gv_handle_candidates(nick, nick.count, UInt32(range.lowerBound), UInt32(range.upperBound), &out))
        let joined = String(decoding: Core.take(&out), as: UTF8.self)
        return try joined.split(separator: "\n").map { try Username(String($0)) }
    }

    public func generateProof() throws -> Data {
        try generateProof(withRandomness: randomBytes(32))
    }

    public func generateProof<Bytes: ContiguousBytes>(withRandomness randomness: Bytes) throws -> Data {
        let raw = value.octets
        let r = Core.octets(randomness)
        var proof = Core.cell()
        try Core.check(gv_handle_proof(raw, raw.count, r, r.count, &proof))
        return Core.take(&proof)
    }

    public static func verify<ProofBytes: ContiguousBytes, HashBytes: ContiguousBytes>(proof: ProofBytes, forHash hash: HashBytes) throws {
        let p = Core.octets(proof)
        let h = Core.octets(hash)
        var ok: UInt8 = 0
        try Core.check(gv_handle_verify(p, p.count, h, h.count, &ok))
        guard ok == 1 else { throw GossveilError.verificationFailed("username proof does not match hash") }
    }

    public func createLink(previousEntropy: Data? = nil) throws -> (entropy: Data, encrypted: Data) {
        let raw = value.octets
        let previous = previousEntropy?.octets ?? []
        var entropy = Core.cell()
        var sealed = Core.cell()
        try Core.check(gv_handle_link(raw, raw.count, previous, previous.count, &entropy, &sealed))
        return (Core.take(&entropy), Core.take(&sealed))
    }
}
