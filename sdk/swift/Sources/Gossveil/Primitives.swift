import Foundation
import GossveilKit

public func hkdf<IkmBytes: ContiguousBytes, SaltBytes: ContiguousBytes, InfoBytes: ContiguousBytes>(outputLength: Int, inputKeyMaterial: IkmBytes, salt: SaltBytes, info: InfoBytes) throws -> Data {
    let material = Core.octets(inputKeyMaterial)
    let s = Core.octets(salt)
    let i = Core.octets(info)
    var out = Core.cell()
    try Core.check(gv_hkdf(material, material.count, s, s.count, s.isEmpty ? 0 : 1, i, i.count, UInt32(outputLength), &out))
    return Core.take(&out)
}

public func hkdf<IkmBytes: ContiguousBytes, InfoBytes: ContiguousBytes>(outputLength: Int, inputKeyMaterial: IkmBytes, info: InfoBytes) throws -> Data {
    try hkdf(outputLength: outputLength, inputKeyMaterial: inputKeyMaterial, salt: Data(), info: info)
}

public func randomBytes(_ count: Int) -> Data {
    var out = Core.cell()
    _ = gv_random(UInt32(count), &out)
    return Core.take(&out)
}

public struct Aes256GcmSiv: Sendable {
    private let key: [UInt8]

    public init<Bytes: ContiguousBytes>(key: Bytes) throws {
        let raw = Core.octets(key)
        guard raw.count == 32 else { throw GossveilError.invalidKey("key must be 32 bytes") }
        self.key = raw
    }

    public func encrypt<MessageBytes: ContiguousBytes, NonceBytes: ContiguousBytes, AdBytes: ContiguousBytes>(_ message: MessageBytes, nonce: NonceBytes, associatedData: AdBytes) throws -> Data {
        let m = Core.octets(message)
        let n = Core.octets(nonce)
        let ad = Core.octets(associatedData)
        var out = Core.cell()
        try Core.check(gv_siv_seal(key, key.count, n, n.count, m, m.count, ad, ad.count, &out))
        return Core.take(&out)
    }

    public func decrypt<MessageBytes: ContiguousBytes, NonceBytes: ContiguousBytes, AdBytes: ContiguousBytes>(_ message: MessageBytes, nonce: NonceBytes, associatedData: AdBytes) throws -> Data {
        let m = Core.octets(message)
        let n = Core.octets(nonce)
        let ad = Core.octets(associatedData)
        var out = Core.cell()
        try Core.check(gv_siv_open(key, key.count, n, n.count, m, m.count, ad, ad.count, &out))
        return Core.take(&out)
    }
}

/// Chunked authentication of a stream: one MAC per `chunkSize` bytes so a
/// download validates as it arrives.
public enum IncrementalMac {
    public static func calculate<KeyBytes: ContiguousBytes, DataBytes: ContiguousBytes>(key: KeyBytes, chunkSize: Int, data: DataBytes) throws -> Data {
        let k = Core.octets(key)
        let d = Core.octets(data)
        var out = Core.cell()
        try Core.check(gv_chunk_tags(k, k.count, UInt32(chunkSize), d, d.count, &out))
        return Core.take(&out)
    }

    public static func validate<KeyBytes: ContiguousBytes, DataBytes: ContiguousBytes, MacBytes: ContiguousBytes>(key: KeyBytes, chunkSize: Int, data: DataBytes, digest: MacBytes) throws {
        let k = Core.octets(key)
        let d = Core.octets(data)
        let tags = Core.octets(digest)
        try Core.check(gv_chunk_check(k, k.count, UInt32(chunkSize), d, d.count, tags, tags.count))
    }
}
