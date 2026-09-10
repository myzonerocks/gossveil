import Foundation
import GossveilKit

public enum AccountEntropyPool {
    public static func generate() -> String {
        var out = Core.cell()
        _ = gv_pool_random(&out)
        return String(decoding: Core.take(&out), as: UTF8.self)
    }

    public static func isValid(_ pool: String) -> Bool {
        let raw = pool.octets
        return gv_pool_valid(raw, raw.count) == 1
    }

    public static func deriveSvrKey(_ pool: String) throws -> Data {
        try derive(pool).recovery
    }

    public static func deriveBackupKey(_ pool: String) throws -> BackupKey {
        try BackupKey(contents: derive(pool).backup)
    }

    private static func derive(_ pool: String) throws -> (recovery: Data, backup: Data) {
        let raw = pool.octets
        var recovery = Core.cell()
        var backup = Core.cell()
        try Core.check(gv_pool_derive(raw, raw.count, &recovery, &backup))
        return (Core.take(&recovery), Core.take(&backup))
    }
}

public struct BackupKey: Sendable, Hashable {
    public static let size = 32
    public let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(contents: Bytes) throws {
        let raw = Core.octets(contents)
        guard raw.count == Self.size else { throw GossveilError.invalidArgument("backup key must be 32 bytes") }
        bytes = raw
    }

    public static func generateRandom() -> BackupKey {
        var out = Core.cell()
        _ = gv_backup_key_random(&out)
        return try! BackupKey(contents: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }

    public func deriveBackupId(aci: Aci) -> Data {
        forAccount(aci).id
    }

    public func deriveEcKey(aci: Aci) -> PrivateKey {
        PrivateKey(unchecked: forAccount(aci).signing.octets)
    }

    private func forAccount(_ aci: Aci) -> (id: Data, signing: Data) {
        let account = aci.serviceIdString.octets
        var id = Core.cell()
        var signing = Core.cell()
        _ = gv_backup_key_for_account(bytes, bytes.count, account, account.count, &id, &signing)
        return (Core.take(&id), Core.take(&signing))
    }

    public func deriveLocalBackupMetadataKey() -> Data {
        var out = Core.cell()
        _ = gv_backup_key_local_metadata(bytes, bytes.count, &out)
        return Core.take(&out)
    }

    public func deriveMediaId(mediaName: String) -> Data {
        let name = mediaName.octets
        var id = Core.cell()
        var key = Core.cell()
        var thumbnail = Core.cell()
        _ = gv_backup_key_media(bytes, bytes.count, name, name.count, &id, &key, &thumbnail)
        _ = Core.take(&key)
        _ = Core.take(&thumbnail)
        return Core.take(&id)
    }

    public func deriveMediaEncryptionKey<Bytes: ContiguousBytes>(mediaId: Bytes) throws -> Data {
        try mediaKeys(mediaId).media
    }

    public func deriveThumbnailTransitEncryptionKey<Bytes: ContiguousBytes>(mediaId: Bytes) throws -> Data {
        try mediaKeys(mediaId).thumbnail
    }

    private func mediaKeys<Bytes: ContiguousBytes>(_ mediaId: Bytes) throws -> (media: Data, thumbnail: Data) {
        let id = Core.octets(mediaId)
        var media = Core.cell()
        var thumbnail = Core.cell()
        try Core.check(gv_backup_key_media_keys(bytes, bytes.count, id, id.count, &media, &thumbnail))
        return (Core.take(&media), Core.take(&thumbnail))
    }
}

public struct GroupMasterKey: Sendable, Hashable {
    public static let size = 32
    public let bytes: [UInt8]

    public init<Bytes: ContiguousBytes>(contents: Bytes) throws {
        let raw = Core.octets(contents)
        guard raw.count == Self.size else { throw GossveilError.invalidArgument("group master key must be 32 bytes") }
        bytes = raw
    }

    public static func generate() -> GroupMasterKey {
        var out = Core.cell()
        _ = gv_circle_master_random(&out)
        return try! GroupMasterKey(contents: Core.take(&out))
    }

    public func serialize() -> Data { Data(bytes) }
}

public struct GroupSecretParams: Sendable, Hashable {
    public let bytes: [UInt8]
    public let masterKey: GroupMasterKey
    public let groupIdentifier: Data
    public let publicParams: Data

    public init<Bytes: ContiguousBytes>(contents: Bytes) throws {
        let raw = Core.octets(contents)
        var master = Core.cell()
        var identifier = Core.cell()
        var publicCell = Core.cell()
        try Core.check(gv_circle_params_info(raw, raw.count, &master, &identifier, &publicCell))
        bytes = raw
        masterKey = try GroupMasterKey(contents: Core.take(&master))
        groupIdentifier = Core.take(&identifier)
        publicParams = Core.take(&publicCell)
    }

    public static func derive(from masterKey: GroupMasterKey) throws -> GroupSecretParams {
        var out = Core.cell()
        try Core.check(gv_circle_secret_params(masterKey.bytes, masterKey.bytes.count, &out))
        return try GroupSecretParams(contents: Core.take(&out))
    }

    public static func generate() throws -> GroupSecretParams {
        try derive(from: GroupMasterKey.generate())
    }

    public func serialize() -> Data { Data(bytes) }
}
