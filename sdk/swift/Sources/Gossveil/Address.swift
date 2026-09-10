import Foundation

public final class ProtocolAddress: Hashable, Sendable, CustomStringConvertible {
    public let name: String
    public let deviceId: UInt32

    public init(name: String, deviceId: UInt32) throws {
        guard !name.isEmpty else { throw GossveilError.invalidProtocolAddress(name: name, deviceId: deviceId, message: "empty name") }
        guard deviceId != 0 else { throw GossveilError.invalidProtocolAddress(name: name, deviceId: deviceId, message: "device id must not be zero") }
        self.name = name
        self.deviceId = deviceId
    }

    public convenience init(_ serviceId: ServiceId, deviceId: UInt32) {
        try! self.init(name: serviceId.serviceIdString, deviceId: deviceId)
    }

    public var serviceId: ServiceId? {
        try? ServiceId.parseFrom(serviceIdString: name)
    }

    public var description: String {
        "\(name).\(deviceId)"
    }

    public static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        lhs.name == rhs.name && lhs.deviceId == rhs.deviceId
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(name)
        hasher.combine(deviceId)
    }
}

public enum ServiceIdKind: UInt8, Sendable {
    case aci = 0
    case pni = 1
}

/// An account identifier: a UUID typed as an ACI or a PNI, in the three
/// encodings the protocol uses.
public struct ServiceId: Hashable, Sendable, CustomStringConvertible {
    public let kind: ServiceIdKind
    public let rawUUID: UUID

    public init(kind: ServiceIdKind, uuid: UUID) {
        self.kind = kind
        rawUUID = uuid
    }

    public var serviceIdString: String {
        let text = rawUUID.uuidString.lowercased()
        return kind == .pni ? "PNI:" + text : text
    }

    public var description: String { serviceIdString }

    public var serviceIdBinary: Data {
        kind == .pni ? Data([1]) + rawUUID.data : rawUUID.data
    }

    public var serviceIdFixedWidthBinary: Data {
        Data([kind.rawValue]) + rawUUID.data
    }

    public static func parseFrom(serviceIdString string: String) throws -> ServiceId {
        let pni = string.hasPrefix("PNI:")
        guard let uuid = UUID(uuidString: pni ? String(string.dropFirst(4)) : string) else { throw GossveilError.invalidArgument("bad service id") }
        return ServiceId(kind: pni ? .pni : .aci, uuid: uuid)
    }

    public static func parseFrom<Bytes: ContiguousBytes>(serviceIdFixedWidthBinary bytes: Bytes) throws -> ServiceId {
        let raw = Core.octets(bytes)
        guard raw.count == 17, let kind = ServiceIdKind(rawValue: raw[0]) else { throw GossveilError.invalidArgument("bad service id") }
        return ServiceId(kind: kind, uuid: UUID(bytes: Array(raw[1...])))
    }

    public static func parseFrom<Bytes: ContiguousBytes>(serviceIdBinary bytes: Bytes) throws -> ServiceId {
        let raw = Core.octets(bytes)
        if raw.count == 16 { return ServiceId(kind: .aci, uuid: UUID(bytes: raw)) }
        guard raw.count == 17, raw[0] == 1 else { throw GossveilError.invalidArgument("bad service id") }
        return ServiceId(kind: .pni, uuid: UUID(bytes: Array(raw[1...])))
    }
}

public struct Aci: Hashable, Sendable {
    public let rawUUID: UUID

    public init(fromUUID uuid: UUID) {
        rawUUID = uuid
    }

    public var serviceId: ServiceId { ServiceId(kind: .aci, uuid: rawUUID) }
    public var serviceIdString: String { serviceId.serviceIdString }
}

public struct Pni: Hashable, Sendable {
    public let rawUUID: UUID

    public init(fromUUID uuid: UUID) {
        rawUUID = uuid
    }

    public var serviceId: ServiceId { ServiceId(kind: .pni, uuid: rawUUID) }
    public var serviceIdString: String { serviceId.serviceIdString }
}
