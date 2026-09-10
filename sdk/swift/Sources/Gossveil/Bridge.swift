import Foundation
import GossveilKit

/// The seam to the core: statuses become thrown errors and library-owned
/// buffers become `Data` the library no longer holds.
enum Core {
    static func check(_ status: Int32) throws {
        if status != GV_OK.rawValue { throw GossveilError.of(status: status) }
    }

    static func cell() -> GvBuffer {
        GvBuffer(ptr: nil, len: 0)
    }

    /// Copies a buffer out and releases it, whatever the call's status was.
    static func take(_ cell: inout GvBuffer) -> Data {
        defer {
            gv_free(cell.ptr, cell.len)
            cell = GvBuffer(ptr: nil, len: 0)
        }
        guard let ptr = cell.ptr, cell.len > 0 else { return Data() }
        return Data(bytes: ptr, count: cell.len)
    }

    static func octets<Bytes: ContiguousBytes>(_ value: Bytes) -> [UInt8] {
        value.withUnsafeBytes { [UInt8]($0) }
    }

    /// The bytes of a fixed-size C array field, copied out of its struct.
    static func fixed<T>(_ value: T) -> [UInt8] {
        withUnsafeBytes(of: value) { [UInt8]($0) }
    }

    /// Pins every array for the duration of `body`, handing over base pointers.
    static func pinned<T>(_ arrays: [[UInt8]], _ body: ([UnsafePointer<UInt8>?]) throws -> T) throws -> T {
        func step(_ i: Int, _ pointers: [UnsafePointer<UInt8>?]) throws -> T {
            if i == arrays.count { return try body(pointers) }
            return try arrays[i].withUnsafeBufferPointer { try step(i + 1, pointers + [$0.baseAddress]) }
        }
        return try step(0, [])
    }
}

extension Data {
    var octets: [UInt8] { [UInt8](self) }
}

extension String {
    var octets: [UInt8] { Array(utf8) }
}

extension UUID {
    var data: Data {
        Data(Core.fixed(uuid))
    }

    init(bytes: [UInt8]) {
        precondition(bytes.count == 16)
        self.init(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

public enum Gossveil {
    public static var abiVersion: UInt32 { gv_abi_version() }
}
