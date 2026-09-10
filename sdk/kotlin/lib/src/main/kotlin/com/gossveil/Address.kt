package com.gossveil

import java.nio.ByteBuffer
import java.util.UUID

class ProtocolAddress(val name: String, val deviceId: Int) {
    init {
        require(name.isNotEmpty()) { "empty address name" }
    }

    constructor(serviceId: ServiceId, deviceId: Int) : this(serviceId.toServiceIdString(), deviceId)

    val serviceId: ServiceId? get() = runCatching { ServiceId.parseFromString(name) }.getOrNull()

    override fun toString(): String = "$name.$deviceId"

    override fun equals(other: Any?): Boolean = other is ProtocolAddress && name == other.name && deviceId == other.deviceId

    override fun hashCode(): Int = name.hashCode() * 31 + deviceId
}

/** An account identifier: a UUID typed as an ACI or a PNI, in the three encodings the protocol uses. */
sealed class ServiceId(val kind: Kind, val rawUUID: UUID) {
    enum class Kind(val code: Int) { ACI(0), PNI(1) }

    class Aci(uuid: UUID) : ServiceId(Kind.ACI, uuid) {
        companion object {
            @JvmStatic
            fun parseFromString(value: String): Aci = ServiceId.parseFromString(value) as? Aci ?: throw IllegalArgumentException("not an ACI")
        }
    }

    class Pni(uuid: UUID) : ServiceId(Kind.PNI, uuid) {
        companion object {
            @JvmStatic
            fun parseFromString(value: String): Pni = ServiceId.parseFromString(value) as? Pni ?: throw IllegalArgumentException("not a PNI")
        }
    }

    fun toServiceIdString(): String = when (kind) {
        Kind.ACI -> rawUUID.toString()
        Kind.PNI -> "PNI:$rawUUID"
    }

    fun toServiceIdBinary(): ByteArray = when (kind) {
        Kind.ACI -> uuidBytes(rawUUID)
        Kind.PNI -> byteArrayOf(1) + uuidBytes(rawUUID)
    }

    fun toServiceIdFixedWidthBinary(): ByteArray = byteArrayOf(kind.code.toByte()) + uuidBytes(rawUUID)

    override fun toString(): String = toServiceIdString()

    override fun equals(other: Any?): Boolean = other is ServiceId && kind == other.kind && rawUUID == other.rawUUID

    override fun hashCode(): Int = rawUUID.hashCode() * 31 + kind.code

    companion object {
        @JvmStatic
        fun parseFromString(value: String): ServiceId =
            if (value.startsWith("PNI:")) Pni(UUID.fromString(value.substring(4))) else Aci(UUID.fromString(value))

        @JvmStatic
        fun parseFromFixedWidthBinary(bytes: ByteArray): ServiceId {
            require(bytes.size == 17) { "a fixed-width service id is 17 bytes" }
            val uuid = uuidOf(bytes.copyOfRange(1, 17))
            return when (bytes[0].toInt()) {
                0 -> Aci(uuid)
                1 -> Pni(uuid)
                else -> throw IllegalArgumentException("unknown service id kind")
            }
        }

        @JvmStatic
        fun parseFromBinary(bytes: ByteArray): ServiceId = when {
            bytes.size == 16 -> Aci(uuidOf(bytes))
            bytes.size == 17 && bytes[0].toInt() == 1 -> Pni(uuidOf(bytes.copyOfRange(1, 17)))
            else -> throw IllegalArgumentException("bad service id")
        }

        internal fun uuidBytes(uuid: UUID): ByteArray =
            ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()

        internal fun uuidOf(bytes: ByteArray): UUID {
            val view = ByteBuffer.wrap(bytes)
            return UUID(view.long, view.long)
        }
    }
}
