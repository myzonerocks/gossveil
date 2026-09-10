package com.gossveil

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The one seam to the core. Every operation is a number; byte arrays and
 * integers go in and a length-prefixed run of outputs comes back. Errors
 * arrive as the typed exceptions in this package.
 */
object Native {
    init {
        System.loadLibrary("gossveil_jni")
    }

    @JvmStatic
    external fun call(op: Int, args: Array<ByteArray?>, nums: LongArray): ByteArray

    internal const val ABI_VERSION = 0
    internal const val CURVE_PAIR = 1
    internal const val CURVE_PUBLIC = 2
    internal const val CURVE_SIGN = 3
    internal const val CURVE_VERIFY = 4
    internal const val CURVE_AGREE = 5
    internal const val CURVE_CHECK = 6
    internal const val PQ_PAIR = 7
    internal const val PQ_ENCAPSULATE = 8
    internal const val PQ_OPEN = 9
    internal const val IDENTITY_PAIR = 10
    internal const val IDENTITY_SERIALIZE = 11
    internal const val IDENTITY_PARSE = 12
    internal const val IDENTITY_VOUCH = 13
    internal const val IDENTITY_VOUCHED = 14
    internal const val ONE_TIME_RECORD = 15
    internal const val ONE_TIME_PARSE = 16
    internal const val SIGNED_RECORD = 17
    internal const val SIGNED_PARSE = 18
    internal const val PQ_RECORD = 19
    internal const val PQ_RECORD_PARSE = 20
    internal const val SESSION_INFO = 21
    internal const val SESSION_SHELVE = 22
    internal const val SESSION_RATCHET_IS = 23
    internal const val SESSION_START = 24
    internal const val SESSION_SEAL = 25
    internal const val SESSION_OPEN = 26
    internal const val SESSION_OPEN_FIRST = 27
    internal const val OPENER_PARSE = 28
    internal const val WHISPER_PARSE = 29
    internal const val CIRCLE_ANNOUNCE = 30
    internal const val CIRCLE_ADMIT = 31
    internal const val ANNOUNCE_PARSE = 32
    internal const val CIRCLE_SEAL = 33
    internal const val CIRCLE_OPEN = 34
    internal const val NOTE_PARSE = 35
    internal const val SERVER_CERT = 36
    internal const val SERVER_CERT_PARSE = 37
    internal const val SERVER_CERT_CHECK = 38
    internal const val SENDER_CERT = 39
    internal const val SENDER_CERT_PARSE = 40
    internal const val SENDER_CERT_CHECK = 41
    internal const val CONTENT = 42
    internal const val CONTENT_PARSE = 43
    internal const val ENVELOPE_SEAL = 44
    internal const val ENVELOPE_OPEN = 45
    internal const val ENVELOPE_SEAL_MANY = 46
    internal const val ENVELOPE_FOR_SINGLE = 47
    internal const val ENVELOPE_FOR_RECIPIENT = 48
    internal const val SAFETY = 49
    internal const val SAFETY_MATCHES = 50
    internal const val HANDLE_HASH = 51
    internal const val HANDLE_PROOF = 52
    internal const val HANDLE_VERIFY = 53
    internal const val HANDLE_CANDIDATES = 54
    internal const val HANDLE_FROM_PARTS = 55
    internal const val HANDLE_LINK = 56
    internal const val HANDLE_LINK_OPEN = 57
    internal const val POOL_RANDOM = 58
    internal const val POOL_VALID = 59
    internal const val POOL_DERIVE = 60
    internal const val BACKUP_KEY_RANDOM = 61
    internal const val BACKUP_KEY_FOR_ACCOUNT = 62
    internal const val BACKUP_KEY_LOCAL_METADATA = 63
    internal const val BACKUP_KEY_MEDIA = 64
    internal const val BACKUP_KEY_MEDIA_KEYS = 65
    internal const val CIRCLE_MASTER_RANDOM = 66
    internal const val CIRCLE_SECRET_PARAMS = 67
    internal const val CIRCLE_PARAMS_INFO = 68
    internal const val HKDF = 69
    internal const val SIV_SEAL = 70
    internal const val SIV_OPEN = 71
    internal const val RANDOM = 72
    internal const val CHUNK_TAGS = 73
    internal const val CHUNK_CHECK = 74
    internal const val REPORT = 75
    internal const val REPORT_PARSE = 76
    internal const val REPORT_IN_BODY = 77
    internal const val PLAIN_FROM_REPORT = 78
    internal const val PLAIN_BODY = 79

    private val none = LongArray(0)

    /** Runs one operation and returns its outputs in order. */
    internal fun run(op: Int, args: Array<ByteArray?> = emptyArray(), nums: LongArray = none): Reply = Reply(call(op, args, nums))

    internal fun args(vararg values: ByteArray?): Array<ByteArray?> = arrayOf(*values)

    internal fun nums(vararg values: Long): LongArray = values
}

/** A reader over the outputs one call returns, in order. */
internal class Reply(private val raw: ByteArray) {
    private var at = 0

    fun bytes(): ByteArray {
        val len = ByteBuffer.wrap(raw, at, 4).order(ByteOrder.LITTLE_ENDIAN).int
        at += 4
        val out = raw.copyOfRange(at, at + len)
        at += len
        return out
    }

    fun flag(): Boolean = bytes()[0].toInt() == 1

    fun u8(): Int = bytes()[0].toInt() and 0xff

    fun u32(): Int = ByteBuffer.wrap(bytes()).order(ByteOrder.LITTLE_ENDIAN).int

    fun u64(): Long = ByteBuffer.wrap(bytes()).order(ByteOrder.LITTLE_ENDIAN).long

    fun fields(): Fields = Fields(bytes())

    fun string(): String = String(bytes(), Charsets.UTF_8)
}

/** A C struct returned by value: fields read at their natural offsets. */
internal class Fields(private val data: ByteArray) {
    private val view = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

    fun u8(offset: Int): Int = data[offset].toInt() and 0xff

    fun flag(offset: Int): Boolean = u8(offset) == 1

    fun u32(offset: Int): Int = view.getInt(offset)

    fun i64(offset: Int): Long = view.getLong(offset)

    fun bytes(offset: Int, len: Int): ByteArray = data.copyOfRange(offset, offset + len)
}

internal fun String.utf8(): ByteArray = toByteArray(Charsets.UTF_8)
