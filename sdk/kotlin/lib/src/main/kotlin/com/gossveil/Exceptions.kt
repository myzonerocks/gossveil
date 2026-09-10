package com.gossveil

open class InvalidKeyException @JvmOverloads constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

class InvalidKeyIdException(message: String? = null) : Exception(message)

class InvalidMessageException @JvmOverloads constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

class InvalidVersionException(message: String? = null) : Exception(message)

class LegacyMessageException(message: String? = null) : Exception(message)

class DuplicateMessageException(message: String? = null) : Exception(message)

class NoSessionException(message: String? = null) : Exception(message) {
    constructor(address: ProtocolAddress, message: String?) : this("$message: $address")
}

class UntrustedIdentityException(message: String? = null) : Exception(message) {
    var name: String? = null
        private set
    var untrustedIdentity: IdentityKey? = null
        private set

    constructor(name: String, identity: IdentityKey?) : this("untrusted identity for $name") {
        this.name = name
        this.untrustedIdentity = identity
    }
}

class VerificationFailedException(message: String? = null) : Exception(message)

class InvalidRegistrationIdException(val address: ProtocolAddress, message: String?) : Exception(message)

class SelfSendException(message: String? = null) : Exception(message)
