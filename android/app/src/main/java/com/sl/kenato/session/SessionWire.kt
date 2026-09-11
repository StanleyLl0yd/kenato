package com.sl.kenato.session

import com.sl.kenato.contact.CONTACT_ID_BYTES
import com.sl.kenato.contact.MAX_CONTACT_ONE_TIME_PREKEYS
import com.sl.kenato.contact.MAX_CONTACT_PUBLIC_KEY_BYTES
import com.sl.kenato.contact.MAX_CONTACT_SIGNATURE_BYTES
import com.sl.kenato.contact.M2OneTimePreKey
import com.sl.kenato.contact.M2PublicIdentityBundle
import com.sl.kenato.contact.M2SignedPreKey
import com.sl.kenato.contact.validateBundleShape
import java.io.ByteArrayOutputStream

internal const val SESSION_MAX_WIRE_BYTES = 128 * 1024
internal const val SESSION_MAX_BUNDLE_BYTES = 64 * 1024

internal data class SessionPublishWireResponse(
    val acceptedAccountGeneration: Long,
    val acceptedPublicationRevision: Long,
)

internal data class SessionReserveWireResponse(
    val creatorBundle: SessionBootstrapBundle,
    val creatorOneTimePreKey: SessionOneTimePreKey,
)

internal data class SessionClaimWireResponse(
    val redeemerIdentityBundle: M2PublicIdentityBundle,
    val redemptionSignature: ByteArray,
    val redeemedAtEpochSeconds: Long,
    val redeemerSessionBundle: SessionBootstrapBundle,
    val creatorOneTimePreKey: SessionOneTimePreKey,
    val creatorAccountGeneration: Long,
    val olmMessageType: Int,
    val olmMessage: ByteArray,
    val submitSignature: ByteArray,
)

internal object SessionWire {
    fun encodePublishBootstrapRequest(bundle: SessionBootstrapBundle): ByteArray {
        SessionCanonical.validateBootstrap(bundle, requireSignature = true)
        return message {
            uint(1, SESSION_PROTOCOL_VERSION.toLong())
            bytes(2, encodeBootstrapBundle(bundle))
        }
    }

    fun decodePublishBootstrapResponse(data: ByteArray): SessionPublishWireResponse {
        val reader = Reader(data)
        var version: Long? = null
        var generation: Long? = null
        var revision: Long? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "protocol version")
                2 -> generation = unique(generation, reader.readUInt(wireType), "account generation")
                3 -> revision = unique(revision, reader.readUInt(wireType), "publication revision")
                else -> reader.skip(wireType)
            }
        }
        requireVersion(version)
        val acceptedGeneration = generation ?: malformed("accepted account generation is missing")
        val acceptedRevision = revision ?: malformed("accepted publication revision is missing")
        requirePositive(acceptedGeneration, "accepted account generation")
        requirePositive(acceptedRevision, "accepted publication revision")
        return SessionPublishWireResponse(acceptedGeneration, acceptedRevision)
    }

    fun encodeReserveBootstrapRequest(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
        reserveSignature: ByteArray,
    ): ByteArray {
        SessionCanonical.reservePayload(creatorIdentityId, redeemerIdentityId, inviteToken)
        requireSignature(reserveSignature, "reserve signature")
        return message {
            uint(1, SESSION_PROTOCOL_VERSION.toLong())
            bytes(2, creatorIdentityId)
            bytes(3, redeemerIdentityId)
            bytes(4, inviteToken)
            bytes(5, reserveSignature)
        }
    }

    fun decodeReserveBootstrapResponse(data: ByteArray): SessionReserveWireResponse {
        val reader = Reader(data)
        var version: Long? = null
        var creatorBundle: SessionBootstrapBundle? = null
        var creatorKey: SessionOneTimePreKey? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "protocol version")
                2 -> creatorBundle = unique(
                    creatorBundle,
                    decodeBootstrapBundle(reader.readBytes(wireType, SESSION_MAX_BUNDLE_BYTES)),
                    "creator session bundle",
                )
                3 -> creatorKey = unique(
                    creatorKey,
                    decodeOneTimePreKey(reader.readBytes(wireType, 128)),
                    "creator one-time key",
                )
                else -> reader.skip(wireType)
            }
        }
        requireVersion(version)
        val bundle = creatorBundle ?: malformed("creator session bundle is missing")
        val key = creatorKey ?: malformed("creator one-time key is missing")
        if (bundle.oneTimePreKeys.none { it.id == key.id && it.publicKey.contentEquals(key.publicKey) }) {
            malformed("reserved creator one-time key is not in the authenticated bundle")
        }
        return SessionReserveWireResponse(bundle, key)
    }

    fun encodeSubmitInitRequest(request: SessionSubmitInit): ByteArray {
        SessionCanonical.validateSubmit(request, requireSignature = true)
        return message {
            uint(1, SESSION_PROTOCOL_VERSION.toLong())
            bytes(2, request.creatorIdentityId)
            bytes(3, request.redeemerIdentityId)
            bytes(4, request.inviteToken)
            uint(5, request.creatorAccountGeneration)
            uint(6, request.creatorOneTimePreKeyId)
            uint(7, request.redeemerAccountGeneration)
            uint(8, request.olmMessageType.toLong())
            bytes(9, request.olmMessage)
            bytes(10, request.submitSignature)
        }
    }

    fun decodeSubmitInitResponse(data: ByteArray) {
        val reader = Reader(data)
        var version: Long? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "protocol version")
                else -> reader.skip(wireType)
            }
        }
        requireVersion(version)
    }

    fun encodeClaimInitRequest(
        creatorIdentityId: ByteArray,
        inviteToken: ByteArray,
        claimSignature: ByteArray,
    ): ByteArray {
        SessionCanonical.claimPayload(creatorIdentityId, inviteToken)
        requireSignature(claimSignature, "claim signature")
        return message {
            uint(1, SESSION_PROTOCOL_VERSION.toLong())
            bytes(2, creatorIdentityId)
            bytes(3, inviteToken)
            bytes(4, claimSignature)
        }
    }

    fun decodeClaimInitResponse(data: ByteArray): SessionClaimWireResponse {
        val reader = Reader(data)
        var version: Long? = null
        var redeemerIdentity: M2PublicIdentityBundle? = null
        var redemptionSignature: ByteArray? = null
        var redeemedAt: Long? = null
        var redeemerSession: SessionBootstrapBundle? = null
        var creatorKey: SessionOneTimePreKey? = null
        var creatorGeneration: Long? = null
        var messageType: Long? = null
        var olmMessage: ByteArray? = null
        var submitSignature: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "protocol version")
                2 -> redeemerIdentity = unique(
                    redeemerIdentity,
                    decodeIdentityBundle(reader.readBytes(wireType, SESSION_MAX_BUNDLE_BYTES)),
                    "redeemer identity bundle",
                )
                3 -> redemptionSignature = unique(
                    redemptionSignature,
                    reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES),
                    "redemption signature",
                )
                4 -> redeemedAt = unique(redeemedAt, reader.readUInt(wireType), "redemption timestamp")
                5 -> redeemerSession = unique(
                    redeemerSession,
                    decodeBootstrapBundle(reader.readBytes(wireType, SESSION_MAX_BUNDLE_BYTES)),
                    "redeemer session bundle",
                )
                6 -> creatorKey = unique(
                    creatorKey,
                    decodeOneTimePreKey(reader.readBytes(wireType, 128)),
                    "creator one-time key",
                )
                7 -> creatorGeneration = unique(
                    creatorGeneration,
                    reader.readUInt(wireType),
                    "creator account generation",
                )
                8 -> messageType = unique(messageType, reader.readUInt(wireType), "Olm message type")
                9 -> olmMessage = unique(
                    olmMessage,
                    reader.readBytes(wireType, SESSION_MAX_OLM_MESSAGE_BYTES),
                    "Olm message",
                )
                10 -> submitSignature = unique(
                    submitSignature,
                    reader.readBytes(wireType, SESSION_MAX_SIGNATURE_BYTES),
                    "submit signature",
                )
                else -> reader.skip(wireType)
            }
        }
        requireVersion(version)
        val identity = redeemerIdentity ?: malformed("redeemer identity bundle is missing")
        val redemption = redemptionSignature ?: malformed("redemption signature is missing")
        val timestamp = redeemedAt ?: malformed("redemption timestamp is missing")
        val session = redeemerSession ?: malformed("redeemer session bundle is missing")
        val key = creatorKey ?: malformed("creator one-time key is missing")
        val generation = creatorGeneration ?: malformed("creator account generation is missing")
        val type = messageType ?: malformed("Olm message type is missing")
        val message = olmMessage ?: malformed("Olm message is missing")
        val submit = submitSignature ?: malformed("submit signature is missing")
        requireSignature(redemption, "redemption signature")
        requireSignature(submit, "submit signature")
        requirePositive(generation, "creator account generation")
        if (timestamp < 0 || type != SESSION_OLM_MESSAGE_PRE_KEY.toLong() || message.isEmpty()) {
            malformed("claimed M3 initialization metadata is invalid")
        }
        return SessionClaimWireResponse(
            identity,
            redemption,
            timestamp,
            session,
            key,
            generation,
            type.toInt(),
            message,
            submit,
        )
    }

    fun encodeBootstrapBundle(bundle: SessionBootstrapBundle): ByteArray {
        SessionCanonical.validateBootstrap(bundle, requireSignature = true)
        return message(SESSION_MAX_BUNDLE_BYTES) {
            bytes(1, bundle.identityId)
            uint(2, bundle.accountGeneration)
            uint(3, bundle.publicationRevision)
            bytes(4, bundle.olmEd25519IdentityKey)
            bytes(5, bundle.olmCurve25519IdentityKey)
            bundle.oneTimePreKeys.forEach { key -> bytes(6, encodeOneTimePreKey(key)) }
            bytes(7, bundle.bindingSignature)
        }
    }

    fun decodeBootstrapBundle(data: ByteArray): SessionBootstrapBundle {
        if (data.isEmpty() || data.size > SESSION_MAX_BUNDLE_BYTES) malformed("session bundle size is invalid")
        val reader = Reader(data, SESSION_MAX_BUNDLE_BYTES)
        var identityId: ByteArray? = null
        var generation: Long? = null
        var revision: Long? = null
        var ed25519: ByteArray? = null
        var curve25519: ByteArray? = null
        val oneTimeKeys = ArrayList<SessionOneTimePreKey>()
        var signature: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> identityId = unique(identityId, reader.readBytes(wireType, SESSION_IDENTITY_BYTES), "identity id")
                2 -> generation = unique(generation, reader.readUInt(wireType), "account generation")
                3 -> revision = unique(revision, reader.readUInt(wireType), "publication revision")
                4 -> ed25519 = unique(ed25519, reader.readBytes(wireType, SESSION_OLM_PUBLIC_KEY_BYTES), "Ed25519 key")
                5 -> curve25519 = unique(curve25519, reader.readBytes(wireType, SESSION_OLM_PUBLIC_KEY_BYTES), "Curve25519 key")
                6 -> {
                    if (oneTimeKeys.size >= SESSION_MAX_ONE_TIME_KEYS) malformed("too many session one-time keys")
                    oneTimeKeys += decodeOneTimePreKey(reader.readBytes(wireType, 128))
                }
                7 -> signature = unique(
                    signature,
                    reader.readBytes(wireType, SESSION_MAX_SIGNATURE_BYTES),
                    "binding signature",
                )
                else -> reader.skip(wireType)
            }
        }
        val bundle = SessionBootstrapBundle(
            identityId = identityId ?: malformed("session identity id is missing"),
            accountGeneration = generation ?: malformed("session account generation is missing"),
            publicationRevision = revision ?: malformed("session publication revision is missing"),
            olmEd25519IdentityKey = ed25519 ?: malformed("session Ed25519 identity key is missing"),
            olmCurve25519IdentityKey = curve25519 ?: malformed("session Curve25519 identity key is missing"),
            oneTimePreKeys = oneTimeKeys,
            bindingSignature = signature ?: malformed("session binding signature is missing"),
        )
        SessionCanonical.validateBootstrap(bundle, requireSignature = true)
        return bundle
    }

    private fun encodeOneTimePreKey(key: SessionOneTimePreKey): ByteArray = message(128) {
        if (key.id <= 0 || key.publicKey.size != SESSION_OLM_PUBLIC_KEY_BYTES) {
            malformed("session one-time key is invalid")
        }
        uint(1, key.id)
        bytes(2, key.publicKey)
    }

    private fun decodeOneTimePreKey(data: ByteArray): SessionOneTimePreKey {
        val reader = Reader(data, 128)
        var id: Long? = null
        var publicKey: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> id = unique(id, reader.readUInt(wireType), "one-time-key id")
                2 -> publicKey = unique(
                    publicKey,
                    reader.readBytes(wireType, SESSION_OLM_PUBLIC_KEY_BYTES),
                    "one-time public key",
                )
                else -> reader.skip(wireType)
            }
        }
        val key = SessionOneTimePreKey(
            id ?: malformed("one-time-key id is missing"),
            publicKey ?: malformed("one-time public key is missing"),
        )
        if (key.id <= 0 || key.publicKey.size != SESSION_OLM_PUBLIC_KEY_BYTES || key.publicKey.all { it == 0.toByte() }) {
            malformed("session one-time key is invalid")
        }
        return key
    }

    private fun decodeIdentityBundle(data: ByteArray): M2PublicIdentityBundle {
        val reader = Reader(data, SESSION_MAX_BUNDLE_BYTES)
        var identityId: ByteArray? = null
        var identityPublicKey: ByteArray? = null
        var revision: Long? = null
        var signedPreKey: M2SignedPreKey? = null
        val oneTimePreKeys = ArrayList<M2OneTimePreKey>()
        var publicationSignature: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> identityId = unique(identityId, reader.readBytes(wireType, CONTACT_ID_BYTES), "identity id")
                2 -> identityPublicKey = unique(
                    identityPublicKey,
                    reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES),
                    "identity public key",
                )
                3 -> revision = unique(revision, reader.readUInt(wireType), "identity publication revision")
                4 -> signedPreKey = unique(
                    signedPreKey,
                    decodeSignedPreKey(reader.readBytes(wireType, SESSION_MAX_BUNDLE_BYTES)),
                    "signed prekey",
                )
                5 -> {
                    if (oneTimePreKeys.size >= MAX_CONTACT_ONE_TIME_PREKEYS) malformed("too many identity one-time prekeys")
                    oneTimePreKeys += decodeIdentityOneTimePreKey(reader.readBytes(wireType, SESSION_MAX_BUNDLE_BYTES))
                }
                6 -> publicationSignature = unique(
                    publicationSignature,
                    reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES),
                    "identity publication signature",
                )
                else -> reader.skip(wireType)
            }
        }
        val bundle = M2PublicIdentityBundle(
            identityId ?: malformed("identity id is missing"),
            identityPublicKey ?: malformed("identity public key is missing"),
            revision ?: malformed("identity publication revision is missing"),
            signedPreKey ?: malformed("signed prekey is missing"),
            oneTimePreKeys,
            publicationSignature ?: malformed("identity publication signature is missing"),
        )
        try {
            validateBundleShape(bundle, requirePublicationSignature = true)
        } catch (error: Exception) {
            throw SessionStateException("Claimed M2 identity bundle shape is invalid", error)
        }
        return bundle
    }

    private fun decodeSignedPreKey(data: ByteArray): M2SignedPreKey {
        val reader = Reader(data, SESSION_MAX_BUNDLE_BYTES)
        var id: Long? = null
        var publicKey: ByteArray? = null
        var signature: ByteArray? = null
        var createdAt: Long? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> id = unique(id, reader.readUInt(wireType), "signed prekey id")
                2 -> publicKey = unique(publicKey, reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES), "signed prekey key")
                3 -> signature = unique(signature, reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES), "signed prekey signature")
                4 -> createdAt = unique(createdAt, reader.readUInt(wireType), "signed prekey timestamp")
                else -> reader.skip(wireType)
            }
        }
        return M2SignedPreKey(
            id ?: malformed("signed prekey id is missing"),
            publicKey ?: malformed("signed prekey key is missing"),
            signature ?: malformed("signed prekey signature is missing"),
            createdAt ?: malformed("signed prekey timestamp is missing"),
        )
    }

    private fun decodeIdentityOneTimePreKey(data: ByteArray): M2OneTimePreKey {
        val reader = Reader(data, SESSION_MAX_BUNDLE_BYTES)
        var id: Long? = null
        var publicKey: ByteArray? = null
        var createdAt: Long? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> id = unique(id, reader.readUInt(wireType), "identity one-time-prekey id")
                2 -> publicKey = unique(
                    publicKey,
                    reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES),
                    "identity one-time-prekey key",
                )
                3 -> createdAt = unique(createdAt, reader.readUInt(wireType), "identity one-time-prekey timestamp")
                else -> reader.skip(wireType)
            }
        }
        return M2OneTimePreKey(
            id ?: malformed("identity one-time-prekey id is missing"),
            publicKey ?: malformed("identity one-time-prekey key is missing"),
            createdAt ?: malformed("identity one-time-prekey timestamp is missing"),
        )
    }

    private fun requireVersion(value: Long?) {
        if (value != SESSION_PROTOCOL_VERSION.toLong()) malformed("unsupported M3 protocol version")
    }

    private fun requirePositive(value: Long, name: String) {
        if (value <= 0) malformed("$name is invalid")
    }

    private fun requireSignature(value: ByteArray, name: String) {
        if (value.isEmpty() || value.size > SESSION_MAX_SIGNATURE_BYTES) malformed("$name size is invalid")
    }

    private fun <T> unique(current: T?, value: T, name: String): T {
        if (current != null) malformed("duplicate $name field")
        return value
    }

    private fun message(maximum: Int = SESSION_MAX_WIRE_BYTES, block: Writer.() -> Unit): ByteArray =
        Writer(maximum).apply(block).toByteArray()

    private fun malformed(message: String): Nothing = throw SessionStateException(message)
}

private class Writer(private val maximum: Int) {
    private val output = ByteArrayOutputStream()

    fun uint(field: Int, value: Long) {
        if (field !in 1..MAX_PROTO_FIELD || value < 0) throw SessionStateException("invalid protobuf integer field")
        tag(field, 0)
        writeVarint(value)
        enforceBound()
    }

    fun bytes(field: Int, value: ByteArray) {
        if (field !in 1..MAX_PROTO_FIELD || value.size > maximum) throw SessionStateException("invalid protobuf bytes field")
        tag(field, 2)
        writeVarint(value.size.toLong())
        output.write(value)
        enforceBound()
    }

    fun toByteArray(): ByteArray = output.toByteArray().also {
        if (it.isEmpty() || it.size > maximum) throw SessionStateException("M3 protobuf message size is invalid")
    }

    private fun tag(field: Int, wireType: Int) = writeVarint((field.toLong() shl 3) or wireType.toLong())

    private fun writeVarint(value: Long) {
        var remaining = value
        while (remaining and -128L != 0L) {
            output.write(((remaining and 0x7f) or 0x80).toInt())
            remaining = remaining ushr 7
        }
        output.write(remaining.toInt())
    }

    private fun enforceBound() {
        if (output.size() > maximum) throw SessionStateException("M3 protobuf message exceeds its bound")
    }

    private companion object {
        const val MAX_PROTO_FIELD = 536_870_911
    }
}

private class Reader(data: ByteArray, private val maximum: Int = SESSION_MAX_WIRE_BYTES) {
    private val data = data.copyOf()
    private var position = 0

    init {
        if (data.isEmpty() || data.size > maximum) throw SessionStateException("M3 protobuf message size is invalid")
    }

    fun fields(block: (Int, Int) -> Unit) {
        while (position < data.size) {
            val tag = readVarint()
            val field = tag ushr 3
            val wireType = (tag and 7).toInt()
            if (tag < 0 || field !in 1L..536_870_911L) throw SessionStateException("invalid protobuf field number")
            block(field.toInt(), wireType)
        }
    }

    fun readUInt(wireType: Int): Long {
        requireWireType(wireType, 0)
        val value = readVarint()
        if (value < 0) throw SessionStateException("unsigned protobuf integer exceeds signed Android range")
        return value
    }

    fun readBytes(wireType: Int, fieldMaximum: Int): ByteArray {
        requireWireType(wireType, 2)
        val length = readVarint()
        if (length < 0 || length > fieldMaximum.toLong() || length > data.size - position) {
            throw SessionStateException("protobuf bytes field size is invalid")
        }
        val start = position
        position += length.toInt()
        return data.copyOfRange(start, position)
    }

    fun skip(wireType: Int) {
        when (wireType) {
            0 -> readVarint()
            1 -> skipFixed(8)
            2 -> {
                val length = readVarint()
                if (length < 0 || length > data.size - position) throw SessionStateException("unknown protobuf field is invalid")
                position += length.toInt()
            }
            5 -> skipFixed(4)
            else -> throw SessionStateException("unsupported protobuf wire type")
        }
    }

    private fun readVarint(): Long {
        var result = 0L
        var shift = 0
        repeat(10) { index ->
            if (position >= data.size) throw SessionStateException("truncated protobuf varint")
            val byte = data[position++].toInt() and 0xff
            if (index == 9 && byte > 1) throw SessionStateException("protobuf varint overflows uint64")
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
        }
        throw SessionStateException("protobuf varint is too long")
    }

    private fun requireWireType(actual: Int, expected: Int) {
        if (actual != expected) throw SessionStateException("protobuf wire type is invalid")
    }

    private fun skipFixed(size: Int) {
        if (size > data.size - position) throw SessionStateException("truncated fixed protobuf field")
        position += size
    }
}
