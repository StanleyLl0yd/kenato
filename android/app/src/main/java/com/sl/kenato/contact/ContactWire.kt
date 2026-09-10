package com.sl.kenato.contact

import java.io.ByteArrayOutputStream

private const val MAX_PROTOBUF_FIELD_NUMBER = 536_870_911

internal data class PublishIdentityWireResponse(val acceptedRevision: Long)
internal data class CreateInviteWireResponse(val expiresAtEpochSeconds: Long)
internal data class RedeemInviteWireResponse(
    val creatorBundle: M2PublicIdentityBundle,
    val redeemedAtEpochSeconds: Long,
)
internal data class ClaimInviteWireResponse(
    val redeemerBundle: M2PublicIdentityBundle,
    val redemptionSignature: ByteArray,
    val redeemedAtEpochSeconds: Long,
)

internal object ContactWire {
    fun encodePublishIdentityRequest(bundle: M2PublicIdentityBundle): ByteArray = message {
        uint(1, CONTACT_PROTOCOL_VERSION.toLong())
        bytes(2, encodeBundle(bundle))
    }

    fun decodePublishIdentityResponse(data: ByteArray): PublishIdentityWireResponse {
        val reader = ProtoReader(data)
        var protocolVersion: Long? = null
        var revision: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> protocolVersion = unique(protocolVersion, reader.readUInt(wireType), "protocol version")
                2 -> revision = unique(revision, reader.readUInt(wireType), "accepted revision")
                else -> reader.skip(wireType)
            }
        }
        requireProtocolVersion(protocolVersion)
        val accepted = revision ?: throw ContactProtocolException("Publish response revision is missing")
        if (accepted <= 0) throw ContactProtocolException("Publish response revision is invalid")
        return PublishIdentityWireResponse(accepted)
    }

    fun encodeCreateInviteRequest(invite: M2InviteDescriptor): ByteArray = message {
        uint(1, CONTACT_PROTOCOL_VERSION.toLong())
        bytes(2, encodeInvite(invite))
    }

    fun decodeCreateInviteResponse(data: ByteArray): CreateInviteWireResponse {
        val reader = ProtoReader(data)
        var protocolVersion: Long? = null
        var expiresAt: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> protocolVersion = unique(protocolVersion, reader.readUInt(wireType), "protocol version")
                2 -> expiresAt = unique(expiresAt, reader.readUInt(wireType), "invite expiry")
                else -> reader.skip(wireType)
            }
        }
        requireProtocolVersion(protocolVersion)
        val expiry = expiresAt ?: throw ContactProtocolException("Invite expiry is missing")
        if (expiry <= 0) throw ContactProtocolException("Invite expiry is invalid")
        return CreateInviteWireResponse(expiry)
    }

    fun encodeRedeemInviteRequest(
        invite: M2InviteDescriptor,
        redeemerBundle: M2PublicIdentityBundle,
        redemptionSignature: ByteArray,
    ): ByteArray {
        requireBoundedWireSignature(redemptionSignature)
        return message {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            bytes(2, encodeInvite(invite))
            bytes(3, encodeBundle(redeemerBundle))
            bytes(4, redemptionSignature)
        }
    }

    fun decodeRedeemInviteResponse(data: ByteArray): RedeemInviteWireResponse {
        val reader = ProtoReader(data)
        var protocolVersion: Long? = null
        var creatorBundle: M2PublicIdentityBundle? = null
        var redeemedAt: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> protocolVersion = unique(protocolVersion, reader.readUInt(wireType), "protocol version")
                2 -> creatorBundle = unique(creatorBundle, decodeBundle(reader.readBytes(wireType)), "creator bundle")
                3 -> redeemedAt = unique(redeemedAt, reader.readUInt(wireType), "redemption timestamp")
                else -> reader.skip(wireType)
            }
        }
        requireProtocolVersion(protocolVersion)
        val bundle = creatorBundle ?: throw ContactProtocolException("Creator bundle is missing")
        val timestamp = redeemedAt ?: throw ContactProtocolException("Redemption timestamp is missing")
        if (timestamp < 0) throw ContactProtocolException("Redemption timestamp is invalid")
        return RedeemInviteWireResponse(bundle, timestamp)
    }

    fun encodeClaimInviteRequest(
        creatorIdentityId: ByteArray,
        token: ByteArray,
        claimSignature: ByteArray,
    ): ByteArray {
        if (creatorIdentityId.size != CONTACT_ID_BYTES || token.size != INVITE_TOKEN_BYTES) {
            throw ContactProtocolException("Claim identity or token size is invalid")
        }
        requireBoundedWireSignature(claimSignature)
        return message {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            bytes(2, creatorIdentityId)
            bytes(3, token)
            bytes(4, claimSignature)
        }
    }

    fun decodeClaimInviteResponse(data: ByteArray): ClaimInviteWireResponse {
        val reader = ProtoReader(data)
        var protocolVersion: Long? = null
        var redeemerBundle: M2PublicIdentityBundle? = null
        var redemptionSignature: ByteArray? = null
        var redeemedAt: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> protocolVersion = unique(protocolVersion, reader.readUInt(wireType), "protocol version")
                2 -> redeemerBundle = unique(redeemerBundle, decodeBundle(reader.readBytes(wireType)), "redeemer bundle")
                3 -> redemptionSignature = unique(
                    redemptionSignature,
                    reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES),
                    "redemption signature",
                )
                4 -> redeemedAt = unique(redeemedAt, reader.readUInt(wireType), "redemption timestamp")
                else -> reader.skip(wireType)
            }
        }
        requireProtocolVersion(protocolVersion)
        val bundle = redeemerBundle ?: throw ContactProtocolException("Redeemer bundle is missing")
        val signature = redemptionSignature ?: throw ContactProtocolException("Redemption signature is missing")
        requireBoundedWireSignature(signature)
        val timestamp = redeemedAt ?: throw ContactProtocolException("Redemption timestamp is missing")
        return ClaimInviteWireResponse(bundle, signature, timestamp)
    }

    private fun encodeBundle(bundle: M2PublicIdentityBundle): ByteArray {
        validateBundleShape(bundle, requirePublicationSignature = true)
        return message {
            bytes(1, bundle.identityId)
            bytes(2, bundle.identityPublicKey)
            uint(3, bundle.publicationRevision)
            bytes(4, message {
                uint(1, bundle.signedPreKey.id)
                bytes(2, bundle.signedPreKey.publicKey)
                bytes(3, bundle.signedPreKey.signature)
                uint(4, bundle.signedPreKey.createdAtEpochSeconds)
            })
            bundle.oneTimePreKeys.forEach { preKey ->
                bytes(5, message {
                    uint(1, preKey.id)
                    bytes(2, preKey.publicKey)
                    uint(3, preKey.createdAtEpochSeconds)
                })
            }
            bytes(6, bundle.publicationSignature)
        }
    }

    private fun decodeBundle(data: ByteArray): M2PublicIdentityBundle {
        val reader = ProtoReader(data)
        var identityId: ByteArray? = null
        var identityPublicKey: ByteArray? = null
        var revision: Long? = null
        var signedPreKey: M2SignedPreKey? = null
        val oneTimePreKeys = ArrayList<M2OneTimePreKey>()
        var publicationSignature: ByteArray? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> identityId = unique(identityId, reader.readBytes(wireType, CONTACT_ID_BYTES), "identity id")
                2 -> identityPublicKey = unique(
                    identityPublicKey,
                    reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES),
                    "identity public key",
                )
                3 -> revision = unique(revision, reader.readUInt(wireType), "publication revision")
                4 -> signedPreKey = unique(signedPreKey, decodeSignedPreKey(reader.readBytes(wireType)), "signed prekey")
                5 -> {
                    if (oneTimePreKeys.size >= MAX_CONTACT_ONE_TIME_PREKEYS) {
                        throw ContactProtocolException("Too many one-time prekeys")
                    }
                    oneTimePreKeys += decodeOneTimePreKey(reader.readBytes(wireType))
                }
                6 -> publicationSignature = unique(
                    publicationSignature,
                    reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES),
                    "publication signature",
                )
                else -> reader.skip(wireType)
            }
        }
        val bundle = M2PublicIdentityBundle(
            identityId = identityId ?: throw ContactProtocolException("Identity id is missing"),
            identityPublicKey = identityPublicKey ?: throw ContactProtocolException("Identity public key is missing"),
            publicationRevision = revision ?: throw ContactProtocolException("Publication revision is missing"),
            signedPreKey = signedPreKey ?: throw ContactProtocolException("Signed prekey is missing"),
            oneTimePreKeys = oneTimePreKeys,
            publicationSignature = publicationSignature ?: throw ContactProtocolException("Publication signature is missing"),
        )
        validateBundleShape(bundle, requirePublicationSignature = true)
        return bundle
    }

    private fun decodeSignedPreKey(data: ByteArray): M2SignedPreKey {
        val reader = ProtoReader(data)
        var id: Long? = null
        var publicKey: ByteArray? = null
        var signature: ByteArray? = null
        var createdAt: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> id = unique(id, reader.readUInt(wireType), "signed prekey id")
                2 -> publicKey = unique(publicKey, reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES), "signed prekey key")
                3 -> signature = unique(signature, reader.readBytes(wireType, MAX_CONTACT_SIGNATURE_BYTES), "signed prekey signature")
                4 -> createdAt = unique(createdAt, reader.readUInt(wireType), "signed prekey timestamp")
                else -> reader.skip(wireType)
            }
        }
        return M2SignedPreKey(
            id ?: throw ContactProtocolException("Signed prekey id is missing"),
            publicKey ?: throw ContactProtocolException("Signed prekey key is missing"),
            signature ?: throw ContactProtocolException("Signed prekey signature is missing"),
            createdAt ?: throw ContactProtocolException("Signed prekey timestamp is missing"),
        )
    }

    private fun decodeOneTimePreKey(data: ByteArray): M2OneTimePreKey {
        val reader = ProtoReader(data)
        var id: Long? = null
        var publicKey: ByteArray? = null
        var createdAt: Long? = null
        reader.fields { number, wireType ->
            when (number) {
                1 -> id = unique(id, reader.readUInt(wireType), "one-time prekey id")
                2 -> publicKey = unique(publicKey, reader.readBytes(wireType, MAX_CONTACT_PUBLIC_KEY_BYTES), "one-time prekey key")
                3 -> createdAt = unique(createdAt, reader.readUInt(wireType), "one-time prekey timestamp")
                else -> reader.skip(wireType)
            }
        }
        return M2OneTimePreKey(
            id ?: throw ContactProtocolException("One-time prekey id is missing"),
            publicKey ?: throw ContactProtocolException("One-time prekey key is missing"),
            createdAt ?: throw ContactProtocolException("One-time prekey timestamp is missing"),
        )
    }

    private fun encodeInvite(invite: M2InviteDescriptor): ByteArray {
        validateInviteShape(invite)
        return message {
            bytes(1, invite.creatorIdentityId)
            bytes(2, invite.token)
            bytes(3, invite.signature)
        }
    }

    private fun requireProtocolVersion(value: Long?) {
        if (value != CONTACT_PROTOCOL_VERSION.toLong()) {
            throw ContactProtocolException("Unsupported contact protocol version")
        }
    }

    private fun requireBoundedWireSignature(value: ByteArray) {
        if (value.isEmpty() || value.size > MAX_CONTACT_SIGNATURE_BYTES) {
            throw ContactProtocolException("Contact signature size is invalid")
        }
    }

    private fun <T> unique(current: T?, value: T, name: String): T {
        if (current != null) throw ContactProtocolException("Duplicate $name field")
        return value
    }

    private fun message(block: ProtoWriter.() -> Unit): ByteArray = ProtoWriter().apply(block).toByteArray()
}

private class ProtoWriter {
    private val output = ByteArrayOutputStream()

    fun uint(field: Int, value: Long) {
        if (field !in 1..MAX_PROTOBUF_FIELD_NUMBER || value < 0) {
            throw ContactProtocolException("Invalid protobuf integer field")
        }
        tag(field, 0)
        var remaining = value
        while (remaining and -128L != 0L) {
            output.write(((remaining and 0x7f) or 0x80).toInt())
            remaining = remaining ushr 7
        }
        output.write(remaining.toInt())
        enforceSize()
    }

    fun bytes(field: Int, value: ByteArray) {
        if (field !in 1..MAX_PROTOBUF_FIELD_NUMBER || value.size > MAX_CONTACT_WIRE_BYTES) {
            throw ContactProtocolException("Invalid protobuf bytes field")
        }
        tag(field, 2)
        writeVarint(value.size.toLong())
        output.write(value)
        enforceSize()
    }

    fun toByteArray(): ByteArray = output.toByteArray().also {
        if (it.isEmpty() || it.size > MAX_CONTACT_WIRE_BYTES) {
            throw ContactProtocolException("Contact protobuf message size is invalid")
        }
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

    private fun enforceSize() {
        if (output.size() > MAX_CONTACT_WIRE_BYTES) {
            throw ContactProtocolException("Contact protobuf message is too large")
        }
    }
}

private class ProtoReader(data: ByteArray) {
    private val data = data.copyOf()
    private var position = 0

    init {
        if (data.isEmpty() || data.size > MAX_CONTACT_WIRE_BYTES) {
            throw ContactProtocolException("Contact protobuf message size is invalid")
        }
    }

    fun fields(block: (Int, Int) -> Unit) {
        while (position < data.size) {
            val tag = readVarint()
            val field = tag ushr 3
            val wireType = (tag and 7).toInt()
            if (tag < 0 || field !in 1L..MAX_PROTOBUF_FIELD_NUMBER.toLong()) {
                throw ContactProtocolException("Invalid protobuf field number")
            }
            block(field.toInt(), wireType)
        }
    }

    fun readUInt(wireType: Int): Long {
        requireWireType(wireType, 0)
        val value = readVarint()
        if (value < 0) throw ContactProtocolException("Unsigned protobuf integer is too large")
        return value
    }

    fun readBytes(wireType: Int, maximum: Int = MAX_CONTACT_WIRE_BYTES): ByteArray {
        requireWireType(wireType, 2)
        val length = readVarint()
        if (length < 0 || length > maximum || length > data.size - position) {
            throw ContactProtocolException("Protobuf bytes field size is invalid")
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
                if (length < 0 || length > data.size - position) {
                    throw ContactProtocolException("Unknown protobuf field size is invalid")
                }
                position += length.toInt()
            }
            5 -> skipFixed(4)
            else -> throw ContactProtocolException("Unsupported protobuf wire type")
        }
    }

    private fun readVarint(): Long {
        var result = 0L
        var shift = 0
        repeat(10) { index ->
            if (position >= data.size) throw ContactProtocolException("Truncated protobuf varint")
            val byte = data[position++].toInt() and 0xff
            if (index == 9 && byte > 1) throw ContactProtocolException("Protobuf varint overflows uint64")
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
        }
        throw ContactProtocolException("Invalid protobuf varint")
    }

    private fun skipFixed(size: Int) {
        if (size > data.size - position) throw ContactProtocolException("Truncated protobuf fixed field")
        position += size
    }

    private fun requireWireType(actual: Int, expected: Int) {
        if (actual != expected) throw ContactProtocolException("Unexpected protobuf wire type")
    }
}
