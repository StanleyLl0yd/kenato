package com.sl.kenato.contact

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

internal const val CONTACT_PROTOCOL_VERSION = 1
internal const val CONTACT_ID_BYTES = 32
internal const val INVITE_TOKEN_BYTES = 32
internal const val MAX_CONTACT_PUBLIC_KEY_BYTES = 2_048
internal const val MAX_CONTACT_SIGNATURE_BYTES = 2_048
internal const val MAX_CONTACT_ONE_TIME_PREKEYS = 100
internal const val MAX_CONTACT_WIRE_BYTES = 64 shl 10

internal class ContactProtocolException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class M2SignedPreKey(
    val id: Long,
    val publicKey: ByteArray,
    val signature: ByteArray,
    val createdAtEpochSeconds: Long,
)

internal data class M2OneTimePreKey(
    val id: Long,
    val publicKey: ByteArray,
    val createdAtEpochSeconds: Long,
)

internal data class M2PublicIdentityBundle(
    val identityId: ByteArray,
    val identityPublicKey: ByteArray,
    val publicationRevision: Long,
    val signedPreKey: M2SignedPreKey,
    val oneTimePreKeys: List<M2OneTimePreKey>,
    val publicationSignature: ByteArray,
)

internal data class M2InviteDescriptor(
    val creatorIdentityId: ByteArray,
    val token: ByteArray,
    val signature: ByteArray,
)

internal object ContactCanonical {
    private val publicationDomain = "KENATO-PUBLICATION-V1\u0000".toByteArray(Charsets.UTF_8)
    private val signedPreKeyDomain = "KENATO-SIGNED-PREKEY-V1\u0000".toByteArray(Charsets.UTF_8)
    private val inviteDomain = "KENATO-INVITE-V1\u0000".toByteArray(Charsets.UTF_8)
    private val redeemDomain = "KENATO-REDEEM-V1\u0000".toByteArray(Charsets.UTF_8)
    private val claimDomain = "KENATO-CLAIM-V1\u0000".toByteArray(Charsets.UTF_8)

    fun publicationPayload(bundle: M2PublicIdentityBundle): ByteArray {
        validateBundleShape(bundle, requirePublicationSignature = false)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(publicationDomain)
                output.write(bundle.identityId)
                output.writeLong(bundle.publicationRevision)
                output.writeSized(bundle.identityPublicKey)
                output.writeInt(bundle.signedPreKey.id.toUInt32Int())
                output.writeLong(bundle.signedPreKey.createdAtEpochSeconds)
                output.writeSized(bundle.signedPreKey.publicKey)
                output.writeSized(bundle.signedPreKey.signature)
                output.writeInt(bundle.oneTimePreKeys.size)
                bundle.oneTimePreKeys.forEach { preKey ->
                    output.writeInt(preKey.id.toUInt32Int())
                    output.writeLong(preKey.createdAtEpochSeconds)
                    output.writeSized(preKey.publicKey)
                }
            }
            bytes.toByteArray()
        }.also(::requireWireSized)
    }

    fun signedPreKeyPayload(id: Long, publicKey: ByteArray): ByteArray {
        requireUInt32(id, "signed prekey id")
        requireBounded(publicKey, MAX_CONTACT_PUBLIC_KEY_BYTES, "signed prekey public key")
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(signedPreKeyDomain)
                output.writeInt(id.toUInt32Int())
                output.writeSized(publicKey)
            }
            bytes.toByteArray()
        }
    }

    fun invitePayload(creatorIdentityId: ByteArray, token: ByteArray): ByteArray {
        requireExact(creatorIdentityId, CONTACT_ID_BYTES, "creator identity id")
        requireExact(token, INVITE_TOKEN_BYTES, "invite token")
        return inviteDomain + creatorIdentityId + token
    }

    fun redemptionPayload(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        token: ByteArray,
    ): ByteArray {
        requireExact(creatorIdentityId, CONTACT_ID_BYTES, "creator identity id")
        requireExact(redeemerIdentityId, CONTACT_ID_BYTES, "redeemer identity id")
        requireExact(token, INVITE_TOKEN_BYTES, "invite token")
        return redeemDomain + creatorIdentityId + redeemerIdentityId + token
    }

    fun claimPayload(creatorIdentityId: ByteArray, token: ByteArray): ByteArray {
        requireExact(creatorIdentityId, CONTACT_ID_BYTES, "creator identity id")
        requireExact(token, INVITE_TOKEN_BYTES, "invite token")
        return claimDomain + creatorIdentityId + token
    }

    fun publicationMaterialHash(bundle: M2PublicIdentityBundle): ByteArray {
        val normalized = bundle.copy(publicationRevision = 1, publicationSignature = ByteArray(0))
        return MessageDigest.getInstance("SHA-256").digest(publicationPayload(normalized))
    }

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }
}

internal object ContactCrypto {
    private val p256Parameters: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    fun identityId(publicKey: ByteArray): ByteArray {
        canonicalP256PublicKey(publicKey)
        return MessageDigest.getInstance("SHA-256").digest(publicKey)
    }

    fun verifyPublicIdentityBundle(bundle: M2PublicIdentityBundle) {
        validateBundleShape(bundle, requirePublicationSignature = true)
        val identityKey = canonicalP256PublicKey(bundle.identityPublicKey)
        if (!MessageDigest.isEqual(identityId(bundle.identityPublicKey), bundle.identityId)) {
            throw ContactProtocolException("Public identity id does not match its public key")
        }

        val signedPreKey = bundle.signedPreKey
        canonicalP256PublicKey(signedPreKey.publicKey)
        if (!verifySignature(
                identityKey,
                ContactCanonical.signedPreKeyPayload(signedPreKey.id, signedPreKey.publicKey),
                signedPreKey.signature,
            )
        ) {
            throw ContactProtocolException("Signed prekey signature is invalid")
        }

        bundle.oneTimePreKeys.forEach { canonicalP256PublicKey(it.publicKey) }
        if (!verifySignature(identityKey, ContactCanonical.publicationPayload(bundle), bundle.publicationSignature)) {
            throw ContactProtocolException("Identity publication signature is invalid")
        }
    }

    fun verifyInvite(invite: M2InviteDescriptor, creatorPublicKey: ByteArray) {
        validateInviteShape(invite)
        val key = canonicalP256PublicKey(creatorPublicKey)
        if (!verifySignature(
                key,
                ContactCanonical.invitePayload(invite.creatorIdentityId, invite.token),
                invite.signature,
            )
        ) {
            throw ContactProtocolException("Invite signature is invalid")
        }
    }

    fun verifyRedemption(
        creatorIdentityId: ByteArray,
        redeemer: M2PublicIdentityBundle,
        token: ByteArray,
        signature: ByteArray,
    ) {
        requireBounded(signature, MAX_CONTACT_SIGNATURE_BYTES, "redemption signature")
        verifyPublicIdentityBundle(redeemer)
        val key = canonicalP256PublicKey(redeemer.identityPublicKey)
        if (!verifySignature(
                key,
                ContactCanonical.redemptionPayload(creatorIdentityId, redeemer.identityId, token),
                signature,
            )
        ) {
            throw ContactProtocolException("Redemption signature is invalid")
        }
    }

    fun canonicalP256PublicKey(encoded: ByteArray): ECPublicKey {
        requireBounded(encoded, MAX_CONTACT_PUBLIC_KEY_BYTES, "EC public key")
        val key = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded)) as? ECPublicKey
        } catch (error: Exception) {
            throw ContactProtocolException("EC public key is invalid", error)
        } ?: throw ContactProtocolException("Public key is not an EC key")

        if (!key.encoded.contentEquals(encoded) || !sameCurve(key.params, p256Parameters)) {
            throw ContactProtocolException("Public key is not canonical P-256")
        }
        return key
    }

    private fun verifySignature(key: ECPublicKey, payload: ByteArray, signature: ByteArray): Boolean {
        requireBounded(signature, MAX_CONTACT_SIGNATURE_BYTES, "ECDSA signature")
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun sameCurve(actual: ECParameterSpec, expected: ECParameterSpec): Boolean {
        val actualField = actual.curve.field as? ECFieldFp ?: return false
        val expectedField = expected.curve.field as? ECFieldFp ?: return false
        return actualField.p == expectedField.p &&
            actual.curve.a == expected.curve.a &&
            actual.curve.b == expected.curve.b &&
            actual.generator == expected.generator &&
            actual.order == expected.order &&
            actual.cofactor == expected.cofactor
    }
}

internal object InviteUriCodec {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val base64Url = Regex("^[A-Za-z0-9_-]+$")

    fun encode(invite: M2InviteDescriptor): String {
        validateInviteShape(invite)
        return buildString {
            append("kenato://invite/v1/")
            append(encoder.encodeToString(invite.creatorIdentityId))
            append('/')
            append(encoder.encodeToString(invite.token))
            append('/')
            append(encoder.encodeToString(invite.signature))
        }
    }

    fun decode(raw: String): M2InviteDescriptor {
        if (raw.isEmpty() || raw.length > MAX_INVITE_URI_CHARS) {
            throw ContactProtocolException("Invite URI size is invalid")
        }
        val uri = try {
            URI(raw)
        } catch (error: Exception) {
            throw ContactProtocolException("Invite URI is malformed", error)
        }
        if (
            uri.scheme != "kenato" ||
            uri.rawAuthority != "invite" ||
            uri.rawUserInfo != null ||
            uri.port != -1 ||
            uri.rawQuery != null ||
            uri.rawFragment != null ||
            '%' in uri.rawPath
        ) {
            throw ContactProtocolException("Invite URI authority or structure is invalid")
        }
        val parts = uri.rawPath.split('/')
        if (parts.size != 5 || parts[0].isNotEmpty() || parts[1] != "v1") {
            throw ContactProtocolException("Invite URI path is invalid")
        }
        val invite = M2InviteDescriptor(
            creatorIdentityId = decodeCanonical(parts[2], CONTACT_ID_BYTES, "creator identity id"),
            token = decodeCanonical(parts[3], INVITE_TOKEN_BYTES, "invite token"),
            signature = decodeCanonical(parts[4], MAX_CONTACT_SIGNATURE_BYTES, "invite signature", exact = false),
        )
        validateInviteShape(invite)
        return invite
    }

    private fun decodeCanonical(value: String, bound: Int, name: String, exact: Boolean = true): ByteArray {
        if (value.isEmpty() || '=' in value || !base64Url.matches(value)) {
            throw ContactProtocolException("$name Base64url encoding is invalid")
        }
        val decoded = try {
            decoder.decode(value)
        } catch (error: IllegalArgumentException) {
            throw ContactProtocolException("$name Base64url encoding is invalid", error)
        }
        if ((exact && decoded.size != bound) || (!exact && decoded.size !in 1..bound)) {
            throw ContactProtocolException("$name size is invalid")
        }
        if (encoder.encodeToString(decoded) != value) {
            throw ContactProtocolException("$name Base64url encoding is non-canonical")
        }
        return decoded
    }

    private const val MAX_INVITE_URI_CHARS = 3_000
}

internal fun validateBundleShape(bundle: M2PublicIdentityBundle, requirePublicationSignature: Boolean) {
    requireExact(bundle.identityId, CONTACT_ID_BYTES, "identity id")
    requireBounded(bundle.identityPublicKey, MAX_CONTACT_PUBLIC_KEY_BYTES, "identity public key")
    if (bundle.publicationRevision <= 0) {
        throw ContactProtocolException("Publication revision is invalid")
    }
    requireUInt32(bundle.signedPreKey.id, "signed prekey id")
    requireBounded(bundle.signedPreKey.publicKey, MAX_CONTACT_PUBLIC_KEY_BYTES, "signed prekey public key")
    requireBounded(bundle.signedPreKey.signature, MAX_CONTACT_SIGNATURE_BYTES, "signed prekey signature")
    if (bundle.signedPreKey.createdAtEpochSeconds < 0) {
        throw ContactProtocolException("Signed prekey timestamp is invalid")
    }
    if (bundle.oneTimePreKeys.size > MAX_CONTACT_ONE_TIME_PREKEYS) {
        throw ContactProtocolException("Too many one-time prekeys")
    }
    var previousId = 0L
    bundle.oneTimePreKeys.forEach { preKey ->
        requireUInt32(preKey.id, "one-time prekey id")
        if (preKey.id == bundle.signedPreKey.id || preKey.id <= previousId) {
            throw ContactProtocolException("One-time prekey ids are invalid")
        }
        if (preKey.createdAtEpochSeconds < 0) {
            throw ContactProtocolException("One-time prekey timestamp is invalid")
        }
        requireBounded(preKey.publicKey, MAX_CONTACT_PUBLIC_KEY_BYTES, "one-time prekey public key")
        previousId = preKey.id
    }
    if (requirePublicationSignature) {
        requireBounded(bundle.publicationSignature, MAX_CONTACT_SIGNATURE_BYTES, "publication signature")
    } else if (bundle.publicationSignature.size > MAX_CONTACT_SIGNATURE_BYTES) {
        throw ContactProtocolException("Publication signature is too large")
    }
}

internal fun validateInviteShape(invite: M2InviteDescriptor) {
    requireExact(invite.creatorIdentityId, CONTACT_ID_BYTES, "creator identity id")
    requireExact(invite.token, INVITE_TOKEN_BYTES, "invite token")
    requireBounded(invite.signature, MAX_CONTACT_SIGNATURE_BYTES, "invite signature")
}

private fun requireWireSized(value: ByteArray) {
    if (value.isEmpty() || value.size > MAX_CONTACT_WIRE_BYTES) {
        throw ContactProtocolException("Canonical payload size is invalid")
    }
}

private fun requireUInt32(value: Long, name: String) {
    if (value !in 1..0xffff_ffffL) {
        throw ContactProtocolException("$name is invalid")
    }
}

private fun Long.toUInt32Int(): Int {
    requireUInt32(this, "uint32 value")
    return toInt()
}

private fun requireExact(value: ByteArray, expected: Int, name: String) {
    if (value.size != expected) {
        throw ContactProtocolException("$name size is invalid")
    }
}

private fun requireBounded(value: ByteArray, maximum: Int, name: String) {
    if (value.isEmpty() || value.size > maximum) {
        throw ContactProtocolException("$name size is invalid")
    }
}
