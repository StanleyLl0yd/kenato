package com.sl.kenato.contact

import com.sl.kenato.identity.IdentityBundle
import com.sl.kenato.identity.LocalIdentityRepository
import java.util.Base64

internal interface ContactIdentityProvider {
    fun currentIdentity(): IdentityBundle

    fun sign(payload: ByteArray): ByteArray
}

internal class LocalContactIdentityProvider(
    private val repository: LocalIdentityRepository,
) : ContactIdentityProvider {
    override fun currentIdentity(): IdentityBundle = repository.loadOrCreate()

    override fun sign(payload: ByteArray): ByteArray = repository.signIdentityProtocolPayload(payload)
}

internal fun IdentityBundle.toUnsignedContactBundle(revision: Long): M2PublicIdentityBundle {
    if (revision <= 0) throw ContactProtocolException("Publication revision is invalid")
    val identityId = decodeCanonicalBase64Url(identityId, CONTACT_ID_BYTES, "local identity id")
    val identityPublicKeyBytes = decodeCanonicalBase64Url(
        identityPublicKey,
        MAX_CONTACT_PUBLIC_KEY_BYTES,
        "local identity public key",
        exact = false,
    )
    val derived = ContactCrypto.identityId(identityPublicKeyBytes)
    if (!derived.contentEquals(identityId)) {
        throw ContactProtocolException("Local identity id does not match the local public key")
    }
    val contactSignedPreKey = M2SignedPreKey(
        id = signedPreKey.id.toLong(),
        publicKey = decodeCanonicalBase64Url(
            signedPreKey.publicKey,
            MAX_CONTACT_PUBLIC_KEY_BYTES,
            "local signed prekey",
            exact = false,
        ),
        signature = decodeCanonicalBase64Url(
            signedPreKey.signature,
            MAX_CONTACT_SIGNATURE_BYTES,
            "local signed prekey signature",
            exact = false,
        ),
        createdAtEpochSeconds = signedPreKey.createdAtEpochSeconds,
    )
    val contactOneTimePreKeys = oneTimePreKeys.map { preKey ->
        M2OneTimePreKey(
            id = preKey.id.toLong(),
            publicKey = decodeCanonicalBase64Url(
                preKey.publicKey,
                MAX_CONTACT_PUBLIC_KEY_BYTES,
                "local one-time prekey",
                exact = false,
            ),
            createdAtEpochSeconds = preKey.createdAtEpochSeconds,
        )
    }
    return M2PublicIdentityBundle(
        identityId = identityId,
        identityPublicKey = identityPublicKeyBytes,
        publicationRevision = revision,
        signedPreKey = contactSignedPreKey,
        oneTimePreKeys = contactOneTimePreKeys,
        publicationSignature = ByteArray(0),
    ).also { validateBundleShape(it, requirePublicationSignature = false) }
}

internal fun ContactIdentityProvider.signPublicBundle(unsigned: M2PublicIdentityBundle): M2PublicIdentityBundle {
    validateBundleShape(unsigned, requirePublicationSignature = false)
    if (unsigned.publicationSignature.isNotEmpty()) {
        throw ContactProtocolException("Unsigned publication unexpectedly contains a signature")
    }
    val signature = sign(ContactCanonical.publicationPayload(unsigned))
    if (signature.isEmpty() || signature.size > MAX_CONTACT_SIGNATURE_BYTES) {
        throw ContactProtocolException("Local publication signature size is invalid")
    }
    return unsigned.copy(publicationSignature = signature).also(ContactCrypto::verifyPublicIdentityBundle)
}

private fun decodeCanonicalBase64Url(
    value: String,
    bound: Int,
    name: String,
    exact: Boolean = true,
): ByteArray {
    if (value.isEmpty() || '=' in value || !BASE64_URL.matches(value)) {
        throw ContactProtocolException("$name encoding is invalid")
    }
    val decoded = try {
        BASE64_DECODER.decode(value)
    } catch (error: IllegalArgumentException) {
        throw ContactProtocolException("$name encoding is invalid", error)
    }
    if ((exact && decoded.size != bound) || (!exact && decoded.size !in 1..bound)) {
        throw ContactProtocolException("$name size is invalid")
    }
    if (BASE64_ENCODER.encodeToString(decoded) != value) {
        throw ContactProtocolException("$name encoding is non-canonical")
    }
    return decoded
}

private val BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding()
private val BASE64_DECODER = Base64.getUrlDecoder()
private val BASE64_URL = Regex("^[A-Za-z0-9_-]+$")
