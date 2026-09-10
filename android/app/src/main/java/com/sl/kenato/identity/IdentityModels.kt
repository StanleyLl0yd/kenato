package com.sl.kenato.identity

/** Public, non-secret identity material that can be published in a later milestone. */
data class IdentityBundle(
    val identityId: String,
    val identityPublicKey: String,
    val signedPreKey: SignedPreKey,
    val oneTimePreKeys: List<OneTimePreKey>,
)

data class SignedPreKey(
    val id: Int,
    val publicKey: String,
    val signature: String,
    val createdAtEpochSeconds: Long,
)

data class OneTimePreKey(
    val id: Int,
    val publicKey: String,
    val createdAtEpochSeconds: Long,
)

/** Fail-closed local identity state or key-material mismatch. */
class IdentityStateException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

/** Durable identity state could not be committed or cleared safely. */
class IdentityPersistenceException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)
