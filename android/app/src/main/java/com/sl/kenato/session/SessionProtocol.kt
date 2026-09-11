package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal const val SESSION_PROTOCOL_VERSION = 1
internal const val SESSION_IDENTITY_BYTES = 32
internal const val SESSION_INVITE_TOKEN_BYTES = 32
internal const val SESSION_OLM_PUBLIC_KEY_BYTES = 32
internal const val SESSION_MAX_ONE_TIME_KEYS = 50
internal const val SESSION_MAX_SIGNATURE_BYTES = 256
internal const val SESSION_MAX_OLM_MESSAGE_BYTES = 96 * 1024
internal const val SESSION_OLM_MESSAGE_PRE_KEY = 0
internal const val SESSION_OLM_MESSAGE_NORMAL = 1

internal data class SessionOneTimePreKey(
    val id: Long,
    val publicKey: ByteArray,
)

internal data class SessionBootstrapBundle(
    val identityId: ByteArray,
    val accountGeneration: Long,
    val publicationRevision: Long,
    val olmEd25519IdentityKey: ByteArray,
    val olmCurve25519IdentityKey: ByteArray,
    val oneTimePreKeys: List<SessionOneTimePreKey>,
    val bindingSignature: ByteArray,
)

internal data class SessionSubmitInit(
    val creatorIdentityId: ByteArray,
    val redeemerIdentityId: ByteArray,
    val inviteToken: ByteArray,
    val creatorAccountGeneration: Long,
    val creatorOneTimePreKeyId: Long,
    val redeemerAccountGeneration: Long,
    val olmMessageType: Int,
    val olmMessage: ByteArray,
    val submitSignature: ByteArray = ByteArray(0),
)

internal object SessionCanonical {
    private val bootstrapDomain = domain("KENATO-SESSION-BOOTSTRAP-V1")
    private val reserveDomain = domain("KENATO-SESSION-RESERVE-V1")
    private val submitDomain = domain("KENATO-SESSION-INIT-SUBMIT-V1")
    private val claimDomain = domain("KENATO-SESSION-CLAIM-V1")
    private val initControlDomain = domain("KENATO-SESSION-INIT-CONTROL-V1")

    fun bootstrapPayload(bundle: SessionBootstrapBundle): ByteArray {
        validateBootstrap(bundle, requireSignature = false)
        return bytes {
            write(bootstrapDomain)
            write(bundle.identityId)
            writeLong(bundle.accountGeneration)
            writeLong(bundle.publicationRevision)
            write(bundle.olmEd25519IdentityKey)
            write(bundle.olmCurve25519IdentityKey)
            writeInt(bundle.oneTimePreKeys.size)
            bundle.oneTimePreKeys.forEach { key ->
                writeLong(key.id)
                write(key.publicKey)
            }
        }
    }

    fun reservePayload(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
    ): ByteArray {
        requireIdentity(creatorIdentityId, "creator identity id")
        requireIdentity(redeemerIdentityId, "redeemer identity id")
        requireInviteToken(inviteToken)
        if (creatorIdentityId.contentEquals(redeemerIdentityId)) {
            throw SessionStateException("M3 reservation identities must be distinct")
        }
        return bytes {
            write(reserveDomain)
            write(creatorIdentityId)
            write(redeemerIdentityId)
            write(inviteToken)
        }
    }

    fun submitPayload(request: SessionSubmitInit): ByteArray {
        validateSubmit(request, requireSignature = false)
        val messageDigest = MessageDigest.getInstance("SHA-256").digest(request.olmMessage)
        return bytes {
            write(submitDomain)
            write(request.creatorIdentityId)
            write(request.redeemerIdentityId)
            write(request.inviteToken)
            writeLong(request.creatorAccountGeneration)
            writeLong(request.creatorOneTimePreKeyId)
            writeLong(request.redeemerAccountGeneration)
            writeInt(request.olmMessageType)
            write(messageDigest)
        }
    }

    fun initControlPayload(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
        redeemerAccountGeneration: Long,
    ): ByteArray {
        requireIdentity(creatorIdentityId, "creator identity id")
        requireIdentity(redeemerIdentityId, "redeemer identity id")
        requireInviteToken(inviteToken)
        if (creatorIdentityId.contentEquals(redeemerIdentityId)) {
            throw SessionStateException("M3 control identities must be distinct")
        }
        requirePositive(creatorAccountGeneration, "creator account generation")
        requirePositive(creatorOneTimePreKeyId, "creator one-time-key id")
        requirePositive(redeemerAccountGeneration, "redeemer account generation")
        val tokenHash = MessageDigest.getInstance("SHA-256").digest(inviteToken)
        return bytes {
            write(initControlDomain)
            write(creatorIdentityId)
            write(redeemerIdentityId)
            write(tokenHash)
            writeLong(creatorAccountGeneration)
            writeLong(creatorOneTimePreKeyId)
            writeLong(redeemerAccountGeneration)
        }
    }

    fun claimPayload(creatorIdentityId: ByteArray, inviteToken: ByteArray): ByteArray {
        requireIdentity(creatorIdentityId, "creator identity id")
        requireInviteToken(inviteToken)
        return bytes {
            write(claimDomain)
            write(creatorIdentityId)
            write(inviteToken)
        }
    }

    fun validateBootstrap(bundle: SessionBootstrapBundle, requireSignature: Boolean) {
        requireIdentity(bundle.identityId, "session bootstrap identity id")
        requirePositive(bundle.accountGeneration, "session account generation")
        requirePositive(bundle.publicationRevision, "session publication revision")
        requireOlmKey(bundle.olmEd25519IdentityKey, "Olm Ed25519 identity key")
        requireOlmKey(bundle.olmCurve25519IdentityKey, "Olm Curve25519 identity key")
        if (bundle.olmEd25519IdentityKey.contentEquals(bundle.olmCurve25519IdentityKey)) {
            throw SessionStateException("Olm account identity keys must be distinct")
        }
        if (bundle.oneTimePreKeys.size !in 1..SESSION_MAX_ONE_TIME_KEYS) {
            throw SessionStateException("M3 bootstrap one-time-key count is invalid")
        }
        var previousId = 0L
        bundle.oneTimePreKeys.forEachIndexed { index, key ->
            requirePositive(key.id, "session one-time-key id")
            if (key.id <= previousId) {
                throw SessionStateException("M3 bootstrap one-time-key ids must be strictly increasing")
            }
            requireOlmKey(key.publicKey, "session one-time public key")
            if (
                key.publicKey.contentEquals(bundle.olmEd25519IdentityKey) ||
                key.publicKey.contentEquals(bundle.olmCurve25519IdentityKey) ||
                bundle.oneTimePreKeys.take(index).any { it.publicKey.contentEquals(key.publicKey) }
            ) {
                throw SessionStateException("M3 bootstrap one-time-key material is not unique")
            }
            previousId = key.id
        }
        if (requireSignature) {
            requireSignature(bundle.bindingSignature, "M3 bootstrap binding signature")
        } else if (bundle.bindingSignature.size > SESSION_MAX_SIGNATURE_BYTES) {
            throw SessionStateException("M3 bootstrap binding signature is too large")
        }
    }

    fun validateSubmit(request: SessionSubmitInit, requireSignature: Boolean) {
        requireIdentity(request.creatorIdentityId, "creator identity id")
        requireIdentity(request.redeemerIdentityId, "redeemer identity id")
        if (request.creatorIdentityId.contentEquals(request.redeemerIdentityId)) {
            throw SessionStateException("M3 submit identities must be distinct")
        }
        requireInviteToken(request.inviteToken)
        requirePositive(request.creatorAccountGeneration, "creator account generation")
        requirePositive(request.creatorOneTimePreKeyId, "creator one-time-key id")
        requirePositive(request.redeemerAccountGeneration, "redeemer account generation")
        if (request.olmMessageType != SESSION_OLM_MESSAGE_PRE_KEY) {
            throw SessionStateException("M3 init must use an Olm pre-key message")
        }
        if (request.olmMessage.isEmpty() || request.olmMessage.size > SESSION_MAX_OLM_MESSAGE_BYTES) {
            throw SessionStateException("M3 init Olm message size is invalid")
        }
        if (requireSignature) {
            requireSignature(request.submitSignature, "M3 init submit signature")
        } else if (request.submitSignature.size > SESSION_MAX_SIGNATURE_BYTES) {
            throw SessionStateException("M3 init submit signature is too large")
        }
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != SESSION_IDENTITY_BYTES) {
            throw SessionStateException("$name size is invalid")
        }
    }

    private fun requireInviteToken(value: ByteArray) {
        if (value.size != SESSION_INVITE_TOKEN_BYTES) {
            throw SessionStateException("M3 invite token size is invalid")
        }
    }

    private fun requireOlmKey(value: ByteArray, name: String) {
        if (value.size != SESSION_OLM_PUBLIC_KEY_BYTES || value.all { it == 0.toByte() }) {
            throw SessionStateException("$name is invalid")
        }
    }

    private fun requirePositive(value: Long, name: String) {
        if (value <= 0) {
            throw SessionStateException("$name is invalid")
        }
    }

    private fun requireSignature(value: ByteArray, name: String) {
        if (value.isEmpty() || value.size > SESSION_MAX_SIGNATURE_BYTES) {
            throw SessionStateException("$name size is invalid")
        }
    }

    private fun bytes(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output -> output.block() }
            buffer.toByteArray()
        }

    private fun domain(value: String): ByteArray =
        (value + "\u0000").toByteArray(StandardCharsets.UTF_8)
}
