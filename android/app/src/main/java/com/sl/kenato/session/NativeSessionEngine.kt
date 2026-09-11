package com.sl.kenato.session

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.charset.StandardCharsets

internal data class NativeSessionSnapshot(
    val ciphertext: ByteArray,
    val pickleKey: ByteArray,
)

internal data class NativeAccountPublicState(
    val olmEd25519IdentityKey: ByteArray,
    val olmCurve25519IdentityKey: ByteArray,
    val unpublishedOneTimeKeys: List<ByteArray>,
    val storedOneTimeKeyCount: Int,
)

internal data class NativeAccountMutation(
    val snapshot: NativeSessionSnapshot,
    val publicState: NativeAccountPublicState,
)

internal data class NativeSessionMessage(
    val messageType: Int,
    val ciphertext: ByteArray,
)

internal data class NativeOutboundSessionResult(
    val snapshot: NativeSessionSnapshot,
    val sessionId: String,
    val initialMessage: NativeSessionMessage,
)

internal data class NativeInboundSessionResult(
    val accountSnapshot: NativeSessionSnapshot,
    val sessionSnapshot: NativeSessionSnapshot,
    val sessionId: String,
    val plaintext: ByteArray,
)

internal data class NativeEncryptResult(
    val snapshot: NativeSessionSnapshot,
    val message: NativeSessionMessage,
)

internal data class NativeDecryptResult(
    val snapshot: NativeSessionSnapshot,
    val plaintext: ByteArray,
)

internal class NativeSessionException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface SessionEngine {
    fun createAccount(): NativeAccountMutation

    fun inspectAccount(snapshot: NativeSessionSnapshot): NativeAccountPublicState

    fun markAccountKeysPublished(snapshot: NativeSessionSnapshot): NativeSessionSnapshot

    fun generateAccountOneTimeKeys(snapshot: NativeSessionSnapshot, count: Int): NativeAccountMutation

    fun createOutboundSession(
        account: NativeSessionSnapshot,
        peerCurve25519IdentityKey: ByteArray,
        peerOneTimeKey: ByteArray,
        initialPlaintext: ByteArray,
    ): NativeOutboundSessionResult

    fun createInboundSession(
        account: NativeSessionSnapshot,
        expectedPeerCurve25519IdentityKey: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): NativeInboundSessionResult

    fun encryptSession(
        session: NativeSessionSnapshot,
        plaintext: ByteArray,
    ): NativeEncryptResult

    fun decryptSession(
        session: NativeSessionSnapshot,
        messageType: Int,
        olmMessage: ByteArray,
    ): NativeDecryptResult
}

internal class JniSessionEngine : SessionEngine {
    override fun createAccount(): NativeAccountMutation =
        NativeSessionCodec.decodeAccountMutation(nativeCall { NativeSessionBridge.createAccount() })

    override fun inspectAccount(snapshot: NativeSessionSnapshot): NativeAccountPublicState {
        validateSnapshot(snapshot, MAX_ACCOUNT_SNAPSHOT_BYTES)
        return NativeSessionCodec.decodePublicAccount(
            nativeCall {
                NativeSessionBridge.inspectAccount(snapshot.ciphertext, snapshot.pickleKey)
            },
        )
    }

    override fun markAccountKeysPublished(snapshot: NativeSessionSnapshot): NativeSessionSnapshot {
        validateSnapshot(snapshot, MAX_ACCOUNT_SNAPSHOT_BYTES)
        return NativeSessionCodec.decodeSnapshot(
            nativeCall {
                NativeSessionBridge.markAccountKeysPublished(snapshot.ciphertext, snapshot.pickleKey)
            },
            MAX_ACCOUNT_SNAPSHOT_BYTES,
        )
    }

    override fun generateAccountOneTimeKeys(
        snapshot: NativeSessionSnapshot,
        count: Int,
    ): NativeAccountMutation {
        validateSnapshot(snapshot, MAX_ACCOUNT_SNAPSHOT_BYTES)
        if (count !in 1..MAX_PUBLICATION_ONE_TIME_KEYS) {
            throw NativeSessionException("Native one-time-key generation count is invalid")
        }
        return NativeSessionCodec.decodeAccountMutation(
            nativeCall {
                NativeSessionBridge.generateAccountOneTimeKeys(
                    snapshot.ciphertext,
                    snapshot.pickleKey,
                    count,
                )
            },
        )
    }

    override fun createOutboundSession(
        account: NativeSessionSnapshot,
        peerCurve25519IdentityKey: ByteArray,
        peerOneTimeKey: ByteArray,
        initialPlaintext: ByteArray,
    ): NativeOutboundSessionResult {
        validateSnapshot(account, MAX_ACCOUNT_SNAPSHOT_BYTES)
        requirePublicKey(peerCurve25519IdentityKey)
        requirePublicKey(peerOneTimeKey)
        requirePlaintext(initialPlaintext)
        return NativeSessionCodec.decodeOutbound(
            nativeCall {
                NativeSessionBridge.createOutboundSession(
                    account.ciphertext,
                    account.pickleKey,
                    peerCurve25519IdentityKey,
                    peerOneTimeKey,
                    initialPlaintext,
                )
            },
        )
    }

    override fun createInboundSession(
        account: NativeSessionSnapshot,
        expectedPeerCurve25519IdentityKey: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): NativeInboundSessionResult {
        validateSnapshot(account, MAX_ACCOUNT_SNAPSHOT_BYTES)
        requirePublicKey(expectedPeerCurve25519IdentityKey)
        requireMessageType(messageType, preKeyOnly = true)
        requireOlmMessage(olmMessage)
        return NativeSessionCodec.decodeInbound(
            nativeCall {
                NativeSessionBridge.createInboundSession(
                    account.ciphertext,
                    account.pickleKey,
                    expectedPeerCurve25519IdentityKey,
                    messageType,
                    olmMessage,
                )
            },
        )
    }

    override fun encryptSession(
        session: NativeSessionSnapshot,
        plaintext: ByteArray,
    ): NativeEncryptResult {
        validateSnapshot(session, MAX_SESSION_SNAPSHOT_BYTES)
        requirePlaintext(plaintext)
        return NativeSessionCodec.decodeEncrypt(
            nativeCall {
                NativeSessionBridge.encryptSession(session.ciphertext, session.pickleKey, plaintext)
            },
        )
    }

    override fun decryptSession(
        session: NativeSessionSnapshot,
        messageType: Int,
        olmMessage: ByteArray,
    ): NativeDecryptResult {
        validateSnapshot(session, MAX_SESSION_SNAPSHOT_BYTES)
        requireMessageType(messageType, preKeyOnly = false)
        requireOlmMessage(olmMessage)
        return NativeSessionCodec.decodeDecrypt(
            nativeCall {
                NativeSessionBridge.decryptSession(
                    session.ciphertext,
                    session.pickleKey,
                    messageType,
                    olmMessage,
                )
            },
        )
    }

    private fun validateSnapshot(snapshot: NativeSessionSnapshot, maximumCiphertextBytes: Int) {
        if (snapshot.ciphertext.isEmpty() || snapshot.ciphertext.size > maximumCiphertextBytes) {
            throw NativeSessionException("Native encrypted snapshot size is invalid")
        }
        if (snapshot.pickleKey.size != PICKLE_KEY_BYTES) {
            throw NativeSessionException("Native pickle key size is invalid")
        }
    }

    private fun requirePublicKey(value: ByteArray) {
        if (value.size != OLM_PUBLIC_KEY_BYTES) {
            throw NativeSessionException("Olm public key size is invalid")
        }
    }

    private fun requirePlaintext(value: ByteArray) {
        if (value.size > MAX_PLAINTEXT_BYTES) {
            throw NativeSessionException("Native plaintext exceeds the M3 bound")
        }
    }

    private fun requireOlmMessage(value: ByteArray) {
        if (value.isEmpty() || value.size > MAX_OLM_MESSAGE_BYTES) {
            throw NativeSessionException("Olm message size is invalid")
        }
    }

    private fun requireMessageType(value: Int, preKeyOnly: Boolean) {
        val valid = if (preKeyOnly) value == MESSAGE_TYPE_PRE_KEY else value in MESSAGE_TYPE_PRE_KEY..MESSAGE_TYPE_NORMAL
        if (!valid) {
            throw NativeSessionException("Olm message type is invalid")
        }
    }

    private fun <T> nativeCall(block: () -> T): T = try {
        block()
    } catch (error: NativeSessionException) {
        throw error
    } catch (error: Throwable) {
        throw NativeSessionException("Native session operation failed closed", error)
    }

    private companion object {
        const val PICKLE_KEY_BYTES = 32
        const val OLM_PUBLIC_KEY_BYTES = 32
        const val MAX_PUBLICATION_ONE_TIME_KEYS = 50
        const val MAX_PLAINTEXT_BYTES = 64 * 1024
        const val MAX_OLM_MESSAGE_BYTES = 96 * 1024
        const val MAX_ACCOUNT_SNAPSHOT_BYTES = 256 * 1024
        const val MAX_SESSION_SNAPSHOT_BYTES = 256 * 1024
        const val MESSAGE_TYPE_PRE_KEY = 0
        const val MESSAGE_TYPE_NORMAL = 1
    }
}

internal object NativeSessionBridge {
    init {
        System.loadLibrary("kenato_session_jni")
    }

    external fun createAccount(): ByteArray

    external fun inspectAccount(accountCiphertext: ByteArray, accountPickleKey: ByteArray): ByteArray

    external fun markAccountKeysPublished(
        accountCiphertext: ByteArray,
        accountPickleKey: ByteArray,
    ): ByteArray

    external fun generateAccountOneTimeKeys(
        accountCiphertext: ByteArray,
        accountPickleKey: ByteArray,
        count: Int,
    ): ByteArray

    external fun createOutboundSession(
        accountCiphertext: ByteArray,
        accountPickleKey: ByteArray,
        peerCurve25519IdentityKey: ByteArray,
        peerOneTimeKey: ByteArray,
        initialPlaintext: ByteArray,
    ): ByteArray

    external fun createInboundSession(
        accountCiphertext: ByteArray,
        accountPickleKey: ByteArray,
        expectedPeerCurve25519IdentityKey: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): ByteArray

    external fun encryptSession(
        sessionCiphertext: ByteArray,
        sessionPickleKey: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    external fun decryptSession(
        sessionCiphertext: ByteArray,
        sessionPickleKey: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): ByteArray
}

internal object NativeSessionCodec {
    private const val BRIDGE_VERSION = 1L
    private const val PICKLE_KEY_BYTES = 32
    private const val OLM_PUBLIC_KEY_BYTES = 32
    private const val MAX_PUBLICATION_ONE_TIME_KEYS = 50
    private const val MAX_STORED_ONE_TIME_KEYS = 100
    private const val MAX_ACCOUNT_SNAPSHOT_BYTES = 256 * 1024
    private const val MAX_SESSION_SNAPSHOT_BYTES = 256 * 1024
    private const val MAX_SESSION_ID_BYTES = 128
    private const val MAX_PLAINTEXT_BYTES = 64 * 1024
    private const val MAX_OLM_MESSAGE_BYTES = 96 * 1024
    private const val MAX_RESPONSE_BYTES = 1024 * 1024
    private const val MESSAGE_TYPE_PRE_KEY = 0
    private const val MESSAGE_TYPE_NORMAL = 1

    fun decodeAccountMutation(encoded: ByteArray): NativeAccountMutation = decode(encoded) {
        NativeAccountMutation(
            snapshot = readSnapshot(MAX_ACCOUNT_SNAPSHOT_BYTES),
            publicState = readPublicAccount(),
        )
    }

    fun decodePublicAccount(encoded: ByteArray): NativeAccountPublicState = decode(encoded) {
        readPublicAccount()
    }

    fun decodeSnapshot(encoded: ByteArray, maximumCiphertextBytes: Int): NativeSessionSnapshot {
        if (maximumCiphertextBytes !in 1..MAX_ACCOUNT_SNAPSHOT_BYTES) {
            throw NativeSessionException("Native snapshot decode bound is invalid")
        }
        return decode(encoded) { readSnapshot(maximumCiphertextBytes) }
    }

    fun decodeOutbound(encoded: ByteArray): NativeOutboundSessionResult = decode(encoded) {
        NativeOutboundSessionResult(
            snapshot = readSnapshot(MAX_SESSION_SNAPSHOT_BYTES),
            sessionId = readUtf8(MAX_SESSION_ID_BYTES),
            initialMessage = readMessage(preKeyOnly = true),
        )
    }

    fun decodeInbound(encoded: ByteArray): NativeInboundSessionResult = decode(encoded) {
        NativeInboundSessionResult(
            accountSnapshot = readSnapshot(MAX_ACCOUNT_SNAPSHOT_BYTES),
            sessionSnapshot = readSnapshot(MAX_SESSION_SNAPSHOT_BYTES),
            sessionId = readUtf8(MAX_SESSION_ID_BYTES),
            plaintext = readSized(MAX_PLAINTEXT_BYTES, allowEmpty = true),
        )
    }

    fun decodeEncrypt(encoded: ByteArray): NativeEncryptResult = decode(encoded) {
        NativeEncryptResult(
            snapshot = readSnapshot(MAX_SESSION_SNAPSHOT_BYTES),
            message = readMessage(preKeyOnly = false),
        )
    }

    fun decodeDecrypt(encoded: ByteArray): NativeDecryptResult = decode(encoded) {
        NativeDecryptResult(
            snapshot = readSnapshot(MAX_SESSION_SNAPSHOT_BYTES),
            plaintext = readSized(MAX_PLAINTEXT_BYTES, allowEmpty = true),
        )
    }

    private fun <T> decode(encoded: ByteArray, block: Reader.() -> T): T {
        if (encoded.isEmpty() || encoded.size > MAX_RESPONSE_BYTES) {
            throw NativeSessionException("Native session response size is invalid")
        }
        try {
            Reader(encoded).use { reader ->
                if (reader.readU32() != BRIDGE_VERSION) {
                    throw NativeSessionException("Native session bridge version is unsupported")
                }
                val result = reader.block()
                if (reader.available() != 0) {
                    throw NativeSessionException("Native session response contains trailing data")
                }
                return result
            }
        } catch (error: NativeSessionException) {
            throw error
        } catch (error: Exception) {
            throw NativeSessionException("Native session response is corrupt", error)
        }
    }

    private class Reader(data: ByteArray) : AutoCloseable {
        private val input = DataInputStream(ByteArrayInputStream(data))

        fun available(): Int = input.available()

        fun readU32(): Long = input.readInt().toLong() and 0xffff_ffffL

        fun readSnapshot(maximumCiphertextBytes: Int): NativeSessionSnapshot =
            NativeSessionSnapshot(
                ciphertext = readSized(maximumCiphertextBytes, allowEmpty = false),
                pickleKey = ByteArray(PICKLE_KEY_BYTES).also(input::readFully),
            )

        fun readPublicAccount(): NativeAccountPublicState {
            val ed25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(input::readFully)
            val curve25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(input::readFully)
            val count = readBoundedCount(MAX_PUBLICATION_ONE_TIME_KEYS, "unpublished one-time-key count")
            val oneTimeKeys = List(count) {
                ByteArray(OLM_PUBLIC_KEY_BYTES).also(input::readFully)
            }
            if (oneTimeKeys.indices.any { left ->
                    (left + 1 until oneTimeKeys.size).any { right ->
                        oneTimeKeys[left].contentEquals(oneTimeKeys[right])
                    }
                }
            ) {
                throw NativeSessionException("Native account contains duplicate one-time keys")
            }
            if (oneTimeKeys.any { it.contentEquals(ed25519) || it.contentEquals(curve25519) }) {
                throw NativeSessionException("Native account one-time key aliases an identity key")
            }
            val storedCount = readU32()
            if (storedCount > MAX_STORED_ONE_TIME_KEYS.toLong() || storedCount < count.toLong()) {
                throw NativeSessionException("Native stored one-time-key count is invalid")
            }
            return NativeAccountPublicState(ed25519, curve25519, oneTimeKeys, storedCount.toInt())
        }

        fun readMessage(preKeyOnly: Boolean): NativeSessionMessage {
            val type = readU32()
            val valid = if (preKeyOnly) type == MESSAGE_TYPE_PRE_KEY.toLong() else type in MESSAGE_TYPE_PRE_KEY.toLong()..MESSAGE_TYPE_NORMAL.toLong()
            if (!valid) {
                throw NativeSessionException("Native Olm message type is invalid")
            }
            return NativeSessionMessage(
                messageType = type.toInt(),
                ciphertext = readSized(MAX_OLM_MESSAGE_BYTES, allowEmpty = false),
            )
        }

        fun readUtf8(maximumBytes: Int): String {
            val encoded = readSized(maximumBytes, allowEmpty = false)
            val decoded = String(encoded, StandardCharsets.UTF_8)
            if (!decoded.toByteArray(StandardCharsets.UTF_8).contentEquals(encoded)) {
                throw NativeSessionException("Native session id encoding is invalid")
            }
            return decoded
        }

        fun readSized(maximum: Int, allowEmpty: Boolean): ByteArray {
            val length = readU32()
            if (length > maximum.toLong() || (!allowEmpty && length == 0L) || length > available().toLong()) {
                throw NativeSessionException("Native session response field size is invalid")
            }
            return ByteArray(length.toInt()).also(input::readFully)
        }

        private fun readBoundedCount(maximum: Int, name: String): Int {
            val count = readU32()
            if (count > maximum.toLong()) {
                throw NativeSessionException("Native $name is invalid")
            }
            return count.toInt()
        }

        override fun close() = input.close()
    }
}

internal fun ByteArray.zeroize() {
    fill(0)
}
