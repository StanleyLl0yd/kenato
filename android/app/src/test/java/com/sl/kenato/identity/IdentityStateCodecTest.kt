package com.sl.kenato.identity

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class IdentityStateCodecTest {
    @Test
    fun stateRoundTripsWithoutChangingKeyMaterial() {
        val original = state()

        val decoded = IdentityStateCodec.decode(IdentityStateCodec.encode(original))

        assertArrayEquals(original.identityPublicKey, decoded.identityPublicKey)
        assertPreKeyEquals(original.signedPreKey, decoded.signedPreKey)
        assertEquals(original.previousSignedPreKey, decoded.previousSignedPreKey)
        assertEquals(original.oneTimePreKeys.size, decoded.oneTimePreKeys.size)
        original.oneTimePreKeys.zip(decoded.oneTimePreKeys).forEach { (expected, actual) ->
            assertPreKeyEquals(expected, actual)
        }
        assertEquals(original.nextPreKeyId, decoded.nextPreKeyId)
    }

    @Test
    fun trailingSerializedDataIsRejectedEvenWithValidChecksum() {
        val encoded = IdentityStateCodec.encode(state())
        val payload = encoded.copyOfRange(0, encoded.size - SHA256_BYTES) + byteArrayOf(1)
        val malformed = payload + MessageDigest.getInstance(SHA256).digest(payload)

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.decode(malformed)
        }
    }

    @Test
    fun nonCanonicalBooleanIsRejectedEvenWithValidChecksum() {
        val original = state()
        val malformed = IdentityStateCodec.encode(original).withValidChecksumMutation { payload ->
            val signaturePresenceOffset =
                MAGIC_BYTES +
                    Int.SIZE_BYTES +
                    Int.SIZE_BYTES + original.identityPublicKey.size +
                    Int.SIZE_BYTES +
                    Long.SIZE_BYTES +
                    Int.SIZE_BYTES + original.signedPreKey.publicKey.size +
                    Int.SIZE_BYTES + original.signedPreKey.encryptedPrivateKey.size
            payload[signaturePresenceOffset] = 2
        }

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.decode(malformed)
        }
    }

    @Test
    fun validLookingMetadataCorruptionIsRejected() {
        val original = state()
        val encoded = IdentityStateCodec.encode(original)
        val signedTimestampLastByte =
            MAGIC_BYTES + Int.SIZE_BYTES + Int.SIZE_BYTES + original.identityPublicKey.size + Int.SIZE_BYTES + Long.SIZE_BYTES - 1
        encoded[signedTimestampLastByte] = (encoded[signedTimestampLastByte].toInt() xor 1).toByte()

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.decode(encoded)
        }
    }

    @Test
    fun duplicatePrekeyIdsAreRejected() {
        val original = state()
        val duplicate = original.copy(
            oneTimePreKeys = listOf(preKey(id = original.signedPreKey.id, signed = false)),
            nextPreKeyId = 3,
        )

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.encode(duplicate)
        }
    }

    @Test
    fun oneTimePrekeyCountIsHardBounded() {
        val tooMany = (1..IdentityStateCodec.MAX_ONE_TIME_PREKEYS + 1).map { index ->
            preKey(id = index + 1, signed = false)
        }
        val original = state().copy(
            oneTimePreKeys = tooMany,
            nextPreKeyId = IdentityStateCodec.MAX_ONE_TIME_PREKEYS + 3,
        )

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.encode(original)
        }
    }

    @Test
    fun aggregateSerializedStateSizeIsHardBounded() {
        val largePool = (1..IdentityStateCodec.MAX_ONE_TIME_PREKEYS).map { index ->
            preKey(id = index + 1, signed = false).copy(
                encryptedPrivateKey = ByteArray(IdentityStateCodec.MAX_ENCRYPTED_PRIVATE_KEY_BYTES) { 1 },
            )
        }
        val original = state().copy(
            oneTimePreKeys = largePool,
            nextPreKeyId = IdentityStateCodec.MAX_ONE_TIME_PREKEYS + 2,
        )

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.encode(original)
        }
    }

    @Test
    fun oversizedSerializedInputIsRejectedBeforeParsing() {
        val oversized = ByteArray(IdentityStateCodec.MAX_STATE_BYTES + 1)

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.decode(oversized)
        }
    }

    @Test
    fun nextPrekeyIdMustBeStrictlyGreaterThanAllPersistedIds() {
        val original = state().copy(nextPreKeyId = 2)

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.encode(original)
        }
    }

    private fun state(): LocalIdentityState = LocalIdentityState(
        identityPublicKey = byteArrayOf(1, 2, 3),
        signedPreKey = preKey(id = 1, signed = true),
        previousSignedPreKey = null,
        oneTimePreKeys = listOf(preKey(id = 2, signed = false)),
        nextPreKeyId = 3,
    )

    private fun preKey(id: Int, signed: Boolean): StoredPreKey = StoredPreKey(
        id = id,
        createdAtEpochSeconds = 1_788_973_200L,
        publicKey = byteArrayOf(id.toByte(), 1),
        encryptedPrivateKey = byteArrayOf(id.toByte(), 2),
        signature = if (signed) byteArrayOf(id.toByte(), 3) else null,
    )

    private fun ByteArray.withValidChecksumMutation(mutate: (ByteArray) -> Unit): ByteArray {
        val payloadLength = size - SHA256_BYTES
        val result = copyOf()
        mutate(result)
        val digest = MessageDigest.getInstance(SHA256).run {
            update(result, 0, payloadLength)
            digest()
        }
        digest.copyInto(result, destinationOffset = payloadLength)
        return result
    }

    private fun assertPreKeyEquals(expected: StoredPreKey, actual: StoredPreKey) {
        assertEquals(expected.id, actual.id)
        assertEquals(expected.createdAtEpochSeconds, actual.createdAtEpochSeconds)
        assertArrayEquals(expected.publicKey, actual.publicKey)
        assertArrayEquals(expected.encryptedPrivateKey, actual.encryptedPrivateKey)
        if (expected.signature == null) {
            assertEquals(null, actual.signature)
        } else {
            assertArrayEquals(expected.signature, actual.signature)
        }
    }

    companion object {
        private const val MAGIC_BYTES = 4
        private const val SHA256 = "SHA-256"
        private const val SHA256_BYTES = 32
    }
}
