package com.sl.kenato.identity

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
    fun trailingSerializedDataIsRejected() {
        val encoded = IdentityStateCodec.encode(state()) + byteArrayOf(1)

        assertThrows(IdentityStateException::class.java) {
            IdentityStateCodec.decode(encoded)
        }
    }

    @Test
    fun validLookingMetadataCorruptionIsRejected() {
        val original = state()
        val encoded = IdentityStateCodec.encode(original)
        val signedTimestampLastByte =
            4 + Int.SIZE_BYTES + Int.SIZE_BYTES + original.identityPublicKey.size + Int.SIZE_BYTES + Long.SIZE_BYTES - 1
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
}
