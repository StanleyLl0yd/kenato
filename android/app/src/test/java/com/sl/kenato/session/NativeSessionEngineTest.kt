package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NativeSessionEngineTest {
    @Test
    fun accountMutationResponseDecodesExactNativeShape() {
        val encoded = message {
            u32(1)
            sized("account-pickle".toByteArray())
            bytes(0x10, 32)
            bytes(0x21, 32)
            bytes(0x22, 32)
            u32(2)
            bytes(0x31, 32)
            bytes(0x32, 32)
            u32(7)
        }

        val decoded = NativeSessionCodec.decodeAccountMutation(encoded)

        assertArrayEquals("account-pickle".toByteArray(), decoded.snapshot.ciphertext)
        assertArrayEquals(bytes(0x10, 32), decoded.snapshot.pickleKey)
        assertArrayEquals(bytes(0x21, 32), decoded.publicState.olmEd25519IdentityKey)
        assertArrayEquals(bytes(0x22, 32), decoded.publicState.olmCurve25519IdentityKey)
        assertEquals(2, decoded.publicState.unpublishedOneTimeKeys.size)
        assertArrayEquals(bytes(0x31, 32), decoded.publicState.unpublishedOneTimeKeys[0])
        assertArrayEquals(bytes(0x32, 32), decoded.publicState.unpublishedOneTimeKeys[1])
        assertEquals(7, decoded.publicState.storedOneTimeKeyCount)
    }

    @Test
    fun outboundResponseRequiresPreKeyMessageType() {
        val encoded = message {
            u32(1)
            sized("session-pickle".toByteArray())
            bytes(0x40, 32)
            sized("session-id".toByteArray())
            u32(1)
            sized("olm".toByteArray())
        }

        assertThrows(NativeSessionException::class.java) {
            NativeSessionCodec.decodeOutbound(encoded)
        }
    }

    @Test
    fun malformedVersionAndTrailingDataFailClosed() {
        val badVersion = message {
            u32(2)
            sized("state".toByteArray())
            bytes(0x20, 32)
        }
        assertThrows(NativeSessionException::class.java) {
            NativeSessionCodec.decodeSnapshot(badVersion, SessionStateCodec.MAX_ACCOUNT_SNAPSHOT_BYTES)
        }

        val trailing = message {
            u32(1)
            sized("state".toByteArray())
            bytes(0x20, 32)
            writeByte(0x7f)
        }
        assertThrows(NativeSessionException::class.java) {
            NativeSessionCodec.decodeSnapshot(trailing, SessionStateCodec.MAX_ACCOUNT_SNAPSHOT_BYTES)
        }
    }

    @Test
    fun publicAccountRejectsUnboundedOrAliasedOneTimeKeys() {
        val tooMany = message {
            u32(1)
            bytes(0x11, 32)
            bytes(0x12, 32)
            u32(51)
        }
        assertThrows(NativeSessionException::class.java) {
            NativeSessionCodec.decodePublicAccount(tooMany)
        }

        val aliased = message {
            u32(1)
            bytes(0x11, 32)
            bytes(0x12, 32)
            u32(1)
            bytes(0x11, 32)
            u32(1)
        }
        assertThrows(NativeSessionException::class.java) {
            NativeSessionCodec.decodePublicAccount(aliased)
        }
    }

    @Test
    fun decryptResponseAllowsEmptyAuthenticatedPlaintext() {
        val encoded = message {
            u32(1)
            sized("session-pickle".toByteArray())
            bytes(0x55, 32)
            sized(ByteArray(0))
        }

        val decoded = NativeSessionCodec.decodeDecrypt(encoded)

        assertEquals(0, decoded.plaintext.size)
        assertArrayEquals("session-pickle".toByteArray(), decoded.snapshot.ciphertext)
    }

    private fun message(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output -> output.block() }
            bytes.toByteArray()
        }

    private fun DataOutputStream.u32(value: Int) = writeInt(value)

    private fun DataOutputStream.sized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataOutputStream.bytes(value: Int, size: Int) = write(ByteArray(size) { value.toByte() })

    private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
}
