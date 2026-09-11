package com.sl.kenato.session

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionStateTest {
    @Test
    fun stateRoundTripPreservesBoundedAccountAndSessionMetadata() {
        val original = sampleState()

        val decoded = SessionStateCodec.decode(SessionStateCodec.encode(original))

        assertArrayEquals(original.ownerIdentityId, decoded.ownerIdentityId)
        assertEquals(original.account.accountGeneration, decoded.account.accountGeneration)
        assertEquals(original.account.publicationRevision, decoded.account.publicationRevision)
        assertEquals(original.account.nextOneTimeKeyId, decoded.account.nextOneTimeKeyId)
        assertArrayEquals(original.account.olmEd25519IdentityKey, decoded.account.olmEd25519IdentityKey)
        assertArrayEquals(original.account.olmCurve25519IdentityKey, decoded.account.olmCurve25519IdentityKey)
        assertEquals(2, decoded.account.oneTimeKeys.size)
        assertArrayEquals(original.account.snapshot.ciphertext, decoded.account.snapshot.ciphertext)
        assertArrayEquals(original.account.snapshot.wrappedPickleKey, decoded.account.snapshot.wrappedPickleKey)
        assertEquals(1, decoded.sessions.size)
        val session = decoded.sessions.single()
        assertArrayEquals(original.sessions.single().localContactId, session.localContactId)
        assertArrayEquals(original.sessions.single().peerIdentityId, session.peerIdentityId)
        assertEquals("session-1", session.sessionId)
        assertTrue(session.initiator)
        assertArrayEquals(original.sessions.single().snapshot.ciphertext, session.snapshot.ciphertext)
    }

    @Test
    fun corruptedStateFailsClosedBeforeParsing() {
        val encoded = SessionStateCodec.encode(sampleState())
        encoded[encoded.lastIndex - 40] = (encoded[encoded.lastIndex - 40].toInt() xor 0x01).toByte()

        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.decode(encoded)
        }
    }

    @Test
    fun duplicateActiveSessionForContactIsRejected() {
        val original = sampleState()
        val duplicate = original.sessions.single().copy(
            peerIdentityId = bytes(0x55, SessionStateCodec.IDENTITY_ID_BYTES),
            sessionId = "session-2",
        )

        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(original.copy(sessions = listOf(original.sessions.single(), duplicate)))
        }
    }

    @Test
    fun oneTimeKeyIdsMustBeStrictlyIncreasingAndBelowNextId() {
        val original = sampleState()
        val invalidAccount = original.account.copy(
            oneTimeKeys = listOf(
                TrackedSessionOneTimeKey(2, bytes(0x41, 32)),
                TrackedSessionOneTimeKey(2, bytes(0x42, 32)),
            ),
        )

        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(original.copy(account = invalidAccount))
        }
    }

    @Test
    fun pickleAadBindsAccountAndPeerSessionContext() {
        val owner = bytes(0x11, 32)
        val contact = bytes(0x22, 16)
        val peer = bytes(0x33, 32)

        val accountA = SessionKeyAad.account(owner, 1)
        val accountB = SessionKeyAad.account(owner, 2)
        val sessionA = SessionKeyAad.session(owner, 1, contact, peer, 7, "session-1")
        val sessionB = SessionKeyAad.session(owner, 1, contact, peer, 8, "session-1")

        assertFalse(accountA.contentEquals(accountB))
        assertFalse(sessionA.contentEquals(sessionB))
        assertArrayEquals(sessionA, SessionKeyAad.session(owner, 1, contact, peer, 7, "session-1"))
    }

    @Test
    fun snapshotAndSessionBoundsFailClosed() {
        val original = sampleState()
        val oversizedSnapshot = original.account.snapshot.copy(
            ciphertext = ByteArray(SessionStateCodec.MAX_ACCOUNT_SNAPSHOT_BYTES + 1),
        )
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(original.copy(account = original.account.copy(snapshot = oversizedSnapshot)))
        }

        val badSession = original.sessions.single().copy(sessionId = "x".repeat(SessionStateCodec.MAX_SESSION_ID_BYTES + 1))
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(original.copy(sessions = listOf(badSession)))
        }
    }

    private fun sampleState(): SessionState = SessionState(
        ownerIdentityId = bytes(0x11, 32),
        account = SessionAccountState(
            accountGeneration = 1,
            publicationRevision = 1,
            nextOneTimeKeyId = 3,
            olmEd25519IdentityKey = bytes(0x21, 32),
            olmCurve25519IdentityKey = bytes(0x22, 32),
            oneTimeKeys = listOf(
                TrackedSessionOneTimeKey(1, bytes(0x31, 32)),
                TrackedSessionOneTimeKey(2, bytes(0x32, 32)),
            ),
            snapshot = WrappedSessionSnapshot(
                ciphertext = "account-pickle".toByteArray(),
                wrappedPickleKey = bytes(0x44, 64),
            ),
        ),
        sessions = listOf(
            PersistedSession(
                localContactId = bytes(0x51, 16),
                peerIdentityId = bytes(0x52, 32),
                peerAccountGeneration = 7,
                peerOlmEd25519IdentityKey = bytes(0x61, 32),
                peerOlmCurve25519IdentityKey = bytes(0x62, 32),
                sessionId = "session-1",
                initiator = true,
                snapshot = WrappedSessionSnapshot(
                    ciphertext = "session-pickle".toByteArray(),
                    wrappedPickleKey = bytes(0x71, 64),
                ),
            ),
        ),
    )

    private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
}
