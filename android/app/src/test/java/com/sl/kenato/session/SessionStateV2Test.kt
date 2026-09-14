package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionStateV2Test {
    @Test
    fun legacyV1StateDecodesWithEmptyHandoffJournalAndMigratesOnEncode() {
        val original = sampleState()
        val legacy = encodeLegacyV1(original)

        val decoded = SessionStateCodec.decode(legacy)
        assertArrayEquals(original.ownerIdentityId, decoded.ownerIdentityId)
        assertEquals(original.account.accountGeneration, decoded.account.accountGeneration)
        assertEquals("session-1", decoded.sessions.single().sessionId)
        assertTrue(decoded.messageHandoffs.isEmpty())

        val migrated = SessionStateCodec.decode(SessionStateCodec.encode(decoded))
        assertArrayEquals(original.ownerIdentityId, migrated.ownerIdentityId)
        assertEquals("session-1", migrated.sessions.single().sessionId)
        assertTrue(migrated.messageHandoffs.isEmpty())
    }

    @Test
    fun v2HandoffJournalRoundTripsExactRecoverableBytes() {
        val state = sampleState()
        val handoff = sampleHandoff(1, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND)
        val decoded = SessionStateCodec.decode(
            SessionStateCodec.encode(state.copy(messageHandoffs = listOf(handoff))),
        )

        val actual = decoded.messageHandoffs.single()
        assertArrayEquals(handoff.localContactId, actual.localContactId)
        assertArrayEquals(handoff.peerIdentityId, actual.peerIdentityId)
        assertArrayEquals(handoff.messageId, actual.messageId)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, actual.direction)
        assertArrayEquals(handoff.encodedPlaintext, actual.encodedPlaintext)
        assertArrayEquals(handoff.encodedEnvelope, actual.encodedEnvelope)
    }

    @Test
    fun duplicateHandoffIdentityFailsClosed() {
        val state = sampleState()
        val first = sampleHandoff(1, SessionStateCodec.HANDOFF_DIRECTION_INBOUND)
        val duplicate = first.copy(encodedEnvelope = "different-envelope".toByteArray())

        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(state.copy(messageHandoffs = listOf(first, duplicate)))
        }
    }

    @Test
    fun handoffCountAndPayloadBytesAreBounded() {
        val state = sampleState()
        val tooMany = (0..SessionStateCodec.MAX_MESSAGE_HANDOFFS).map { index ->
            sampleHandoff(index + 1, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND)
        }
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(state.copy(messageHandoffs = tooMany))
        }

        val payloadHeavy = (0 until SessionStateCodec.MAX_MESSAGE_HANDOFFS).map { index ->
            sampleHandoff(index + 1, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND).copy(
                encodedPlaintext = byteArrayOf(1),
                encodedEnvelope = ByteArray(SessionStateCodec.MAX_HANDOFF_ENVELOPE_BYTES) { 0x55.toByte() },
            )
        }
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(state.copy(messageHandoffs = payloadHeavy))
        }
    }

    @Test
    fun handoffMustBelongToActiveReadySession() {
        val state = sampleState()
        val wrongPeer = sampleHandoff(1, SessionStateCodec.HANDOFF_DIRECTION_INBOUND).copy(
            peerIdentityId = bytes(0x66, SessionStateCodec.IDENTITY_ID_BYTES),
        )
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(state.copy(messageHandoffs = listOf(wrongPeer)))
        }

        val pendingSession = state.sessions.single().copy(
            pendingInit = PendingSessionInit(
                inviteTokenHash = bytes(0x70, SessionStateCodec.INVITE_TOKEN_HASH_BYTES),
                creatorAccountGeneration = state.sessions.single().peerAccountGeneration,
                creatorOneTimePreKeyId = 1,
                redeemerAccountGeneration = state.account.accountGeneration,
                messageType = SESSION_OLM_MESSAGE_PRE_KEY,
                olmMessage = byteArrayOf(1),
            ),
        )
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.encode(
                state.copy(
                    sessions = listOf(pendingSession),
                    messageHandoffs = listOf(sampleHandoff(1, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND)),
                ),
            )
        }
    }

    private fun sampleState(): SessionState = SessionState(
        ownerIdentityId = bytes(0x11, SessionStateCodec.IDENTITY_ID_BYTES),
        account = SessionAccountState(
            accountGeneration = 1,
            publicationRevision = 0,
            nextOneTimeKeyId = 1,
            olmEd25519IdentityKey = bytes(0x21, SessionStateCodec.OLM_PUBLIC_KEY_BYTES),
            olmCurve25519IdentityKey = bytes(0x22, SessionStateCodec.OLM_PUBLIC_KEY_BYTES),
            oneTimeKeys = emptyList(),
            snapshot = WrappedSessionSnapshot(
                ciphertext = "account-pickle".toByteArray(),
                wrappedPickleKey = bytes(0x31, 32),
            ),
        ),
        sessions = listOf(
            PersistedSession(
                localContactId = bytes(0x41, SessionStateCodec.LOCAL_CONTACT_ID_BYTES),
                peerIdentityId = bytes(0x42, SessionStateCodec.IDENTITY_ID_BYTES),
                peerAccountGeneration = 2,
                peerOlmEd25519IdentityKey = bytes(0x43, SessionStateCodec.OLM_PUBLIC_KEY_BYTES),
                peerOlmCurve25519IdentityKey = bytes(0x44, SessionStateCodec.OLM_PUBLIC_KEY_BYTES),
                sessionId = "session-1",
                initiator = true,
                snapshot = WrappedSessionSnapshot(
                    ciphertext = "session-pickle".toByteArray(),
                    wrappedPickleKey = bytes(0x45, 32),
                ),
                pendingInit = null,
            ),
        ),
    )

    private fun sampleHandoff(index: Int, direction: Int): SessionMessageHandoff {
        val state = sampleState()
        val messageId = ByteArray(SessionStateCodec.MESSAGE_ID_BYTES)
        messageId[0] = ((index ushr 8) and 0xff).toByte()
        messageId[1] = (index and 0xff).toByte()
        if (messageId.all { it == 0.toByte() }) messageId[0] = 1
        return SessionMessageHandoff(
            localContactId = state.sessions.single().localContactId.copyOf(),
            peerIdentityId = state.sessions.single().peerIdentityId.copyOf(),
            messageId = messageId,
            direction = direction,
            encodedPlaintext = "plaintext-$index".toByteArray(),
            encodedEnvelope = "envelope-$index".toByteArray(),
        )
    }

    private fun encodeLegacyV1(state: SessionState): ByteArray {
        val payload = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), '3'.code.toByte()))
                output.writeInt(1)
                output.write(state.ownerIdentityId)
                val account = state.account
                output.writeLong(account.accountGeneration)
                output.writeLong(account.publicationRevision)
                output.writeLong(account.nextOneTimeKeyId)
                output.write(account.olmEd25519IdentityKey)
                output.write(account.olmCurve25519IdentityKey)
                output.writeInt(account.oneTimeKeys.size)
                account.oneTimeKeys.forEach { key ->
                    output.writeLong(key.id)
                    output.write(key.publicKey)
                }
                output.writeSized(account.snapshot.ciphertext)
                output.writeSized(account.snapshot.wrappedPickleKey)
                output.writeInt(state.sessions.size)
                state.sessions.forEach { session ->
                    output.write(session.localContactId)
                    output.write(session.peerIdentityId)
                    output.writeLong(session.peerAccountGeneration)
                    output.write(session.peerOlmEd25519IdentityKey)
                    output.write(session.peerOlmCurve25519IdentityKey)
                    output.writeStringV1(session.sessionId)
                    output.writeByte(if (session.initiator) 1 else 0)
                    output.writeSized(session.snapshot.ciphertext)
                    output.writeSized(session.snapshot.wrappedPickleKey)
                    output.writeByte(0)
                }
            }
            bytes.toByteArray()
        }
        return payload + MessageDigest.getInstance("SHA-256").digest(payload)
    }

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataOutputStream.writeStringV1(value: String) {
        writeSized(value.toByteArray(StandardCharsets.UTF_8))
    }

    private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
}
