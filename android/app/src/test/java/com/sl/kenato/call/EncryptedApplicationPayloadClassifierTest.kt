package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingPlaintext
import com.sl.kenato.messaging.MessagingWire
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedApplicationPayloadClassifierTest {
    @Test
    fun canonicalTextStillDecodesExactlyAsM4() {
        val (wire, envelope) = text()
        val value = EncryptedApplicationPayloadClassifier.classify(wire, envelope, NOW)
        assertTrue(value is EncryptedApplicationPayload.Text)
        assertEquals("text-only ordinary message", (value as EncryptedApplicationPayload.Text).plaintext.text)
    }

    @Test
    fun encryptedVoiceIsNeverReturnedAsUserChat() {
        val (wire, envelope) = voice()
        val value = EncryptedApplicationPayloadClassifier.classify(wire, envelope, NOW)
        assertTrue(value is EncryptedApplicationPayload.Voice)
        assertEquals(VoiceSignalKind.OFFER, (value as EncryptedApplicationPayload.Voice).signal.kind)
    }

    @Test
    fun unknownTruncatedOrNoncanonicalApplicationTagsFailClosed() {
        val (wire, envelope) = voice()
        for (invalid in listOf(
            byteArrayOf(),
            byteArrayOf(0x08),
            byteArrayOf(0x08, 0x03) + wire.copyOfRange(2, wire.size),
            byteArrayOf(0x08, 0x82.toByte(), 0x00) + wire.copyOfRange(2, wire.size),
            wire + byteArrayOf(0x50, 0x01),
        )) {
            assertThrows(EncryptedApplicationPayloadException::class.java) {
                EncryptedApplicationPayloadClassifier.classify(invalid, envelope, NOW)
            }
        }
    }

    @Test
    fun innerOuterIdentityAndExpirySubstitutionFailForBothTypes() {
        for ((encoded, original) in listOf(text(), voice())) {
            val mismatches = listOf(
                MessagingEnvelope(PEER, ByteArray(32) { 9 }, MESSAGE, byteArrayOf(1), original.expiresAtEpochSeconds),
                MessagingEnvelope(ByteArray(32) { 8 }, OWNER, MESSAGE, byteArrayOf(1), original.expiresAtEpochSeconds),
                MessagingEnvelope(PEER, OWNER, ByteArray(16) { 7 }, byteArrayOf(1), original.expiresAtEpochSeconds),
                MessagingEnvelope(PEER, OWNER, MESSAGE, byteArrayOf(1), original.expiresAtEpochSeconds + 1),
            )
            for (mismatch in mismatches) {
                assertThrows(EncryptedApplicationPayloadException::class.java) {
                    EncryptedApplicationPayloadClassifier.classify(encoded, mismatch, NOW)
                }
            }
        }
    }

    @Test
    fun voiceSignalingRejectsExpiredRingingEvenIfTheCiphertextWasAuthenticated() {
        val (wire, envelope) = voice()
        assertThrows(EncryptedApplicationPayloadException::class.java) {
            EncryptedApplicationPayloadClassifier.classify(wire, envelope, NOW + 61)
        }
    }

    private fun text(): Pair<ByteArray, MessagingEnvelope> {
        val plaintext = MessagingPlaintext(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = MESSAGE,
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = NOW + 60,
            text = "text-only ordinary message",
        )
        return MessagingWire.encodePlaintext(plaintext) to envelope()
    }

    private fun voice(): Pair<ByteArray, MessagingEnvelope> {
        val plaintext = VoiceSignalPlaintext(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = MESSAGE,
            callId = ByteArray(16) { 4 },
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = NOW + 60,
            kind = VoiceSignalKind.OFFER,
            payload = "v=0\r\n".toByteArray(),
        )
        return VoiceSignalingWire.encode(plaintext) to envelope()
    }

    private fun envelope() = MessagingEnvelope(
        senderIdentityId = PEER,
        recipientIdentityId = OWNER,
        messageId = MESSAGE,
        ciphertext = byteArrayOf(1, 2, 3),
        expiresAtEpochSeconds = NOW + 60,
    )

    companion object {
        private const val NOW = 1_780_000_000L
        private val OWNER = ByteArray(32) { 1 }
        private val PEER = ByteArray(32) { 2 }
        private val MESSAGE = ByteArray(16) { 3 }
    }
}
