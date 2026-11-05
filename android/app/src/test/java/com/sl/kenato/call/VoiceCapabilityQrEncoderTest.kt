package com.sl.kenato.call

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class VoiceCapabilityQrEncoderTest {
    @Test
    fun rendersLocallyGeneratedChallengeWithoutChangingThePayload() {
        val challenge = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(
                ownerIdentityId = ByteArray(32) { (it + 1).toByte() },
                peerIdentityId = ByteArray(32) { (it + 33).toByte() },
                challenge = ByteArray(VoiceCapabilityProofWire.CHALLENGE_BYTES) { (it + 65).toByte() },
                expiresAtEpochSeconds = 1_800_000_000L,
            ),
        )
        val qr = VoiceCapabilityQrEncoder.encode(challenge)
        assertEquals(512, qr.width)
        assertEquals(512, qr.height)
        assertTrue((0 until qr.height).any { y -> (0 until qr.width).any { x -> qr[x, y] } })
    }

    @Test
    fun rendersSupportedProofTextWithoutTreatingItAsApproval() {
        val text = "kenato-voice-v2:proof:" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(230) { (it + 1).toByte() })
        assertEquals(512, VoiceCapabilityQrEncoder.encode(text).width)
    }

    @Test
    fun rejectsOtherSchemesMalformedEncodingAndOversize() {
        listOf(
            "",
            "https://example.org",
            "kenato://invite/v1/abc",
            "kenato-voice-v2:proof:A",
            "kenato-voice-v2:proof:AA=",
            "kenato-voice-v2:challenge:invalid+characters",
            "kenato-voice-v2:proof:" + "a".repeat(512),
        ).forEach { bad ->
            assertThrows(VoiceCapabilityQrException::class.java) {
                VoiceCapabilityQrEncoder.encode(bad)
            }
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrEncoder.encode("kenato-voice-v2:proof:AA", 100)
        }
    }
}
