package com.sl.kenato.call

import com.google.zxing.BarcodeFormat
import com.sl.kenato.contact.CONTACT_ID_BYTES
import com.sl.kenato.contact.INVITE_TOKEN_BYTES
import com.sl.kenato.contact.InviteUriCodec
import com.sl.kenato.contact.M2InviteDescriptor
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class VoiceCapabilityQrPhotoDecoderTest {
    private fun bitmap(record: String): IntArray {
        val matrix = QRCodeWriter().encode(record, BarcodeFormat.QR_CODE, 512, 512)
        return IntArray(512 * 512) { i ->
            if (matrix[i % 512, i / 512]) 0xff000000.toInt() else 0xffffffff.toInt()
        }
    }

    @Test
    fun importsChallengeTextButDoesNotApproveOrMutateConsent() {
        val record = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(
                ownerIdentityId = ByteArray(32) { (it + 1).toByte() },
                peerIdentityId = ByteArray(32) { (it + 33).toByte() },
                challenge = ByteArray(VoiceCapabilityProofWire.CHALLENGE_BYTES) { (it + 65).toByte() },
                expiresAtEpochSeconds = 1_800_000_000L,
            ),
        )
        assertEquals(
            record,
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, bitmap(record), VoiceCapabilityQrPhotoKind.CHALLENGE,
            ),
        )
    }

    @Test
    fun rejectsWrongKindAndUnrelatedQrBeforeUiImport() {
        val proof = "kenato-voice-v2:proof:" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(220) { it.toByte() })
        assertEquals(
            proof,
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, bitmap(proof), VoiceCapabilityQrPhotoKind.PROOF,
            ),
        )
        listOf(proof, "https://example.org", "kenato://invite/v1/test").forEach { record ->
            assertThrows(VoiceCapabilityQrException::class.java) {
                VoiceCapabilityQrPhotoDecoder.decode(
                    512, 512, bitmap(record), VoiceCapabilityQrPhotoKind.CHALLENGE,
                )
            }
        }
    }

    @Test
    fun importsOnlyCanonicalM2InviteQrWithoutRedeemingBearerToken() {
        val uri = InviteUriCodec.encode(
            M2InviteDescriptor(
                creatorIdentityId = ByteArray(CONTACT_ID_BYTES) { (it + 1).toByte() },
                token = ByteArray(INVITE_TOKEN_BYTES) { (it + 33).toByte() },
                signature = byteArrayOf(1, 2, 3, 4),
            ),
        )
        assertEquals(
            uri,
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, bitmap(uri), VoiceCapabilityQrPhotoKind.INVITE,
            ),
        )
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, bitmap(uri), VoiceCapabilityQrPhotoKind.PROOF,
            )
        }
        listOf("https://example.org", "kenato-voice-v2:proof:AAAA").forEach { invalid ->
            assertThrows(VoiceCapabilityQrException::class.java) {
                VoiceCapabilityQrPhotoDecoder.decode(
                    512, 512, bitmap(invalid), VoiceCapabilityQrPhotoKind.INVITE,
                )
            }
        }
    }

    @Test
    fun rejectsInvalidEncodingAndHostileBitmapBounds() {
        val malformed = "kenato-voice-v2:challenge:AA="
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, bitmap(malformed), VoiceCapabilityQrPhotoKind.CHALLENGE,
            )
        }
        val valid = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(
                ownerIdentityId = ByteArray(32) { (it + 1).toByte() },
                peerIdentityId = ByteArray(32) { (it + 33).toByte() },
                challenge = ByteArray(VoiceCapabilityProofWire.CHALLENGE_BYTES) { (it + 65).toByte() },
                expiresAtEpochSeconds = 1_800_000_000L,
            ),
        )
        val image = bitmap(valid)
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrPhotoDecoder.decode(
                1537, 512, image, VoiceCapabilityQrPhotoKind.CHALLENGE,
            )
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, image.copyOf(1), VoiceCapabilityQrPhotoKind.CHALLENGE,
            )
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrPhotoDecoder.decode(
                512, 512, IntArray(512 * 512) { -1 }, VoiceCapabilityQrPhotoKind.CHALLENGE,
            )
        }
    }
}
