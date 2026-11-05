package com.sl.kenato.contact

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExternalInviteLinkTest {
    private val canonical = InviteUriCodec.encode(
        M2InviteDescriptor(
            creatorIdentityId = ByteArray(CONTACT_ID_BYTES) { it.toByte() },
            token = ByteArray(INVITE_TOKEN_BYTES) { (it + 32).toByte() },
            signature = byteArrayOf(1, 2, 3),
        ),
    )

    @Test
    fun allowsOnlyExactCanonicalInvite() {
        assertEquals(canonical, ExternalInviteLink.canonicalOrNull(canonical))
    }

    @Test
    fun rejectsUntrustedOrMalformedViewData() {
        listOf(
            null,
            "",
            "https://example.org",
            canonical + "/",
            canonical + "?redirect=https://example.org",
            canonical.replace("kenato://", "KENATO://"),
            canonical.replace("kenato://", "kenato://other/"),
            "kenato://invite/v1/%2e%2e",
        ).forEach { value ->
            assertNull(ExternalInviteLink.canonicalOrNull(value))
        }
    }
}
