package com.sl.kenato

import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.contact.ShareableInvite
import com.sl.kenato.identity.IdentityBundle
import com.sl.kenato.identity.OneTimePreKey
import com.sl.kenato.identity.SignedPreKey
import com.sl.kenato.messaging.MessagingConversationDeliveryState
import com.sl.kenato.messaging.MessagingConversationDirection
import com.sl.kenato.messaging.MessagingConversationMessage
import com.sl.kenato.messaging.MessagingConversationState
import com.sl.kenato.messaging.MessagingWssState
import com.sl.kenato.session.EstablishedSession
import com.sl.kenato.session.SessionBootstrapRole
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class M45AcceptanceRuntimeTest {
    @Test
    fun serviceOriginRequiresExactHttpsOrigin() {
        assertEquals("https://example.com/", M45ServiceOrigin.parse(" https://EXAMPLE.com ").toString())
        assertEquals("https://example.com:8443/", M45ServiceOrigin.parse("https://example.com:8443/").toString())

        listOf(
            "",
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?query=1",
            "https://example.com/#fragment",
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                M45ServiceOrigin.parse(invalid)
            }
        }
    }

    @Test
    fun identityIdDecoderRequiresCanonicalThirtyTwoByteBase64Url() {
        val expected = ByteArray(32) { index -> (index + 1).toByte() }
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expected)

        assertArrayEquals(expected, decodeM45IdentityId(encoded))
        assertThrows(IllegalArgumentException::class.java) { decodeM45IdentityId("$encoded=") }
        assertThrows(IllegalArgumentException::class.java) {
            decodeM45IdentityId(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31)))
        }
    }

    @Test
    fun creatorFlowPausesTransportMaintainsBootstrapThenRestarts() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        runtime.startMessaging()
        fixture.events.clear()

        val invite = runtime.createInvite()

        assertEquals("kenato://invite/test", invite.uri)
        assertEquals(
            listOf(
                "messaging.stop",
                "identity.load",
                "contacts.publish",
                "sessions.maintain",
                "contacts.create",
                "messaging.start",
            ),
            fixture.events,
        )
        assertTrue(fixture.messaging.started)
    }

    @Test
    fun redeemerFlowPinsBeforeEstablishingOutboundSession() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        val pin = runtime.redeemAndEstablish("kenato://invite/test")

        assertArrayEquals(fixture.pin.localId, pin.localId)
        assertEquals(
            listOf(
                "identity.load",
                "contacts.redeem",
                "sessions.outbound",
            ),
            fixture.events,
        )
        assertArrayEquals(fixture.pin.localId, requireNotNull(fixture.sessions.outboundLocalContactId))
    }

    @Test
    fun creatorClaimUsesSessionClaimBoundaryNotSeparateM2Claim() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        val established = runtime.claimAndEstablish("kenato://invite/test")

        assertEquals(SessionBootstrapRole.RESPONDER, established.role)
        assertEquals(
            listOf(
                "identity.load",
                "sessions.claim",
            ),
            fixture.events,
        )
    }

    @Test
    fun failedTrustMutationLeavesMessagingStopped() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()
        fixture.sessions.failMaintain = true

        assertThrows(IllegalStateException::class.java) {
            runtime.createInvite()
        }

        assertEquals(
            listOf(
                "messaging.stop",
                "identity.load",
                "contacts.publish",
                "sessions.maintain",
            ),
            fixture.events,
        )
        assertFalse(fixture.messaging.started)
    }

    private class Fixture {
        val events = ArrayList<String>()
        val identity = FakeIdentity(events)
        val pin = PinnedContact(
            localId = ByteArray(16) { 0x11 },
            identityId = ByteArray(32) { 0x22 },
            identityPublicKey = byteArrayOf(1, 2, 3),
            pinnedAtEpochSeconds = 1_000,
        )
        val contacts = FakeContacts(events, pin)
        val sessions = FakeSessions(events, pin)
        val messaging = FakeMessaging(events)

        fun runtime() = M45AcceptanceRuntime(identity, contacts, sessions, messaging)
    }

    private class FakeIdentity(
        private val events: MutableList<String>,
    ) : M45IdentityBoundary {
        private val bundle = IdentityBundle(
            identityId = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x33 }),
            identityPublicKey = "AQ",
            signedPreKey = SignedPreKey(
                id = 1,
                publicKey = "Ag",
                signature = "Aw",
                createdAtEpochSeconds = 1,
            ),
            oneTimePreKeys = listOf(
                OneTimePreKey(
                    id = 2,
                    publicKey = "BA",
                    createdAtEpochSeconds = 1,
                ),
            ),
        )

        override fun loadOrCreate(): IdentityBundle {
            events += "identity.load"
            return bundle
        }

        override fun current(): IdentityBundle? = bundle
    }

    private class FakeContacts(
        private val events: MutableList<String>,
        private val pin: PinnedContact,
    ) : M45ContactBoundary {
        override fun publishIdentity() {
            events += "contacts.publish"
        }

        override fun createInvite(): ShareableInvite {
            events += "contacts.create"
            return ShareableInvite(
                uri = "kenato://invite/test",
                qrPayload = "kenato://invite/test",
                expiresAtEpochSeconds = 2_000,
            )
        }

        override fun redeemInvite(uri: String): PinnedContact {
            events += "contacts.redeem"
            return pin
        }

        override fun pendingInvites(): List<ShareableInvite> = emptyList()

        override fun contacts(): List<PinnedContact> = listOf(pin)
    }

    private class FakeSessions(
        private val events: MutableList<String>,
        private val pin: PinnedContact,
    ) : M45SessionBoundary {
        var failMaintain = false
        var outboundLocalContactId: ByteArray? = null

        override fun maintainBootstrap() {
            events += "sessions.maintain"
            if (failMaintain) throw IllegalStateException("simulated bootstrap failure")
        }

        override fun establishOutbound(
            inviteUri: String,
            localContactId: ByteArray,
        ): EstablishedSession {
            events += "sessions.outbound"
            outboundLocalContactId = localContactId.copyOf()
            return EstablishedSession(
                localContactId = localContactId.copyOf(),
                peerIdentityId = pin.identityId.copyOf(),
                localAccountGeneration = 1,
                peerAccountGeneration = 1,
                role = SessionBootstrapRole.INITIATOR,
            )
        }

        override fun claimInbound(inviteUri: String): EstablishedSession {
            events += "sessions.claim"
            return EstablishedSession(
                localContactId = pin.localId.copyOf(),
                peerIdentityId = pin.identityId.copyOf(),
                localAccountGeneration = 1,
                peerAccountGeneration = 1,
                role = SessionBootstrapRole.RESPONDER,
            )
        }
    }

    private class FakeMessaging(
        private val events: MutableList<String>,
    ) : M45MessagingBoundary {
        var started = false

        override fun start() {
            events += "messaging.start"
            started = true
        }

        override fun stop() {
            events += "messaging.stop"
            started = false
        }

        override fun currentState(): MessagingWssState =
            if (started) MessagingWssState.AUTHENTICATED else MessagingWssState.STOPPED

        override fun sendText(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            text: String,
        ): MessagingConversationMessage = MessagingConversationMessage(
            messageId = "message",
            direction = MessagingConversationDirection.OUTBOUND,
            deliveryState = MessagingConversationDeliveryState.PENDING_SEND,
            sentAtEpochSeconds = 1,
            expiresAtEpochSeconds = 2,
            text = text,
        )

        override fun conversation(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
        ): MessagingConversationState = MessagingConversationState(
            peerIdentityId = "peer",
            messages = emptyList(),
        )

        override fun close() {
            started = false
        }
    }
}
