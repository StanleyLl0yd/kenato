package com.sl.kenato.session

import com.sl.kenato.contact.ContactCanonical
import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.InviteUriCodec
import com.sl.kenato.contact.M2InviteDescriptor
import com.sl.kenato.contact.M2PublicIdentityBundle
import com.sl.kenato.contact.M2SignedPreKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionCoordinatorTest {
    @Test
    fun workerThreadGuardFailsBeforeIdentityOrStateAccess() {
        val local = TestIdentity()
        val sessions = FakeSessions(pendingState(local.identityId, TestIdentity().identityId, ByteArray(32) { 0x44 }))
        val coordinator = SessionCoordinator(
            identity = local,
            contacts = RejectingContacts,
            sessions = sessions,
            transport = FakeTransport(),
            threadGuard = SessionThreadGuard { throw SessionStateException("worker required") },
            clock = SessionClock { 1_000 },
        )

        assertThrows(SessionStateException::class.java) {
            coordinator.maintainBootstrap()
        }
        assertEquals(0, local.currentCalls)
        assertEquals(0, sessions.loadCalls)
    }

    @Test
    fun failedSubmitKeepsPersistedFrameAndRestartRetriesItExactly() {
        val fixture = PendingOutboundFixture()
        fixture.transport.failSubmit = true

        assertThrows(SessionTransportException::class.java) {
            fixture.newCoordinator().establishOutbound(fixture.inviteUri, fixture.localContactId)
        }
        assertEquals(1, fixture.transport.submitCalls)
        assertEquals(0, fixture.sessions.clearCalls)
        assertEquals(1, fixture.sessions.pendingReads)
        assertEquals(0, fixture.transport.reserveCalls)
        assertTrue(fixture.sessions.state.sessions.single().pendingInit != null)
        val firstRequest = fixture.transport.lastSubmit!!
        assertArrayEquals(fixture.frame.ciphertext, firstRequest.olmMessage)

        fixture.transport.failSubmit = false
        val established = fixture.newCoordinator().establishOutbound(fixture.inviteUri, fixture.localContactId)

        assertEquals(SessionBootstrapRole.INITIATOR, established.role)
        assertEquals(2, fixture.transport.submitCalls)
        assertEquals(1, fixture.sessions.clearCalls)
        assertEquals(2, fixture.sessions.pendingReads)
        assertEquals(0, fixture.transport.reserveCalls)
        assertEquals(null, fixture.sessions.state.sessions.single().pendingInit)
        assertArrayEquals(firstRequest.olmMessage, fixture.transport.lastSubmit!!.olmMessage)
        assertEquals(firstRequest.olmMessageType, fixture.transport.lastSubmit!!.olmMessageType)
        assertEquals(firstRequest.creatorAccountGeneration, fixture.transport.lastSubmit!!.creatorAccountGeneration)
        assertEquals(firstRequest.creatorOneTimePreKeyId, fixture.transport.lastSubmit!!.creatorOneTimePreKeyId)
        assertEquals(firstRequest.redeemerAccountGeneration, fixture.transport.lastSubmit!!.redeemerAccountGeneration)
    }

    @Test
    fun cancellationRaisedBySuccessfulSubmitDoesNotSkipDurablePendingClear() {
        val fixture = PendingOutboundFixture()
        var cancelled = false
        fixture.transport.afterSubmit = { cancelled = true }

        val established = fixture.newCoordinator().establishOutbound(
            inviteUri = fixture.inviteUri,
            localContactId = fixture.localContactId,
            cancellation = SessionCancellation { cancelled },
        )

        assertEquals(SessionBootstrapRole.INITIATOR, established.role)
        assertEquals(1, fixture.transport.submitCalls)
        assertEquals(1, fixture.sessions.clearCalls)
        assertEquals(null, fixture.sessions.state.sessions.single().pendingInit)
        assertTrue(cancelled)
    }

    @Test
    fun cancellationBeforeSubmitLeavesExactPendingFrameForRestart() {
        val fixture = PendingOutboundFixture()
        var checks = 0
        val cancellation = SessionCancellation {
            checks += 1
            checks >= 3
        }

        assertThrows(SessionOperationCancelledException::class.java) {
            fixture.newCoordinator().establishOutbound(
                fixture.inviteUri,
                fixture.localContactId,
                cancellation,
            )
        }

        assertEquals(0, fixture.transport.submitCalls)
        assertEquals(0, fixture.sessions.clearCalls)
        assertTrue(fixture.sessions.state.sessions.single().pendingInit != null)
        assertArrayEquals(fixture.frame.ciphertext, fixture.sessions.state.sessions.single().pendingInit!!.olmMessage)
    }

    @Test
    fun cancellationRaisedAfterDestructiveClaimStillCommitsVerifiedPinAndInboundSession() {
        val fixture = InboundClaimFixture()
        var cancelled = false
        fixture.transport.afterClaim = { cancelled = true }

        val established = fixture.newCoordinator().claimInbound(
            inviteUri = fixture.inviteUri,
            cancellation = SessionCancellation { cancelled },
        )

        assertTrue(cancelled)
        assertEquals(SessionBootstrapRole.RESPONDER, established.role)
        assertEquals(1, fixture.transport.claimCalls)
        assertEquals(1, fixture.contacts.commitCalls)
        assertEquals(1, fixture.sessions.inboundCalls)
        assertEquals(1, fixture.sessions.state.sessions.size)
        assertFalse(fixture.sessions.state.sessions.single().initiator)
        assertArrayEquals(fixture.redeemer.identityId, fixture.sessions.state.sessions.single().peerIdentityId)
        assertTrue(fixture.sessions.state.account.oneTimeKeys.none { it.id == fixture.creatorOneTimeKey.id })
    }

    @Test
    fun substitutedCreatorOneTimeKeyFailsBeforePinOrInboundStateCommit() {
        val fixture = InboundClaimFixture()
        fixture.transport.claimResponse = fixture.claimResponse.copy(
            creatorOneTimePreKey = fixture.creatorOneTimeKey.copy(publicKey = ByteArray(32) { 0x30 }),
        )

        assertThrows(SessionStateException::class.java) {
            fixture.newCoordinator().claimInbound(fixture.inviteUri)
        }

        assertEquals(1, fixture.transport.claimCalls)
        assertEquals(0, fixture.contacts.commitCalls)
        assertEquals(0, fixture.sessions.inboundCalls)
        assertTrue(fixture.sessions.state.sessions.isEmpty())
        assertTrue(fixture.sessions.state.account.oneTimeKeys.any { it.id == fixture.creatorOneTimeKey.id })
    }

    @Test
    fun failedCreatorContactCommitAfterDestructiveClaimLeavesM3StateUntouched() {
        val fixture = InboundClaimFixture()
        fixture.contacts.failCommit = true

        assertThrows(SessionStateException::class.java) {
            fixture.newCoordinator().claimInbound(fixture.inviteUri)
        }

        assertEquals(1, fixture.transport.claimCalls)
        assertEquals(1, fixture.contacts.commitCalls)
        assertEquals(null, fixture.contacts.committedPin)
        assertEquals(0, fixture.sessions.inboundCalls)
        assertTrue(fixture.sessions.state.sessions.isEmpty())
        assertTrue(fixture.sessions.state.account.oneTimeKeys.any { it.id == fixture.creatorOneTimeKey.id })
    }

    @Test
    fun failedInboundCommitAfterDestructiveClaimKeepsPinButDoesNotConsumeM3State() {
        val fixture = InboundClaimFixture()
        fixture.sessions.failInbound = true

        assertThrows(SessionStateException::class.java) {
            fixture.newCoordinator().claimInbound(fixture.inviteUri)
        }

        assertEquals(1, fixture.transport.claimCalls)
        assertEquals(1, fixture.contacts.commitCalls)
        assertTrue(fixture.contacts.committedPin != null)
        assertEquals(1, fixture.sessions.inboundCalls)
        assertTrue(fixture.sessions.state.sessions.isEmpty())
        assertTrue(fixture.sessions.state.account.oneTimeKeys.any { it.id == fixture.creatorOneTimeKey.id })
    }

    private class PendingOutboundFixture {
        val local = TestIdentity()
        val creator = TestIdentity()
        val token = ByteArray(32) { 0x44 }
        val localContactId = ByteArray(16) { 0x55 }
        val frame = NativeSessionMessage(SESSION_OLM_MESSAGE_PRE_KEY, "persisted-pre-key-frame".toByteArray())
        val invite = M2InviteDescriptor(
            creatorIdentityId = creator.identityId.copyOf(),
            token = token.copyOf(),
            signature = creator.sign(ContactCanonical.invitePayload(creator.identityId, token)),
        )
        val inviteUri = InviteUriCodec.encode(invite)
        val pin = SessionPinnedContact(
            localId = localContactId.copyOf(),
            identityId = creator.identityId.copyOf(),
            identityPublicKey = creator.publicKey.copyOf(),
        )
        val sessions = FakeSessions(
            pendingState(
                ownerIdentityId = local.identityId,
                peerIdentityId = creator.identityId,
                inviteToken = token,
                localContactId = localContactId,
                frame = frame,
            ),
        )
        val transport = FakeTransport()
        val contacts = object : SessionContactBoundary {
            override fun requirePinnedContact(
                ownerIdentityId: ByteArray,
                localContactId: ByteArray,
                expectedPeerIdentityId: ByteArray,
            ): SessionPinnedContact {
                assertArrayEquals(local.identityId, ownerIdentityId)
                assertArrayEquals(this@PendingOutboundFixture.localContactId, localContactId)
                assertArrayEquals(creator.identityId, expectedPeerIdentityId)
                return pin
            }

            override fun requirePendingInvite(
                ownerIdentityId: ByteArray,
                invite: M2InviteDescriptor,
                nowEpochSeconds: Long,
            ) = error("not used")

            override fun commitClaimedContact(
                ownerIdentityId: ByteArray,
                inviteToken: ByteArray,
                peerIdentityId: ByteArray,
                peerIdentityPublicKey: ByteArray,
                pinnedAtEpochSeconds: Long,
            ): SessionPinnedContact = error("not used")
        }

        fun newCoordinator(): SessionCoordinator = SessionCoordinator(
            identity = local,
            contacts = contacts,
            sessions = sessions,
            transport = transport,
            threadGuard = SessionThreadGuard { },
            clock = SessionClock { 1_000 },
        )
    }

    private class InboundClaimFixture {
        val local = TestIdentity()
        val redeemer = TestIdentity()
        val token = ByteArray(32) { 0x45 }
        val localContactId = ByteArray(16) { 0x66 }
        val creatorOneTimeKey = SessionOneTimePreKey(1, ByteArray(32) { 0x31 })
        val invite = M2InviteDescriptor(
            creatorIdentityId = local.identityId.copyOf(),
            token = token.copyOf(),
            signature = local.sign(ContactCanonical.invitePayload(local.identityId, token)),
        )
        val inviteUri = InviteUriCodec.encode(invite)
        val redeemerIdentityBundle = signedM2Bundle(redeemer)
        val redeemerSessionBundle = signedM3Bundle(redeemer)
        private val olmMessage = "creator-claim-pre-key-frame".toByteArray()
        val claimResponse: SessionClaimWireResponse = run {
            val unsignedSubmit = SessionSubmitInit(
                creatorIdentityId = local.identityId.copyOf(),
                redeemerIdentityId = redeemer.identityId.copyOf(),
                inviteToken = token.copyOf(),
                creatorAccountGeneration = CREATOR_GENERATION,
                creatorOneTimePreKeyId = creatorOneTimeKey.id,
                redeemerAccountGeneration = redeemerSessionBundle.accountGeneration,
                olmMessageType = SESSION_OLM_MESSAGE_PRE_KEY,
                olmMessage = olmMessage.copyOf(),
                submitSignature = ByteArray(0),
            )
            SessionClaimWireResponse(
                redeemerIdentityBundle = redeemerIdentityBundle,
                redemptionSignature = redeemer.sign(
                    ContactCanonical.redemptionPayload(local.identityId, redeemer.identityId, token),
                ),
                redeemedAtEpochSeconds = 1_000,
                redeemerSessionBundle = redeemerSessionBundle,
                creatorAccountGeneration = CREATOR_GENERATION,
                creatorOneTimePreKey = creatorOneTimeKey,
                olmMessageType = SESSION_OLM_MESSAGE_PRE_KEY,
                olmMessage = olmMessage.copyOf(),
                submitSignature = redeemer.sign(SessionCanonical.submitPayload(unsignedSubmit)),
            )
        }
        val sessions = FakeSessions(
            creatorState(
                ownerIdentityId = local.identityId,
                creatorOneTimeKey = creatorOneTimeKey,
            ),
        )
        val transport = FakeTransport().also { it.claimResponse = claimResponse }
        val contacts = FakeContacts()

        private inner class FakeContacts : SessionContactBoundary {
            var commitCalls = 0
            var failCommit = false
            var committedPin: SessionPinnedContact? = null

            override fun requirePinnedContact(
                ownerIdentityId: ByteArray,
                localContactId: ByteArray,
                expectedPeerIdentityId: ByteArray,
            ): SessionPinnedContact = error("not used")

            override fun requirePendingInvite(
                ownerIdentityId: ByteArray,
                invite: M2InviteDescriptor,
                nowEpochSeconds: Long,
            ) {
                assertArrayEquals(local.identityId, ownerIdentityId)
                assertArrayEquals(token, invite.token)
                assertEquals(1_000L, nowEpochSeconds)
            }

            override fun commitClaimedContact(
                ownerIdentityId: ByteArray,
                inviteToken: ByteArray,
                peerIdentityId: ByteArray,
                peerIdentityPublicKey: ByteArray,
                pinnedAtEpochSeconds: Long,
            ): SessionPinnedContact {
                assertArrayEquals(local.identityId, ownerIdentityId)
                assertArrayEquals(token, inviteToken)
                assertArrayEquals(redeemer.identityId, peerIdentityId)
                assertArrayEquals(redeemer.publicKey, peerIdentityPublicKey)
                assertEquals(1_000L, pinnedAtEpochSeconds)
                commitCalls += 1
                if (failCommit) throw SessionStateException("simulated M2 contact commit failure")
                return SessionPinnedContact(
                    localId = localContactId.copyOf(),
                    identityId = peerIdentityId.copyOf(),
                    identityPublicKey = peerIdentityPublicKey.copyOf(),
                ).also { committedPin = it }
            }
        }

        fun newCoordinator(): SessionCoordinator = SessionCoordinator(
            identity = local,
            contacts = contacts,
            sessions = sessions,
            transport = transport,
            threadGuard = SessionThreadGuard { },
            clock = SessionClock { 1_000 },
        )
    }

    private class TestIdentity : SessionIdentityBoundary {
        private val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val publicKey: ByteArray = keyPair.public.encoded
        val identityId: ByteArray = ContactCrypto.identityId(publicKey)
        var currentCalls = 0

        override fun current(): SessionIdentityMaterial {
            currentCalls += 1
            return SessionIdentityMaterial(identityId.copyOf(), publicKey.copyOf())
        }

        override fun sign(payload: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(payload)
            sign()
        }
    }

    private class FakeSessions(initialState: SessionState) : SessionLocalBoundary {
        var state = initialState
        var loadCalls = 0
        var pendingReads = 0
        var clearCalls = 0
        var inboundCalls = 0
        var failInbound = false

        override fun loadOrCreateAccount(ownerIdentityId: ByteArray): SessionAccountState {
            loadCalls += 1
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            return state.account
        }

        override fun currentState(ownerIdentityId: ByteArray): SessionState? {
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            return state
        }

        override fun prepareBootstrapPublicationOrNull(ownerIdentityId: ByteArray): SessionBootstrapBundle? = null

        override fun completeBootstrapPublication(
            ownerIdentityId: ByteArray,
            acceptedAccountGeneration: Long,
            acceptedPublicationRevision: Long,
        ) = error("not used")

        override fun replenishOneTimeKeys(ownerIdentityId: ByteArray): SessionAccountState {
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            return state.account
        }

        override fun createOutboundSession(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            peerIdentityId: ByteArray,
            peerAccountGeneration: Long,
            peerOlmEd25519IdentityKey: ByteArray,
            peerOlmCurve25519IdentityKey: ByteArray,
            creatorOneTimePreKeyId: Long,
            peerOneTimeKey: ByteArray,
            inviteToken: ByteArray,
            initialPlaintext: ByteArray,
        ): NativeSessionMessage = error("not used")

        override fun pendingOutboundInit(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            inviteToken: ByteArray,
            creatorAccountGeneration: Long,
            creatorOneTimePreKeyId: Long,
        ): NativeSessionMessage? {
            pendingReads += 1
            val session = state.sessions.single()
            val pending = session.pendingInit ?: return null
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            assertArrayEquals(session.localContactId, localContactId)
            assertArrayEquals(pending.inviteTokenHash, MessageDigest.getInstance("SHA-256").digest(inviteToken))
            assertEquals(pending.creatorAccountGeneration, creatorAccountGeneration)
            assertEquals(pending.creatorOneTimePreKeyId, creatorOneTimePreKeyId)
            return NativeSessionMessage(pending.messageType, pending.olmMessage.copyOf())
        }

        override fun markOutboundInitSubmitted(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            inviteToken: ByteArray,
            creatorAccountGeneration: Long,
            creatorOneTimePreKeyId: Long,
        ) {
            val session = state.sessions.single()
            val pending = session.pendingInit ?: error("pending init missing")
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            assertArrayEquals(session.localContactId, localContactId)
            assertArrayEquals(pending.inviteTokenHash, MessageDigest.getInstance("SHA-256").digest(inviteToken))
            assertEquals(pending.creatorAccountGeneration, creatorAccountGeneration)
            assertEquals(pending.creatorOneTimePreKeyId, creatorOneTimePreKeyId)
            clearCalls += 1
            state = state.copy(sessions = listOf(session.copy(pendingInit = null)))
        }

        override fun createInboundSession(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            peerIdentityId: ByteArray,
            peerAccountGeneration: Long,
            peerOlmEd25519IdentityKey: ByteArray,
            peerOlmCurve25519IdentityKey: ByteArray,
            consumedOneTimeKeyId: Long,
            expectedInitialPlaintext: ByteArray,
            messageType: Int,
            olmMessage: ByteArray,
        ): ByteArray {
            assertArrayEquals(state.ownerIdentityId, ownerIdentityId)
            val consumed = state.account.oneTimeKeys.single { it.id == consumedOneTimeKeyId }
            inboundCalls += 1
            if (failInbound) throw SessionStateException("simulated M3 inbound persistence failure")
            val persisted = PersistedSession(
                localContactId = localContactId.copyOf(),
                peerIdentityId = peerIdentityId.copyOf(),
                peerAccountGeneration = peerAccountGeneration,
                peerOlmEd25519IdentityKey = peerOlmEd25519IdentityKey.copyOf(),
                peerOlmCurve25519IdentityKey = peerOlmCurve25519IdentityKey.copyOf(),
                sessionId = "inbound-session",
                initiator = false,
                snapshot = WrappedSessionSnapshot("inbound".toByteArray(), ByteArray(32) { 0x43 }),
            )
            state = state.copy(
                account = state.account.copy(
                    oneTimeKeys = state.account.oneTimeKeys.filterNot { it.id == consumed.id },
                ),
                sessions = state.sessions + persisted,
            )
            return expectedInitialPlaintext.copyOf()
        }
    }

    private class FakeTransport : SessionTransport {
        var submitCalls = 0
        var reserveCalls = 0
        var claimCalls = 0
        var failSubmit = false
        var lastSubmit: SessionSubmitInit? = null
        var claimResponse: SessionClaimWireResponse? = null
        var afterSubmit: () -> Unit = { }
        var afterClaim: () -> Unit = { }

        override fun publishBootstrap(bundle: SessionBootstrapBundle): SessionPublishWireResponse = error("not used")

        override fun reserveBootstrap(
            creatorIdentityId: ByteArray,
            redeemerIdentityId: ByteArray,
            inviteToken: ByteArray,
            reserveSignature: ByteArray,
        ): SessionReserveWireResponse {
            reserveCalls += 1
            error("reserve must not run for persisted pending init")
        }

        override fun submitInit(request: SessionSubmitInit) {
            submitCalls += 1
            lastSubmit = request
            if (failSubmit) throw SessionTransportException("simulated failure")
            afterSubmit()
        }

        override fun claimInit(
            creatorIdentityId: ByteArray,
            inviteToken: ByteArray,
            claimSignature: ByteArray,
        ): SessionClaimWireResponse {
            claimCalls += 1
            val response = claimResponse ?: error("claim response is not configured")
            afterClaim()
            return response
        }
    }

    private object RejectingContacts : SessionContactBoundary {
        override fun requirePinnedContact(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            expectedPeerIdentityId: ByteArray,
        ): SessionPinnedContact = error("must not be called")

        override fun requirePendingInvite(
            ownerIdentityId: ByteArray,
            invite: M2InviteDescriptor,
            nowEpochSeconds: Long,
        ) = error("must not be called")

        override fun commitClaimedContact(
            ownerIdentityId: ByteArray,
            inviteToken: ByteArray,
            peerIdentityId: ByteArray,
            peerIdentityPublicKey: ByteArray,
            pinnedAtEpochSeconds: Long,
        ): SessionPinnedContact = error("must not be called")
    }

    companion object {
        private const val CREATOR_GENERATION = 3L

        private fun signedM2Bundle(identity: TestIdentity): M2PublicIdentityBundle {
            val signedPreKeyIdentity = TestIdentity()
            val signedPreKey = M2SignedPreKey(
                id = 1,
                publicKey = signedPreKeyIdentity.publicKey.copyOf(),
                signature = identity.sign(
                    ContactCanonical.signedPreKeyPayload(1, signedPreKeyIdentity.publicKey),
                ),
                createdAtEpochSeconds = 900,
            )
            val unsigned = M2PublicIdentityBundle(
                identityId = identity.identityId.copyOf(),
                identityPublicKey = identity.publicKey.copyOf(),
                publicationRevision = 1,
                signedPreKey = signedPreKey,
                oneTimePreKeys = emptyList(),
                publicationSignature = ByteArray(0),
            )
            return unsigned.copy(
                publicationSignature = identity.sign(ContactCanonical.publicationPayload(unsigned)),
            )
        }

        private fun signedM3Bundle(identity: TestIdentity): SessionBootstrapBundle {
            val unsigned = SessionBootstrapBundle(
                identityId = identity.identityId.copyOf(),
                accountGeneration = 5,
                publicationRevision = 2,
                olmEd25519IdentityKey = ByteArray(32) { 0x71 },
                olmCurve25519IdentityKey = ByteArray(32) { 0x72 },
                oneTimePreKeys = listOf(SessionOneTimePreKey(1, ByteArray(32) { 0x73 })),
                bindingSignature = ByteArray(0),
            )
            return unsigned.copy(
                bindingSignature = identity.sign(SessionCanonical.bootstrapPayload(unsigned)),
            )
        }

        private fun creatorState(
            ownerIdentityId: ByteArray,
            creatorOneTimeKey: SessionOneTimePreKey,
        ): SessionState = SessionState(
            ownerIdentityId = ownerIdentityId.copyOf(),
            account = SessionAccountState(
                accountGeneration = CREATOR_GENERATION,
                publicationRevision = 4,
                nextOneTimeKeyId = creatorOneTimeKey.id + 1,
                olmEd25519IdentityKey = ByteArray(32) { 0x21 },
                olmCurve25519IdentityKey = ByteArray(32) { 0x22 },
                oneTimeKeys = listOf(
                    TrackedSessionOneTimeKey(creatorOneTimeKey.id, creatorOneTimeKey.publicKey.copyOf()),
                ),
                snapshot = WrappedSessionSnapshot("account".toByteArray(), ByteArray(32) { 0x41 }),
            ),
            sessions = emptyList(),
        )

        private fun pendingState(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            inviteToken: ByteArray,
            localContactId: ByteArray = ByteArray(16) { 0x55 },
            frame: NativeSessionMessage = NativeSessionMessage(
                SESSION_OLM_MESSAGE_PRE_KEY,
                "persisted-pre-key-frame".toByteArray(),
            ),
        ): SessionState {
            val accountGeneration = 3L
            val creatorGeneration = 7L
            val creatorOneTimeKeyId = 9L
            return SessionState(
                ownerIdentityId = ownerIdentityId.copyOf(),
                account = SessionAccountState(
                    accountGeneration = accountGeneration,
                    publicationRevision = 4,
                    nextOneTimeKeyId = 3,
                    olmEd25519IdentityKey = ByteArray(32) { 0x21 },
                    olmCurve25519IdentityKey = ByteArray(32) { 0x22 },
                    oneTimeKeys = listOf(
                        TrackedSessionOneTimeKey(1, ByteArray(32) { 0x31 }),
                        TrackedSessionOneTimeKey(2, ByteArray(32) { 0x32 }),
                    ),
                    snapshot = WrappedSessionSnapshot("account".toByteArray(), ByteArray(32) { 0x41 }),
                ),
                sessions = listOf(
                    PersistedSession(
                        localContactId = localContactId.copyOf(),
                        peerIdentityId = peerIdentityId.copyOf(),
                        peerAccountGeneration = creatorGeneration,
                        peerOlmEd25519IdentityKey = ByteArray(32) { 0x61 },
                        peerOlmCurve25519IdentityKey = ByteArray(32) { 0x62 },
                        sessionId = "session-recovery",
                        initiator = true,
                        snapshot = WrappedSessionSnapshot("session".toByteArray(), ByteArray(32) { 0x42 }),
                        pendingInit = PendingSessionInit(
                            inviteTokenHash = MessageDigest.getInstance("SHA-256").digest(inviteToken),
                            creatorAccountGeneration = creatorGeneration,
                            creatorOneTimePreKeyId = creatorOneTimeKeyId,
                            redeemerAccountGeneration = accountGeneration,
                            messageType = frame.messageType,
                            olmMessage = frame.ciphertext.copyOf(),
                        ),
                    ),
                ),
            )
        }
    }
}
