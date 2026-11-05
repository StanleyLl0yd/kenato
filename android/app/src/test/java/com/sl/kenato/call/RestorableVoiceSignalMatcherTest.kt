package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RestorableVoiceSignalMatcherTest {
    @Test
    fun onlyDurablyAdmittedOfferIsRestorableEvenAfterCrash() {
        val f = Fixture()
        f.accept(handoff(1, expiry = NOW + 30))
        f.accept(handoff(2, expiry = NOW + 80))
        assertEquals(2, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        val live = f.matcher().restorableCandidates(OWNER, NOW)
        assertEquals(1, live.size)
        assertArrayEquals(id(1), live.single().messageId)
        assertEquals("v=0\r\n", live.single().payload.toString(Charsets.UTF_8))
        // No call resurrection when first offer expires and only a suppressed one remains.
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 31).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW + 31).size)
    }

    @Test
    fun verifiedClaimReturnsDecryptedEventAtMostOnceAcrossRestarts() {
        val f = Fixture()
        f.accept(handoff(51))
        val claimed = f.matcher().claimRestorableCandidate(OWNER, PEER, id(51), NOW)
        assertArrayEquals(id(51), claimed!!.messageId)
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW).isEmpty())
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(51), NOW))
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun protectedMatcherRefusesOldJournalRestorationEvenWhenSemanticEventIsAuthentic() {
        val f = Fixture()
        f.accept(handoff(110))
        val originalUnclaimedJournal = requireNotNull(f.replayStore.read()).copyOf()
        val originalPermit = f.journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        val ledger = f.ledger()

        val claimed = f.matcher().claimRestorableCandidateWithEpochLedger(
            OWNER, PEER, id(110), NOW, ledger,
        )
        assertArrayEquals(id(110), requireNotNull(claimed).messageId)
        assertTrue(ledger.hasClaim(OWNER, originalPermit))

        // Both journal and encrypted semantic event are still authentic.
        // Replaying the old unclaimed journal MUST NOT return another effect.
        f.replayStore.write(originalUnclaimedJournal)
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(null, f.matcher().claimRestorableCandidateWithEpochLedger(
            OWNER, PEER, id(110), NOW, f.ledger(),
        ))
        assertTrue(f.ledger().hasClaim(OWNER, originalPermit))
    }

    @Test
    fun failureOfProtectedClaimCannotReturnAnAlreadyClaimedSemanticEffect() {
        val f = Fixture()
        f.accept(handoff(111))
        f.ledgerRaw.failWrite = true
        assertThrows(VoiceSignalReplayException::class.java) {
            f.matcher().claimRestorableCandidateWithEpochLedger(
                OWNER, PEER, id(111), NOW, f.ledger(),
            )
        }
        // Fail closed even though the separate journal claim committed.
        assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        f.ledgerRaw.failWrite = false
        assertEquals(null, f.matcher().claimRestorableCandidateWithEpochLedger(
            OWNER, PEER, id(111), NOW, f.ledger(),
        ))
    }

    @Test
    fun protectedClaimNeverRunsWithoutIndependentEncryptedSemanticCounterpart() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(112), NOW)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidateWithEpochLedger(
                OWNER, PEER, id(112), NOW, f.ledger(),
            )
        }
        assertEquals(null, f.ledgerRaw.bytes)
    }

    @Test
    fun epochGuardedControlAdmitsOneVerifiedOfferIntoReducerAndNoSecondOne() {
        val f = Fixture()
        f.accept(handoff(120))
        val admission = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val guarded = EpochGuardedVoiceCallClaimedControlSource(
            f.matcher(), f.ledger(), admission, VoiceCallCoordinatorClock { NOW },
        )
        val coordinator = VoiceCallAdmissionCoordinator(
            OWNER, admission, guarded, VoiceCallCoordinatorClock { NOW },
        )
        val accepted = requireNotNull(coordinator.receiveClaimedControl(PEER, id(120)))
        assertEquals(VoiceCallPhase.INCOMING_RINGING, accepted.next.phase)
        assertTrue(accepted.effects.isEmpty())
        assertEquals(null, coordinator.receiveClaimedControl(PEER, id(120)))
        assertEquals(VoiceCallPhase.INCOMING_RINGING, coordinator.snapshot().phase)
        assertTrue(f.ledger().hasClaim(
            OWNER,
            VoiceSignalReplayDispatchPermit(
                PEER, id(120), id(77), VoiceSignalKind.OFFER,
                f.journal.pendingLiveReceipts(OWNER, NOW).single().envelopeDigest,
            ),
        ))
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun epochGuardedSourceRejectsRevokedConsentWithoutConsumingAnyClaim() {
        val f = Fixture()
        f.accept(handoff(121))
        val admission = VoiceCallVerifiedPeerAdmission { _, _ ->
            throw VoiceCallAdmissionException("Consent revoked")
        }
        val coordinator = VoiceCallAdmissionCoordinator(
            OWNER, admission,
            EpochGuardedVoiceCallClaimedControlSource(
                f.matcher(), f.ledger(), admission, VoiceCallCoordinatorClock { NOW },
            ),
            VoiceCallCoordinatorClock { NOW },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            coordinator.receiveClaimedControl(PEER, id(121))
        }
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(null, f.ledgerRaw.bytes)
        assertEquals(VoiceCallPhase.IDLE, coordinator.snapshot().phase)
    }

    @Test
    fun revokeDuringDurableCommitReturnsNoControlAndCannotRetryTheClaim() {
        val f = Fixture()
        f.accept(handoff(122))
        var allowed = true
        val admission = VoiceCallVerifiedPeerAdmission { _, _ ->
            if (!allowed) throw VoiceCallAdmissionException("Revoked while writing claim")
        }
        f.ledgerRaw.afterWrite = { allowed = false }
        val coordinator = VoiceCallAdmissionCoordinator(
            OWNER, admission,
            EpochGuardedVoiceCallClaimedControlSource(
                f.matcher(), f.ledger(), admission, VoiceCallCoordinatorClock { NOW },
            ),
            VoiceCallCoordinatorClock { NOW },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            coordinator.receiveClaimedControl(PEER, id(122))
        }
        assertEquals(VoiceCallPhase.IDLE, coordinator.snapshot().phase)
        assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        allowed = true
        assertEquals(null, coordinator.receiveClaimedControl(PEER, id(122)))
        assertEquals(VoiceCallPhase.IDLE, coordinator.snapshot().phase)
    }

    @Test
    fun expiryDuringDurableCommitReturnsNoControlButConsumesTheClaim() {
        val f = Fixture()
        f.accept(handoff(123))
        var clockValue = NOW
        f.ledgerRaw.afterWrite = { clockValue = NOW + 60L }
        val admission = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val currentClock = VoiceCallCoordinatorClock { clockValue }
        val coordinator = VoiceCallAdmissionCoordinator(
            OWNER, admission,
            EpochGuardedVoiceCallClaimedControlSource(
                f.matcher(), f.ledger(), admission, currentClock,
            ), currentClock,
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            coordinator.receiveClaimedControl(PEER, id(123))
        }
        assertEquals(VoiceCallPhase.IDLE, coordinator.snapshot().phase)
        assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun epochGuardedControlIgnoresIceWithoutConsumingItsDedicatedMediaClaim() {
        val f = Fixture()
        f.accept(handoff(124, kind = VoiceSignalKind.ICE_CANDIDATE))
        val admission = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val guarded = EpochGuardedVoiceCallClaimedControlSource(
            f.matcher(), f.ledger(), admission, VoiceCallCoordinatorClock { NOW },
        )
        assertEquals(null, guarded.claimControl(OWNER, PEER, id(124), NOW))
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(null, f.ledgerRaw.bytes)
    }

    @Test
    fun swappedAuthenticatedSemanticSnapshotAfterEpochCommitCannotReturnOldEvent() {
        val f = Fixture()
        f.accept(handoff(125))
        val original = f.journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        f.ledgerRaw.afterWrite = {
            // Adversarial private-file replacement during the protected commit:
            // an independently valid encrypted semantic event with the same
            // sender/message ID but a different call ID and outer envelope.
            f.semanticStore.bytes = null
            f.semantic.persistAuthenticatedVoiceEvent(OWNER, handoff(125, call = 99))
        }
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidateWithEpochLedger(
                OWNER, PEER, id(125), NOW, f.ledger(),
            )
        }
        assertTrue(f.ledger().hasClaim(OWNER, original))
        assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun disappearanceOfSemanticFileDuringEpochCommitCannotReturnStalePlaintext() {
        val f = Fixture()
        f.accept(handoff(126))
        val original = f.journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        f.ledgerRaw.afterWrite = { f.semanticStore.bytes = null }
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidateWithEpochLedger(
                OWNER, PEER, id(126), NOW, f.ledger(),
            )
        }
        assertTrue(f.ledger().hasClaim(OWNER, original))
        assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
    }

    @Test
    fun concurrentGuardedSourcesAcrossSeparateCoordinatorsAdmitOnlyOneEffect() {
        val f = Fixture()
        f.accept(handoff(127))
        val admission = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val pool = Executors.newFixedThreadPool(2)
        val begin = CountDownLatch(1)
        try {
            val attempts = (1..2).map {
                pool.submit<VoiceCallTransition?> {
                    val guarded = EpochGuardedVoiceCallClaimedControlSource(
                        f.matcher(), f.ledger(), admission, VoiceCallCoordinatorClock { NOW },
                    )
                    val coordinator = VoiceCallAdmissionCoordinator(
                        OWNER, admission, guarded, VoiceCallCoordinatorClock { NOW },
                    )
                    begin.await()
                    coordinator.receiveClaimedControl(PEER, id(127))
                }
            }
            begin.countDown()
            val outcomes = attempts.map { it.get(15, TimeUnit.SECONDS) }
            assertEquals(1, outcomes.count { it != null })
            assertEquals(1, outcomes.count { it == null })
            assertEquals(VoiceCallPhase.INCOMING_RINGING, outcomes.filterNotNull().single().next.phase)
            assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
            assertTrue(f.journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun isolatedForegroundOwnerClaimsSendOfferProposalOnceAndNeverRunsNetwork() {
        val f = Fixture()
        val guard = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, guard, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val proposed = owner.userDial(PEER, explicitUserApproval = true)
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, proposed.snapshot.phase)
        assertEquals(1, proposed.tickets.size)
        val ticket = proposed.tickets.single()
        val effect = requireNotNull(owner.claimProposal(ticket))
        assertEquals(VoiceCallEffectKind.SEND_OFFER, effect.kind)
        assertEquals(proposed.snapshot.active, effect.key)
        assertEquals(null, owner.claimProposal(ticket))
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, owner.snapshot().phase)
        owner.close()
        assertThrows(VoiceCallAdmissionException::class.java) { owner.claimProposal(ticket) }
    }

    @Test
    fun isolatedForegroundOwnerCancelsOutstandingTicketWhenInboundControlIsNotClaimed() {
        val f = Fixture()
        val guard = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, guard, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val outbound = owner.userDial(PEER, explicitUserApproval = true)
        val oldTicket = outbound.tickets.single()
        assertEquals(null, owner.receiveControl(PEER, id(200)))
        assertEquals(null, owner.claimProposal(oldTicket))
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, owner.snapshot().phase)
        owner.close()
    }

    @Test
    fun isolatedForegroundOwnerUsesKdl1OnIncomingControlAndExpiresOldTickets() {
        val f = Fixture()
        f.accept(handoff(128))
        val guard = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, guard, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val received = requireNotNull(owner.receiveControl(PEER, id(128)))
        assertEquals(VoiceCallPhase.INCOMING_RINGING, received.snapshot.phase)
        assertTrue(received.tickets.isEmpty())
        assertEquals(null, owner.receiveControl(PEER, id(128)))
        val key = requireNotNull(received.snapshot.active)
        val accepted = owner.userAction(VoiceCallEventKind.LOCAL_ACCEPT, key, true)
        assertEquals(VoiceCallPhase.CONNECTING, accepted.snapshot.phase)
        assertEquals(2, accepted.tickets.size)
        assertEquals(
            VoiceCallEffectKind.SEND_ACCEPT,
            owner.claimProposal(accepted.tickets[0])!!.kind,
        )
        assertEquals(
            VoiceCallEffectKind.START_MEDIA,
            owner.claimProposal(accepted.tickets[1])!!.kind,
        )
        assertEquals(null, owner.claimProposal(accepted.tickets[1]))
        owner.close()
    }

    @Test
    fun isolatedForegroundOwnerRejectsRevokedStartButStillProposesExactMediaStop() {
        val f = Fixture()
        f.accept(handoff(129))
        var allowed = true
        val guard = VoiceCallVerifiedPeerAdmission { _, _ ->
            if (!allowed) throw VoiceCallAdmissionException("Consent revoked")
        }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, guard, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val ringing = requireNotNull(owner.receiveControl(PEER, id(129)))
        val key = requireNotNull(ringing.snapshot.active)
        val connecting = owner.userAction(VoiceCallEventKind.LOCAL_ACCEPT, key, true)
        allowed = false
        assertEquals(null, owner.claimProposal(connecting.tickets[0]))
        assertEquals(null, owner.claimProposal(connecting.tickets[1]))
        val terminated = owner.revalidateActiveCall()
        assertEquals(VoiceCallPhase.IDLE, terminated.snapshot.phase)
        assertEquals(1, terminated.tickets.size)
        val stop = requireNotNull(owner.claimProposal(terminated.tickets.single()))
        assertEquals(VoiceCallEffectKind.STOP_MEDIA, stop.kind)
        assertEquals(key, stop.key)
        owner.close()
    }

    @Test
    fun isolatedForegroundOwnerInvalidatesPreviousTicketsOnTransitionAndClose() {
        val f = Fixture()
        val guard = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, guard, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val dial = owner.userDial(PEER, true)
        val oldTicket = dial.tickets.single()
        val active = requireNotNull(dial.snapshot.active)
        val cancelled = owner.userAction(VoiceCallEventKind.LOCAL_HANGUP, active)
        assertEquals(VoiceCallPhase.IDLE, cancelled.snapshot.phase)
        assertEquals(null, owner.claimProposal(oldTicket))
        owner.close()
        assertThrows(VoiceCallAdmissionException::class.java) { owner.userDial(PEER, true) }
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.receiveControl(PEER, id(1))
        }
        owner.close()
    }

    @Test
    fun isolatedForegroundOwnerClosesAfterUncertainDurableInboundClaim() {
        val f = Fixture()
        f.accept(handoff(130))
        val admission = VoiceCallVerifiedPeerAdmission { _, _ -> }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, admission, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        val outbound = owner.userDial(PEER, explicitUserApproval = true)
        f.ledgerRaw.failWrite = true
        assertThrows(VoiceSignalReplayException::class.java) {
            owner.receiveControl(PEER, id(130))
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.claimProposal(outbound.tickets.single())
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.userDial(PEER, explicitUserApproval = true)
        }
        assertThrows(VoiceCallAdmissionException::class.java) { owner.snapshot() }
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        owner.close()
    }

    @Test
    fun isolatedForegroundOwnerCannotResumeAfterConsentRevokedDuringClaim() {
        val f = Fixture()
        f.accept(handoff(131))
        var allowed = true
        val admission = VoiceCallVerifiedPeerAdmission { _, _ ->
            if (!allowed) throw VoiceCallAdmissionException("Consent revoked")
        }
        f.ledgerRaw.afterWrite = { allowed = false }
        val owner = IsolatedVoiceForegroundOwner(
            OWNER, admission, f.matcher(), f.ledger(), VoiceCallCoordinatorClock { NOW },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.receiveControl(PEER, id(131))
        }
        allowed = true
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.userDial(PEER, explicitUserApproval = true)
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            owner.receiveControl(PEER, id(131))
        }
        owner.close()
    }

    @Test
    fun callControlAdapterClaimsOfferOnceButLeavesIceForFutureMediaOwner() {
        val f = Fixture()
        f.accept(handoff(91, kind = VoiceSignalKind.ICE_CANDIDATE))
        val source = MatcherVoiceCallClaimedControlSource(f.matcher())
        assertEquals(null, source.claimControl(OWNER, PEER, id(91), NOW))
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(
            VoiceSignalKind.ICE_CANDIDATE,
            f.matcher().claimRestorableCandidate(OWNER, PEER, id(91), NOW)!!.kind,
        )

        f.accept(handoff(92))
        assertEquals(
            VoiceSignalKind.OFFER,
            source.claimControl(OWNER, PEER, id(92), NOW)!!.kind,
        )
        assertEquals(null, source.claimControl(OWNER, PEER, id(92), NOW))
        assertEquals(2, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun receiptChangedAfterSemanticPairingCannotClaimDifferentCall() {
        val f = Fixture()
        f.accept(handoff(61, call = 77))
        f.replayStore.afterReadOnce = {
            val state = VoiceSignalReplayStateCodec.decode(f.replayStore.read()!!)
            val original = state.records.single()
            val replacement = VoiceSignalReplayRecord(
                peerIdentityId = original.peerIdentityId.copyOf(),
                messageId = original.messageId.copyOf(),
                callId = id(99),
                kind = original.kind,
                expiresAtEpochSeconds = original.expiresAtEpochSeconds,
                envelopeDigest = original.envelopeDigest.copyOf(),
            )
            f.replayStore.write(VoiceSignalReplayStateCodec.encode(
                VoiceSignalReplayState(OWNER.copyOf(), listOf(replacement)),
            ))
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.matcher().claimRestorableCandidate(OWNER, PEER, id(61), NOW)
        }
        val state = VoiceSignalReplayStateCodec.decode(f.replayStore.read()!!)
        assertArrayEquals(id(99), state.records.single().callId)
        assertEquals(false, state.records.single().dispatchClaimed)
    }

    @Test
    fun noSemanticPayloadCannotClaimReplayPermission() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(52), NOW)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidate(OWNER, PEER, id(52), NOW)
        }
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
    }

    @Test
    fun suppressedAndExpiredOffersCannotClaimAnEffect() {
        val f = Fixture()
        f.accept(handoff(53, expiry = NOW + 30))
        f.accept(handoff(54, expiry = NOW + 80))
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(54), NOW))
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(53), NOW + 30))
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW + 31).size)
    }

    @Test
    fun replayReceiptWithoutDurableSemanticPayloadFailsClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(3), NOW)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun semanticPayloadWithoutAdmittedReplayReceiptCannotBeDispatched() {
        val f = Fixture()
        f.semantic.persistAuthenticatedVoiceEvent(OWNER, handoff(4))
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
        assertTrue(f.journal.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
    }

    @Test
    fun orphanEncryptedSemanticEventBlocksOtherValidEffectUntilDurableReconciliation() {
        val f = Fixture()
        f.accept(handoff(140))
        val validPermit = f.journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        // Crash window: encrypted semantic write succeeded but the next replay
        // receipt import did not commit. There is still another valid call.
        val orphan = handoff(141)
        f.semantic.persistAuthenticatedVoiceEvent(OWNER, orphan)
        assertEquals(1, f.journal.pendingLiveReceipts(OWNER, NOW).size)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidateWithEpochLedger(
                OWNER, PEER, id(140), NOW, f.ledger(),
            )
        }
        // No irreversible claim is consumed while the stores are inconsistent.
        assertEquals(null, f.ledgerRaw.bytes)
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)

        // Recover from the actual authenticated M3 handoff, not by dropping
        // or silently approving the orphan plaintext.
        f.journal.importAuthenticatedInboundHandoff(OWNER, orphan, NOW)
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW).any {
            it.messageId.contentEquals(validPermit.messageId)
        })
    }

    @Test
    fun mismatchedPersistedCallForSameAuthenticatedMessageIdFailsClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(5, call = 100), NOW)
        f.semantic.persistAuthenticatedVoiceEvent(OWNER, handoff(5, call = 101))
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun samePeerMessageAndCallWithDifferentAuthenticatedEnvelopeDigestFailClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(8), NOW)
        f.semantic.persistAuthenticatedVoiceEvent(
            OWNER, handoff(8, ciphertext = byteArrayOf(7, 8, 9)),
        )
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun tamperedSemanticCiphertextAndWrongOwnerDoNotYieldEffects() {
        val f = Fixture()
        f.accept(handoff(6))
        f.semanticStore.bytes = f.semanticStore.bytes!!.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceSemanticEventException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.matcher().restorableCandidates(ByteArray(32) { 9 }, NOW)
        }
    }

    @Test
    fun exactExpiryBoundaryUsesOneSnapshotAcrossStores() {
        val f = Fixture()
        f.accept(handoff(7, expiry = NOW + 60))
        assertEquals(1, f.matcher().restorableCandidates(OWNER, NOW + 59).size)
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 60).isEmpty())
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 360).isEmpty())
    }

    private class Fixture {
        val replayStore = MemoryReplayStore()
        val semanticStore = MemoryEncryptedStore()
        val journal = VoiceSignalReplayJournal(replayStore)
        val cipher = JvmAesGcmCipher()
        val semantic = DurableVoiceSemanticEventRepository(
            semanticStore, cipher, VoiceSemanticClock { NOW },
        )
        fun accept(event: SessionMessageHandoff) {
            semantic.persistAuthenticatedVoiceEvent(OWNER, event)
            journal.importAuthenticatedInboundHandoff(OWNER, event, NOW)
        }
        val ledgerRaw = MemoryLedgerRaw()
        val ledgerKeys = MemoryLedgerKeys()
        fun ledger() = VoiceDispatchContinuityLedger(ledgerRaw, ledgerKeys)
        fun matcher() = RestorableVoiceSignalMatcher(
            VoiceSignalReplayJournal(replayStore),
            DurableVoiceSemanticEventRepository(
                semanticStore, cipher, VoiceSemanticClock { NOW },
            ),
        )
    }

    private class MemoryLedgerRaw : VoiceDispatchLedgerRawStore {
        var bytes: ByteArray? = null
        var failWrite = false
        var afterWrite: (() -> Unit)? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean {
            if (failWrite) return false
            this.bytes = bytes.copyOf()
            afterWrite?.invoke()
            return true
        }
    }

    private class MemoryLedgerKeys : VoiceDispatchLedgerEpochKeys {
        private val keyMap = linkedMapOf<String, SecretKeySpec>()
        private val random = SecureRandom()
        private var next = 1
        override fun epochIds(): Set<String> = keyMap.keys.toSet()
        override fun createEpoch(): String {
            val epoch = (next++).toString(16).padStart(32, '0')
            keyMap[epoch] = SecretKeySpec(ByteArray(32).also(random::nextBytes), "AES")
            return epoch
        }
        override fun encrypt(epoch: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, requireNotNull(keyMap[epoch]), GCMParameterSpec(128, iv))
            cipher.updateAAD(aad)
            return iv + cipher.doFinal(plaintext)
        }
        override fun decrypt(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE, requireNotNull(keyMap[epoch]),
                GCMParameterSpec(128, ciphertext.copyOfRange(0, 12)),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext.copyOfRange(12, ciphertext.size))
        }
        override fun retireEpoch(epoch: String) {
            check(keyMap.remove(epoch) != null)
        }
    }

    private class MemoryReplayStore : VoiceSignalReplayStore {
        private var bytes: ByteArray? = null
        var afterReadOnce: (() -> Unit)? = null
        override fun read(): ByteArray? {
            val snapshot = bytes?.copyOf()
            val callback = afterReadOnce
            afterReadOnce = null
            callback?.invoke()
            return snapshot
        }
        override fun write(bytes: ByteArray): Boolean {
            this.bytes = bytes.copyOf()
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class MemoryEncryptedStore : VoiceSemanticEncryptedStore {
        var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            bytes = value.copyOf()
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class JvmAesGcmCipher : VoiceSemanticPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x31.toByte() }, "AES")
        private val random = SecureRandom()
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return byteArrayOf(1) + iv + c.doFinal(plaintext)
        }
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
            c.updateAAD(aad)
            return c.doFinal(encrypted.copyOfRange(13, encrypted.size))
        }
    }

    private fun handoff(
        message: Int,
        call: Int = 77,
        expiry: Long = NOW + 60,
        ciphertext: ByteArray = byteArrayOf(1, 2, 3),
        kind: VoiceSignalKind = VoiceSignalKind.OFFER,
    ): SessionMessageHandoff {
        val signal = VoiceSignalPlaintext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(message),
            callId = id(call),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = expiry,
            kind = kind,
            payload = if (kind == VoiceSignalKind.ICE_CANDIDATE) {
                "candidate:0 1 udp 1 192.0.2.1 5000 typ host".toByteArray()
            } else {
                "v=0\r\n".toByteArray()
            },
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(message),
            expiresAtEpochSeconds = expiry,
            ciphertext = ciphertext,
        )
        return SessionMessageHandoff(
            localContactId = ByteArray(16) { 3 },
            peerIdentityId = PEER.copyOf(),
            messageId = id(message),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            encodedPlaintext = VoiceSignalingWire.encode(signal),
            encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
        )
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
        fun id(n: Int) = ByteArray(16).also {
            it[0] = (n and 255).toByte()
            it[1] = ((n ushr 8) and 255).toByte()
        }
    }
}
