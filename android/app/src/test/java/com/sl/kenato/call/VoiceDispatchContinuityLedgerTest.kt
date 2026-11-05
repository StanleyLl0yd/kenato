package com.sl.kenato.call

import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic file-only adversary + fault injection. NOT a physical Android test
 * and NOT proof that the future effect runner uses this isolated ledger.
 */
class VoiceDispatchContinuityLedgerTest {
    @Test
    fun claimedPermitSurvivesInstanceRestartAndCannotDispatchTwice() {
        val f = Fixture()
        val p = permit()
        assertFalse(f.ledger.hasClaim(OWNER, p))
        assertTrue(f.ledger.claim(OWNER, p))
        assertTrue(f.newLedger().hasClaim(OWNER, p))
        assertFalse(f.newLedger().claim(OWNER, p))
        assertEquals(1, f.keys.epochIds().size)
    }

    @Test
    fun restoringOldAuthenticUnclaimedFileFailsAfterLaterClaim() {
        val f = Fixture()
        val earlier = permit(1)
        val later = permit(2)
        assertTrue(f.ledger.claim(OWNER, earlier))
        val authenticOld = f.raw.bytes!!.clone()
        assertTrue(f.ledger.claim(OWNER, later))
        assertTrue(f.newLedger().hasClaim(OWNER, later))
        f.raw.bytes = authenticOld
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, later)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().hasClaim(OWNER, earlier)
        }
    }

    @Test
    fun forgedUnkeyedJournalClaimFlagCannotResetIndependentLedger() {
        val f = Fixture()
        val p = permit()
        assertTrue(f.ledger.claim(OWNER, p))
        // The existing v1 replay journal's unkeyed checksum can be recomputed.
        // The isolated key-retired ledger is independently committed instead.
        val originalJournal = VoiceSignalReplayState(
            OWNER,
            listOf(
                VoiceSignalReplayRecord(
                    PEER, p.messageId, p.callId, p.kind, 1_780_000_060L,
                    p.envelopeDigest, dispatchClaimed = true,
                ),
            ),
        )
        val original = VoiceSignalReplayStateCodec.encode(originalJournal)
        val decoded = VoiceSignalReplayStateCodec.decode(original).records.single()
        val forgedJournal = VoiceSignalReplayStateCodec.encode(
            VoiceSignalReplayState(OWNER, listOf(VoiceSignalReplayRecord(
                decoded.peerIdentityId, decoded.messageId, decoded.callId,
                decoded.kind, decoded.expiresAtEpochSeconds, decoded.envelopeDigest,
                dispatchClaimed = false,
            ))),
        )
        assertFalse(VoiceSignalReplayStateCodec.decode(forgedJournal)
            .records.single().dispatchClaimed)
        assertFalse(f.newLedger().claim(OWNER, p))
    }

    @Test
    fun entireEncryptedFileCannotBeSilentlyReplacedByPlainJournal() {
        val f = Fixture()
        f.ledger.claim(OWNER, permit())
        f.raw.bytes = VoiceSignalReplayStateCodec.encode(
            VoiceSignalReplayState(OWNER, emptyList()),
        )
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, permit(3))
        }
    }

    @Test
    fun orphanedAndUnexpectedKeysFailClosedEvenWhenFileMissing() {
        val f = Fixture()
        f.keys.createEpoch()
        assertThrows(VoiceSignalReplayException::class.java) {
            f.ledger.claim(OWNER, permit())
        }
        assertEquals(null, f.raw.bytes)
    }

    @Test
    fun lostActiveKeyAndUnrelatedExtraKeyBothFailClosed() {
        val f = Fixture()
        f.ledger.claim(OWNER, permit())
        val old = f.keys.epochIds().single()
        f.keys.createEpoch()
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, permit(4))
        }
        f.keys.retireEpoch(old)
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().hasClaim(OWNER, permit())
        }
    }

    @Test
    fun beforeOrAfterWriteFailureNeverReturnsAClaimPermit() {
        for (mode in listOf("before", "after", "false-commit")) {
            val f = Fixture()
            f.ledger.claim(OWNER, permit(1))
            f.raw.failure = mode
            assertThrows(Exception::class.java) {
                f.ledger.claim(OWNER, permit(2))
            }
            assertThrows(VoiceSignalReplayException::class.java) {
                f.ledger.claim(OWNER, permit(3))
            }
            assertThrows(VoiceSignalReplayException::class.java) {
                f.newLedger().claim(OWNER, permit(2))
            }
        }
    }

    @Test
    fun failureAfterNewKeyCreationCannotReopenAsCleanInstall() {
        val f = Fixture()
        f.keys.throwAfterCreate = true
        assertThrows(VoiceSignalReplayException::class.java) {
            f.ledger.claim(OWNER, permit())
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, permit())
        }
    }

    @Test
    fun retirementFailureLeavesTwoEpochsAndIsTerminal() {
        val f = Fixture()
        f.ledger.claim(OWNER, permit(1))
        f.keys.failRetire = true
        assertThrows(VoiceSignalReplayException::class.java) {
            f.ledger.claim(OWNER, permit(2))
        }
        assertEquals(2, f.keys.epochIds().size)
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().hasClaim(OWNER, permit(1))
        }
    }

    @Test
    fun ownerAndCorrelationAreBoundAndInvalidInputDoesNotGrant() {
        val f = Fixture()
        assertTrue(f.ledger.claim(OWNER, permit()))
        val p = permit()
        val switchedCall = VoiceSignalReplayDispatchPermit(
            PEER, p.messageId, id(500), p.kind, p.envelopeDigest,
        )
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().hasClaim(OWNER, switchedCall)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, switchedCall)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(ByteArray(32) { 7 }, p)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, VoiceSignalReplayDispatchPermit(
                PEER, byteArrayOf(1), p.callId, p.kind, p.envelopeDigest,
            ))
        }
        assertTrue(f.newLedger().hasClaim(OWNER, p))
    }

    @Test
    fun sameMessageIdDifferentAuthenticatedEnvelopeDigestOrKindCannotObtainSecondClaim() {
        val f = Fixture()
        val original = permit(33)
        assertTrue(f.ledger.claim(OWNER, original))
        val forgedDigest = VoiceSignalReplayDispatchPermit(
            PEER, original.messageId, original.callId, original.kind,
            original.envelopeDigest.copyOf().also { it[0] = 99.toByte() },
        )
        val forgedKind = VoiceSignalReplayDispatchPermit(
            PEER, original.messageId, original.callId, VoiceSignalKind.ANSWER,
            original.envelopeDigest,
        )
        for (variant in listOf(forgedDigest, forgedKind)) {
            assertThrows(VoiceSignalReplayException::class.java) {
                f.newLedger().claim(OWNER, variant)
            }
            assertThrows(VoiceSignalReplayException::class.java) {
                f.newLedger().hasClaim(OWNER, variant)
            }
        }
        assertFalse(f.newLedger().claim(OWNER, original))
    }

    @Test
    fun twoInstanceSimultaneousClaimAllowsOnlyOne() {
        val f = Fixture()
        val p = permit()
        val pool = Executors.newFixedThreadPool(2)
        val release = CountDownLatch(1)
        try {
            val tasks = (1..2).map {
                pool.submit<Boolean> {
                    release.await()
                    f.newLedger().claim(OWNER, p)
                }
            }
            release.countDown()
            val values = tasks.map { it.get(15, TimeUnit.SECONDS) }
            assertEquals(1, values.count { it })
            assertEquals(1, values.count { !it })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun replacingTheCommittedFileWithNothingCannotCreateNewLedger() {
        val f = Fixture()
        f.ledger.claim(OWNER, permit())
        f.raw.bytes = null
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, permit(10))
        }
    }

    @Test
    fun corruptedCiphertextAndDestructiveClearAreRejected() {
        val f = Fixture()
        f.ledger.claim(OWNER, permit())
        f.raw.bytes = f.raw.bytes!!.clone().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().claim(OWNER, permit(9))
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.newLedger().clearForIdentityRecovery()
        }
    }

    private class Fixture {
        val raw = MemoryRaw()
        val keys = Keys()
        val ledger = newLedger()
        fun newLedger() = VoiceDispatchContinuityLedger(raw, keys)
    }

    private class MemoryRaw : VoiceDispatchLedgerRawStore {
        var bytes: ByteArray? = null
        var failure: String? = null
        override fun read(): ByteArray? = bytes?.clone()
        override fun write(bytes: ByteArray): Boolean {
            when (failure) {
                "before" -> return false
                "false-commit" -> return true
            }
            this.bytes = bytes.clone()
            if (failure == "after") throw VoiceSignalReplayException("Uncertain after durable file write")
            return true
        }
    }

    private class Keys : VoiceDispatchLedgerEpochKeys {
        private val random = SecureRandom()
        private val map = linkedMapOf<String, SecretKeySpec>()
        private var nextId = 1
        var failRetire = false
        var throwAfterCreate = false

        override fun epochIds(): Set<String> = map.keys.toSet()
        override fun createEpoch(): String {
            val id = (nextId++).toString(16).padStart(32, '0')
            map[id] = SecretKeySpec(ByteArray(32).also(random::nextBytes), "AES")
            if (throwAfterCreate) throw VoiceSignalReplayException("Key created, returning error")
            return id
        }
        override fun encrypt(epoch: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, requireNotNull(map[epoch]), GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            return nonce + c.doFinal(plaintext)
        }
        override fun decrypt(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(
                Cipher.DECRYPT_MODE, requireNotNull(map[epoch]),
                GCMParameterSpec(128, ciphertext.copyOfRange(0, 12)),
            )
            c.updateAAD(aad)
            return c.doFinal(ciphertext.copyOfRange(12, ciphertext.size))
        }
        override fun retireEpoch(epoch: String) {
            if (failRetire) throw VoiceSignalReplayException("Key deletion uncertain")
            check(map.remove(epoch) != null)
        }
    }

    private fun permit(message: Int = 1): VoiceSignalReplayDispatchPermit =
        VoiceSignalReplayDispatchPermit(
            PEER, id(message), id(77), VoiceSignalKind.OFFER, ByteArray(32) { 4 },
        )

    private fun id(number: Int): ByteArray =
        ByteArray(16).also {
            it[0] = (number and 255).toByte()
            it[1] = (number ushr 8).toByte()
        }

    private companion object {
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
    }
}
