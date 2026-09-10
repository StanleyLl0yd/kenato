package com.sl.kenato.contact

import com.sl.kenato.identity.IdentityBundle
import com.sl.kenato.identity.OneTimePreKey
import com.sl.kenato.identity.SignedPreKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactRepositoryTest {
    @Test
    fun createRedeemClaimRoundTripPinsBothPeers() {
        val server = TestContactServer()
        val creatorIdentity = TestContactIdentityProvider()
        val redeemerIdentity = TestContactIdentityProvider()
        val creatorState = ContactLocalState(TestContactStateStore())
        val redeemerState = ContactLocalState(TestContactStateStore())
        val creator = repository(creatorIdentity, creatorState, server)
        val redeemer = repository(redeemerIdentity, redeemerState, server)

        val invite = creator.createInvite()
        val creatorPin = redeemer.redeemInvite(invite.uri)
        val redeemerPin = creator.claimInvite(invite.uri)

        val creatorId = creatorIdentity.identityId()
        val redeemerId = redeemerIdentity.identityId()
        assertArrayEquals(creatorId, creatorPin.identityId)
        assertArrayEquals(redeemerId, redeemerPin.identityId)
        assertArrayEquals(creatorId, redeemer.contacts().single().identityId)
        assertArrayEquals(redeemerId, creator.contacts().single().identityId)
        assertTrue(creator.pendingInvites().isEmpty())
        assertEquals(1, server.redeemCalls)
        assertEquals(1, server.claimCalls)
    }

    @Test
    fun publicationRevisionIsStableForRetryAndAdvancesOnMaterialChange() {
        val server = TestContactServer()
        val identity = TestContactIdentityProvider()
        val repository = repository(identity, ContactLocalState(TestContactStateStore()), server)

        assertEquals(1L, repository.publishIdentity().publicationRevision)
        assertEquals(1L, repository.publishIdentity().publicationRevision)
        identity.replaceOneTimePreKeyMaterial()
        assertEquals(2L, repository.publishIdentity().publicationRevision)
    }

    @Test
    fun unexpectedAcceptedPublicationRevisionFailsClosed() {
        val server = TestContactServer().apply { acceptedRevisionDelta = 1 }
        val repository = repository(
            TestContactIdentityProvider(),
            ContactLocalState(TestContactStateStore()),
            server,
        )

        assertThrows(ContactProtocolException::class.java) { repository.publishIdentity() }
    }

    @Test
    fun selfInviteFailsBeforeRedemptionTransport() {
        val server = TestContactServer()
        val identity = TestContactIdentityProvider()
        val repository = repository(identity, ContactLocalState(TestContactStateStore()), server)
        val invite = repository.createInvite()

        assertThrows(ContactIdentityConflictException::class.java) {
            repository.redeemInvite(invite.uri)
        }
        assertEquals(0, server.redeemCalls)
    }

    @Test
    fun substitutedCreatorBundleIsRejectedWithoutPinning() {
        val server = TestContactServer()
        val creator = repository(
            TestContactIdentityProvider(),
            ContactLocalState(TestContactStateStore()),
            server,
        )
        val redeemerState = ContactLocalState(TestContactStateStore())
        val redeemerIdentity = TestContactIdentityProvider()
        val redeemer = repository(redeemerIdentity, redeemerState, server)
        val attacker = TestContactIdentityProvider()
        val attackerBundle = attacker.signedBundle(1)
        val invite = creator.createInvite()
        server.creatorResponseOverride = attackerBundle

        assertThrows(ContactIdentityConflictException::class.java) {
            redeemer.redeemInvite(invite.uri)
        }
        assertTrue(redeemer.contacts().isEmpty())
    }

    @Test
    fun invalidRedemptionProofIsRejectedAndPendingInviteIsRetained() {
        val server = TestContactServer()
        val creatorState = ContactLocalState(TestContactStateStore())
        val creator = repository(TestContactIdentityProvider(), creatorState, server)
        val redeemer = repository(
            TestContactIdentityProvider(),
            ContactLocalState(TestContactStateStore()),
            server,
        )
        val invite = creator.createInvite()
        redeemer.redeemInvite(invite.uri)
        server.redemptionSignatureOverride = byteArrayOf(1, 2, 3)

        assertThrows(ContactProtocolException::class.java) {
            creator.claimInvite(invite.uri)
        }
        assertTrue(creator.contacts().isEmpty())
        assertEquals(1, creator.pendingInvites().size)
    }

    @Test
    fun claimRequiresMatchingLocalPendingInviteBeforeTransport() {
        val server = TestContactServer()
        val identity = TestContactIdentityProvider()
        val state = ContactLocalState(TestContactStateStore())
        val creator = repository(identity, state, server)
        val invite = creator.createInvite()
        val descriptor = InviteUriCodec.decode(invite.uri)
        assertTrue(state.removePendingInvite(identity.identityId(), descriptor.token))

        assertThrows(ContactStateException::class.java) {
            creator.claimInvite(invite.uri)
        }
        assertEquals(0, server.claimCalls)
    }

    private fun repository(
        identity: TestContactIdentityProvider,
        state: ContactLocalState,
        transport: ContactTransport,
    ): ContactRepository = ContactRepository(
        identity = identity,
        localState = state,
        transport = transport,
        random = SecureRandom(),
        clock = ContactClock { TEST_NOW },
    )

    private companion object {
        const val TEST_NOW = 1_789_000_000L
    }
}

private class TestContactServer : ContactTransport {
    private val publications = ArrayList<M2PublicIdentityBundle>()
    private var invite: M2InviteDescriptor? = null
    private var redeemerBundle: M2PublicIdentityBundle? = null
    private var redemptionSignature: ByteArray? = null

    var acceptedRevisionDelta = 0L
    var creatorResponseOverride: M2PublicIdentityBundle? = null
    var redemptionSignatureOverride: ByteArray? = null
    var redeemCalls = 0
        private set
    var claimCalls = 0
        private set

    override fun publishIdentity(bundle: M2PublicIdentityBundle): Long {
        ContactCrypto.verifyPublicIdentityBundle(bundle)
        publications.removeAll { it.identityId.contentEquals(bundle.identityId) }
        publications += bundle
        return bundle.publicationRevision + acceptedRevisionDelta
    }

    override fun createInvite(invite: M2InviteDescriptor): Long {
        val creator = publications.firstOrNull { it.identityId.contentEquals(invite.creatorIdentityId) }
            ?: throw AssertionError("Creator must be published before invite creation")
        ContactCrypto.verifyInvite(invite, creator.identityPublicKey)
        this.invite = invite.copy(
            creatorIdentityId = invite.creatorIdentityId.copyOf(),
            token = invite.token.copyOf(),
            signature = invite.signature.copyOf(),
        )
        return 1_789_003_600L
    }

    override fun redeemInvite(
        invite: M2InviteDescriptor,
        redeemerBundle: M2PublicIdentityBundle,
        redemptionSignature: ByteArray,
    ): RedeemInviteWireResponse {
        redeemCalls += 1
        val storedInvite = requireNotNull(this.invite)
        if (!storedInvite.token.contentEquals(invite.token)) {
            throw AssertionError("Redeem token differs from created invite")
        }
        ContactCrypto.verifyPublicIdentityBundle(redeemerBundle)
        this.redeemerBundle = redeemerBundle
        this.redemptionSignature = redemptionSignature.copyOf()
        val creator = publications.first { it.identityId.contentEquals(invite.creatorIdentityId) }
        return RedeemInviteWireResponse(
            creatorBundle = creatorResponseOverride ?: creator,
            redeemedAtEpochSeconds = 1_789_000_100L,
        )
    }

    override fun claimInvite(
        creatorIdentityId: ByteArray,
        token: ByteArray,
        claimSignature: ByteArray,
    ): ClaimInviteWireResponse {
        claimCalls += 1
        val storedInvite = requireNotNull(invite)
        if (
            !storedInvite.creatorIdentityId.contentEquals(creatorIdentityId) ||
            !storedInvite.token.contentEquals(token) ||
            claimSignature.isEmpty()
        ) {
            throw AssertionError("Claim does not match the created invite")
        }
        return ClaimInviteWireResponse(
            redeemerBundle = requireNotNull(redeemerBundle),
            redemptionSignature = redemptionSignatureOverride ?: requireNotNull(redemptionSignature),
            redeemedAtEpochSeconds = 1_789_000_100L,
        )
    }
}

private class TestContactIdentityProvider : ContactIdentityProvider {
    private val identity = keyPair()
    private val signedPreKey = keyPair()
    private var oneTimePreKey = keyPair()

    override fun currentIdentity(): IdentityBundle = IdentityBundle(
        identityId = encode(ContactCrypto.identityId(identity.public.encoded)),
        identityPublicKey = encode(identity.public.encoded),
        signedPreKey = SignedPreKey(
            id = 1,
            publicKey = encode(signedPreKey.public.encoded),
            signature = encode(signRaw(ContactCanonical.signedPreKeyPayload(1, signedPreKey.public.encoded))),
            createdAtEpochSeconds = 1_788_900_000L,
        ),
        oneTimePreKeys = listOf(
            OneTimePreKey(
                id = 2,
                publicKey = encode(oneTimePreKey.public.encoded),
                createdAtEpochSeconds = 1_788_900_001L,
            ),
        ),
    )

    override fun sign(payload: ByteArray): ByteArray = signRaw(payload)

    fun identityId(): ByteArray = ContactCrypto.identityId(identity.public.encoded)

    fun signedBundle(revision: Long): M2PublicIdentityBundle =
        signPublicBundle(currentIdentity().toUnsignedContactBundle(revision))

    fun replaceOneTimePreKeyMaterial() {
        oneTimePreKey = keyPair()
    }

    private fun signRaw(payload: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(identity.private)
        update(payload)
        sign()
    }

    private fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private companion object {
        fun keyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
    }
}

private class TestContactStateStore : ContactStateStore {
    private var value: ByteArray? = null

    override fun read(): ByteArray? = value?.copyOf()

    override fun write(value: ByteArray): Boolean {
        this.value = value.copyOf()
        return true
    }

    override fun clear(): Boolean {
        value = null
        return true
    }
}
