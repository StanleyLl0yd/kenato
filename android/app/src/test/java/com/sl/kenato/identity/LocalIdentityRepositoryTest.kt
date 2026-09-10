package com.sl.kenato.identity

import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalIdentityRepositoryTest {
    @Test
    fun loadOrCreateCreatesStableBoundedIdentity() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)

        val first = repository.loadOrCreate()
        val second = repository.loadOrCreate()

        assertEquals(first, second)
        assertEquals(1, backend.createCalls)
        assertEquals(LocalIdentityRepository.DEFAULT_ONE_TIME_PREKEYS, first.oneTimePreKeys.size)
        assertEquals(
            1 + LocalIdentityRepository.DEFAULT_ONE_TIME_PREKEYS,
            (first.oneTimePreKeys.map { it.id } + first.signedPreKey.id).toSet().size,
        )
        assertEquals(
            IdentityPrimitives.identityId(IdentityPrimitives.decodeBase64Url(first.identityPublicKey)),
            first.identityId,
        )
    }

    @Test
    fun keystoreMaterialWithoutStateFailsClosed() {
        val backend = TestIdentityKeyBackend()
        backend.createManagedKeys()
        val repository = repository(backend, InMemoryIdentityStateStore())

        assertThrows(IdentityStateException::class.java) {
            repository.loadOrCreate()
        }
        assertEquals(1, backend.createCalls)
    }

    @Test
    fun persistedStateWithMissingManagedKeyFailsClosed() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        backend.dropWrappingKey()

        assertThrows(IdentityStateException::class.java) {
            repository.current()
        }
    }

    @Test
    fun failedInitialCommitDeletesNewManagedKeys() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore(failWrites = true)
        val repository = repository(backend, store)

        assertThrows(IdentityPersistenceException::class.java) {
            repository.loadOrCreate()
        }
        assertFalse(backend.hasAnyManagedKey())
        assertEquals(1, backend.deleteCalls)
        assertNull(store.read())
    }

    @Test
    fun failedRotationCommitPreservesPreviouslyDurableState() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        val durableBefore = requireNotNull(store.read())
        store.failWrites = true

        assertThrows(IdentityPersistenceException::class.java) {
            repository.rotateSignedPreKey()
        }

        assertArrayEquals(durableBefore, requireNotNull(store.read()))
    }

    @Test
    fun signedPreKeyRotationRetainsOnlyOnePreviousKey() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        val original = repository.loadOrCreate()

        val firstRotation = repository.rotateSignedPreKey()
        var state = IdentityStateCodec.decode(requireNotNull(store.read()))
        assertEquals(original.signedPreKey.id, state.previousSignedPreKey?.id)
        assertEquals(firstRotation.signedPreKey.id, state.signedPreKey.id)

        val secondRotation = repository.rotateSignedPreKey()
        state = IdentityStateCodec.decode(requireNotNull(store.read()))
        assertEquals(firstRotation.signedPreKey.id, state.previousSignedPreKey?.id)
        assertEquals(secondRotation.signedPreKey.id, state.signedPreKey.id)
        assertNotEquals(original.signedPreKey.id, state.previousSignedPreKey?.id)
    }

    @Test
    fun previousSignedPreKeyCanBeRetiredExplicitly() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        repository.rotateSignedPreKey()

        repository.retirePreviousSignedPreKey()

        val state = IdentityStateCodec.decode(requireNotNull(store.read()))
        assertNull(state.previousSignedPreKey)
    }

    @Test
    fun oneTimePrekeyConsumptionAndReplenishmentAreBounded() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        val initial = repository.loadOrCreate()
        val consumedId = initial.oneTimePreKeys.first().id

        assertTrue(repository.consumeOneTimePreKey(consumedId))
        assertFalse(repository.consumeOneTimePreKey(consumedId))
        assertEquals(
            LocalIdentityRepository.DEFAULT_ONE_TIME_PREKEYS - 1,
            requireNotNull(repository.current()).oneTimePreKeys.size,
        )

        val replenished = repository.replenishOneTimePreKeys()
        assertEquals(LocalIdentityRepository.DEFAULT_ONE_TIME_PREKEYS, replenished.oneTimePreKeys.size)
        assertFalse(replenished.oneTimePreKeys.any { it.id == consumedId })
        assertEquals(
            replenished.oneTimePreKeys.size,
            replenished.oneTimePreKeys.map { it.id }.toSet().size,
        )

        assertThrows(IllegalArgumentException::class.java) {
            repository.replenishOneTimePreKeys(IdentityStateCodec.MAX_ONE_TIME_PREKEYS + 1)
        }
    }

    @Test
    fun failedRecoveryStateClearDoesNotDeleteManagedKeys() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        store.failClears = true

        assertThrows(IdentityPersistenceException::class.java) {
            repository.resetLocalIdentityForRecovery()
        }

        assertTrue(backend.hasAllManagedKeys())
        assertEquals(0, backend.deleteCalls)
        assertTrue(store.read() != null)
    }

    @Test
    fun tamperedSignedPreKeySignatureFailsClosed() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        val state = IdentityStateCodec.decode(requireNotNull(store.read()))
        val signature = requireNotNull(state.signedPreKey.signature).copyOf()
        signature[0] = (signature[0].toInt() xor 1).toByte()
        val tampered = state.copy(
            signedPreKey = state.signedPreKey.copy(signature = signature),
        )
        store.value = IdentityStateCodec.encode(tampered)

        assertThrows(IdentityStateException::class.java) {
            repository.current()
        }
    }

    @Test
    fun tamperedEncryptedPrivatePrekeyFailsClosed() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        val state = IdentityStateCodec.decode(requireNotNull(store.read()))
        val first = state.oneTimePreKeys.first()
        val encrypted = first.encryptedPrivateKey.copyOf()
        encrypted[0] = (encrypted[0].toInt() xor 1).toByte()
        val tampered = state.copy(
            oneTimePreKeys = listOf(first.copy(encryptedPrivateKey = encrypted)) + state.oneTimePreKeys.drop(1),
        )
        store.value = IdentityStateCodec.encode(tampered)

        assertThrows(IdentityStateException::class.java) {
            repository.current()
        }
    }

    @Test
    fun explicitRecoveryResetClearsStateAndManagedKeys() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()

        repository.resetLocalIdentityForRecovery()

        assertNull(store.read())
        assertFalse(backend.hasAnyManagedKey())
        assertEquals(1, backend.deleteCalls)
    }

    @Test
    fun corruptSerializedStateFailsClosed() {
        val backend = TestIdentityKeyBackend()
        val store = InMemoryIdentityStateStore()
        val repository = repository(backend, store)
        repository.loadOrCreate()
        store.value = byteArrayOf(0x01, 0x02, 0x03)

        assertThrows(IdentityStateException::class.java) {
            repository.current()
        }
    }

    private fun repository(
        backend: TestIdentityKeyBackend,
        store: InMemoryIdentityStateStore,
    ) = LocalIdentityRepository(
        keyBackend = backend,
        stateStore = store,
        clock = IdentityClock { 1_788_973_200L },
    )
}

private class InMemoryIdentityStateStore(
    var failWrites: Boolean = false,
    var failClears: Boolean = false,
) : IdentityStateStore {
    var value: ByteArray? = null

    override fun read(): ByteArray? = value?.copyOf()

    override fun write(value: ByteArray): Boolean {
        if (failWrites) {
            return false
        }
        this.value = value.copyOf()
        return true
    }

    override fun clear(): Boolean {
        if (failClears) {
            return false
        }
        value = null
        return true
    }
}

private class TestIdentityKeyBackend : IdentityKeyBackend {
    private var identityKeyPair: KeyPair? = null
    private var wrappingKeyPresent = false

    var createCalls = 0
        private set
    var deleteCalls = 0
        private set

    override fun hasAnyManagedKey(): Boolean = identityKeyPair != null || wrappingKeyPresent

    override fun hasAllManagedKeys(): Boolean = identityKeyPair != null && wrappingKeyPresent

    override fun createManagedKeys(): ByteArray {
        check(!hasAnyManagedKey())
        createCalls += 1
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        identityKeyPair = generator.generateKeyPair()
        wrappingKeyPresent = true
        return requireNotNull(identityKeyPair).public.encoded
    }

    override fun identityPublicKey(): ByteArray = requireNotNull(identityKeyPair).public.encoded

    override fun signIdentity(payload: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(requireNotNull(identityKeyPair).private)
        update(payload)
        sign()
    }

    override fun generatePreKey(id: Int, kind: PreKeyKind): GeneratedPreKey {
        val publicKey = "public:${kind.code}:$id".toByteArray(StandardCharsets.UTF_8)
        return GeneratedPreKey(
            publicKey = publicKey,
            encryptedPrivateKey = expectedEncrypted(id, kind, publicKey),
        )
    }

    override fun validateEncryptedPreKey(preKey: StoredPreKey, kind: PreKeyKind): Boolean =
        wrappingKeyPresent && preKey.encryptedPrivateKey.contentEquals(
            expectedEncrypted(preKey.id, kind, preKey.publicKey),
        )

    override fun deleteManagedKeys() {
        deleteCalls += 1
        identityKeyPair = null
        wrappingKeyPresent = false
    }

    fun dropWrappingKey() {
        wrappingKeyPresent = false
    }

    private fun expectedEncrypted(id: Int, kind: PreKeyKind, publicKey: ByteArray): ByteArray =
        "encrypted:${kind.code}:$id:${IdentityPrimitives.base64Url(publicKey)}"
            .toByteArray(StandardCharsets.UTF_8)
}
