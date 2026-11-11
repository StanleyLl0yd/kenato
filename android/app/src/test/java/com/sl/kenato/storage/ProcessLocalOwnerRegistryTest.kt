package com.sl.kenato.storage

import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class ProcessLocalOwnerRegistryTest {
    @Test
    fun sameStorageLocationReusesOwnerAndDistinctLocationsDoNot() {
        val registry = ProcessLocalOwnerRegistry<Any>()
        val first = registry.getOrCreate("/data/app/a") { Any() }
        val again = registry.getOrCreate("/data/app/a") {
            throw AssertionError("Second owner must never be constructed")
        }
        val separate = registry.getOrCreate("/data/app/b") { Any() }

        assertSame(first, again)
        assertNotSame(first, separate)
        assertThrows(IllegalArgumentException::class.java) {
            registry.getOrCreate("") { Any() }
        }
    }

    @Test
    fun concurrentCallersCannotConstructIndependentOwnersForOneLocation() {
        val registry = ProcessLocalOwnerRegistry<Any>()
        val created = AtomicInteger()
        val gate = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val calls = List(8) {
                executor.submit(Callable {
                    gate.await()
                    registry.getOrCreate("/data/app/session") {
                        created.incrementAndGet()
                        Any()
                    }
                })
            }
            gate.countDown()
            val owners = calls.map { it.get(20, TimeUnit.SECONDS) }
            assertEquals(1, created.get())
            owners.forEach { assertSame(owners.first(), it) }
        } finally {
            gate.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun distinctM2OwnerFamiliesDoNotAliasAtTheSamePrivateDirectory() {
        // Identity and contacts have separate storage/locks, while each family reuses
        // one process-local monitor even when bootstrap and WSS request it separately.
        val identities = ProcessLocalOwnerRegistry<Any>()
        val contacts = ProcessLocalOwnerRegistry<Any>()
        val directory = "/data/app/shared/no_backup"
        val identity = identities.getOrCreate(directory) { Any() }
        val contact = contacts.getOrCreate(directory) { Any() }

        assertNotSame(identity, contact)
        assertSame(identity, identities.getOrCreate(directory) {
            throw AssertionError("Duplicate identity owner")
        })
        assertSame(contact, contacts.getOrCreate(directory) {
            throw AssertionError("Duplicate contact owner")
        })
    }

    @Test
    fun failedConstructionIsNotCachedAndMayBeRetried() {
        val registry = ProcessLocalOwnerRegistry<Any>()
        val attempts = AtomicInteger()
        assertThrows(IllegalStateException::class.java) {
            registry.getOrCreate("/data/app/session") {
                attempts.incrementAndGet()
                throw IllegalStateException("simulated initialization failure")
            }
        }
        val recovered = registry.getOrCreate("/data/app/session") {
            attempts.incrementAndGet()
            Any()
        }
        assertSame(recovered, registry.getOrCreate("/data/app/session") { Any() })
        assertEquals(2, attempts.get())
    }
}
