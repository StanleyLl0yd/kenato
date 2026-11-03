package com.sl.kenato.storage

import com.sl.kenato.M45ProcessTransportGate
import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class M45CrossProcessLeaseTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun competingClaimFailsClosedAndCleanCloseAllowsNewOwner() {
        val root = temporary.newFolder()
        val first = M45CrossProcessLease.acquire(root)
        try {
            assertTrue(first.permitsOperations())
            assertThrows(IllegalStateException::class.java) {
                M45CrossProcessLease.acquire(root)
            }
            assertTrue(root.resolve(M45CrossProcessLease.LOCK_FILE_NAME).isFile)
            assertTrue(first.permitsOperations())
        } finally {
            first.close()
        }
        assertFalse(first.permitsOperations())
        first.close()
        M45CrossProcessLease.acquire(root).use { second ->
            assertTrue(second.permitsOperations())
        }
        // Never unlink the lock inode: another process may already be waiting on it.
        assertTrue(root.resolve(M45CrossProcessLease.LOCK_FILE_NAME).isFile)
    }

    @Test
    fun distinctPrivateDirectoriesHaveIndependentLeases() {
        M45CrossProcessLease.acquire(temporary.newFolder()).use { first ->
            M45CrossProcessLease.acquire(temporary.newFolder()).use { second ->
                assertTrue(first.permitsOperations())
                assertTrue(second.permitsOperations())
            }
        }
    }

    @Test
    fun symlinkCannotRedirectOwnerLockOutsidePrivateDirectory() {
        val root = temporary.newFolder()
        val outside = temporary.newFile()
        val link = root.toPath().resolve(M45CrossProcessLease.LOCK_FILE_NAME)
        try {
            Files.createSymbolicLink(link, outside.toPath())
        } catch (_: UnsupportedOperationException) {
            return
        } catch (_: java.nio.file.FileSystemException) {
            return
        }
        assertThrows(java.io.IOException::class.java) {
            M45CrossProcessLease.acquire(root)
        }
        assertTrue(Files.isSymbolicLink(link))
    }

    @Test
    fun defaultFactoriesCanReuseOneLifetimeLeaseButNewOwnersCannotBypassIt() {
        val directory = temporary.newFolder()
        val first = M45CrossProcessLease.shared(directory)
        try {
            val second = M45CrossProcessLease.shared(directory)
            assertSame(first, second)
            assertThrows(IllegalStateException::class.java) {
                M45CrossProcessLease.acquire(directory)
            }
            val gate = M45ProcessTransportGate(first)
            gate.requireAvailable(Any())
            assertTrue(gate.permitsTransportCallbacks())
            first.close()
            assertFalse(gate.permitsTransportCallbacks())
            assertThrows(IllegalStateException::class.java) {
                gate.requireAvailable(Any())
            }
            assertThrows(IllegalStateException::class.java) {
                M45CrossProcessLease.shared(directory)
            }
        } finally {
            first.close()
        }
    }

    @Test
    fun invalidPrivateDirectoryCannotCreateLockFile() {
        assertThrows(IllegalArgumentException::class.java) {
            M45CrossProcessLease.acquire(temporary.newFile())
        }
    }
}
