package com.sl.kenato.storage

import com.sl.kenato.M45ProcessTransportGate
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class M45CrossProcessLeaseTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun separateJvmsCannotOwnOnePrivateDirectoryAndDeadOwnerReleasesKernelLock() {
        val directory = temporary.newFolder()
        val probe = temporary.newFile("LeaseProbe.java")
        probe.writeText(
            """
            import java.nio.channels.FileChannel;
            import java.nio.channels.FileLock;
            import java.nio.file.LinkOption;
            import java.nio.file.OpenOption;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.util.Set;
            public class LeaseProbe {
                public static void main(String[] args) throws Exception {
                    Path file = Path.of(args[0], "kenato_m45_process_owner.lock");
                    Set<OpenOption> options = Set.of(
                        StandardOpenOption.CREATE, StandardOpenOption.READ,
                        StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS
                    );
                    try (FileChannel channel = FileChannel.open(file, options)) {
                        FileLock lock = channel.tryLock();
                        if (lock == null) System.exit(42);
                        try {
                            if (args.length == 2 && args[1].equals("hold")) {
                                System.out.println("LOCKED");
                                System.out.flush();
                                System.in.read();
                            }
                        } finally { lock.release(); }
                    }
                }
            }
            """.trimIndent(),
        )
        val first = M45CrossProcessLease.shared(directory)
        try {
            assertTrue(first.permitsOperations())
            assertEquals("Second JVM must not acquire the first JVM's lock", 42, probeLock(probe, directory))
            assertTrue(first.permitsOperations())
        } finally {
            first.close()
        }
        assertFalse(first.permitsOperations())
        assertEquals("OS lock must be released after clean close", 0, probeLock(probe, directory))

        // A killed Android-like owner loses the OS lease, not its unfinished transactions.
        val output = temporary.newFile("holder-output.txt")
        val java = File(System.getProperty("java.home"), "bin/java")
        val holder = ProcessBuilder(
            java.absolutePath, probe.absolutePath, directory.absolutePath, "hold",
        ).redirectErrorStream(true).redirectOutput(output).start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25)
            while (!output.readText().contains("LOCKED") && System.nanoTime() < deadline) {
                if (!holder.isAlive) throw AssertionError("Forked lease owner exited before acquiring lock")
                Thread.sleep(20)
            }
            assertTrue("Forked owner must report an acquired lock", output.readText().contains("LOCKED"))
            assertEquals("Competing JVM must reject live owner", 42, probeLock(probe, directory))
        } finally {
            holder.destroyForcibly()
            assertTrue("Killed owner must exit", holder.waitFor(10, TimeUnit.SECONDS))
        }
        assertEquals("OS must release lease after force-kill", 0, probeLock(probe, directory))
        // A persistent inode prevents split owners due to unlink/recreate.
        assertTrue(directory.resolve(M45CrossProcessLease.LOCK_FILE_NAME).isFile)
    }

    @Test
    fun separatePrivateDirectoriesAreIndependent() {
        M45CrossProcessLease.shared(temporary.newFolder()).use { first ->
            M45CrossProcessLease.shared(temporary.newFolder()).use { second ->
                assertTrue(first.permitsOperations())
                assertTrue(second.permitsOperations())
            }
        }
    }

    @Test
    fun defaultFactoriesReuseOneLeaseAndLostLeaseDeniesCallbacksAndMutations() {
        val directory = temporary.newFolder()
        val first = M45CrossProcessLease.shared(directory)
        try {
            assertSame(first, M45CrossProcessLease.shared(directory))
            first.requireActive()
            val gate = M45ProcessTransportGate(first)
            gate.requireAvailable(Any())
            assertTrue(gate.permitsTransportCallbacks())
            first.close()
            assertThrows(IllegalStateException::class.java) { first.requireActive() }
            assertFalse(gate.permitsTransportCallbacks())
            assertThrows(IllegalStateException::class.java) { gate.requireAvailable(Any()) }
            assertThrows(IllegalStateException::class.java) {
                M45CrossProcessLease.shared(directory)
            }
        } finally {
            first.close()
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
            M45CrossProcessLease.shared(root)
        }
        assertTrue(Files.isSymbolicLink(link))
    }

    @Test
    fun invalidPrivateDirectoryCannotCreateLockFile() {
        assertThrows(IllegalArgumentException::class.java) {
            M45CrossProcessLease.shared(temporary.newFile())
        }
    }

    private fun probeLock(probe: File, directory: File): Int {
        val java = File(System.getProperty("java.home"), "bin/java")
        val child = ProcessBuilder(java.absolutePath, probe.absolutePath, directory.absolutePath)
            .redirectErrorStream(true)
            .start()
        try {
            if (!child.waitFor(25, TimeUnit.SECONDS)) {
                child.destroyForcibly()
                throw AssertionError("Forked JVM lease probe exceeded its deadline")
            }
            val output = child.inputStream.bufferedReader().use { it.readText() }
            if (child.exitValue() !in setOf(0, 42)) {
                throw AssertionError("Forked JVM lease probe failed: $output")
            }
            return child.exitValue()
        } finally {
            child.destroy()
        }
    }
}
