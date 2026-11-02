package com.sl.kenato.call

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Dormant M5 dispatch-ledger experiment, NOT a production voice implementation.
 * Only a random test-only Keystore alias prefix is permitted; the production
 * namespace and legacy journal/consent/M3 aliases are inaccessible here.
 */
internal class AndroidKeystoreVoiceDispatchLedgerEpochKeys(
    private val aliasPrefix: String,
) : VoiceDispatchLedgerEpochKeys {
    init {
        require(ACCEPTANCE_PREFIX.matches(aliasPrefix)) {
            "KDL1 requires a fresh 128-bit isolated acceptance Keystore prefix"
        }
    }

    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val random = SecureRandom()

    override fun epochIds(): Set<String> = try {
        val found = HashSet<String>()
        val aliases = store.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (alias.startsWith(aliasPrefix)) {
                // Include malformed aliases so the caller detects ambiguity.
                found.add(alias.removePrefix(aliasPrefix))
            }
        }
        found
    } catch (error: Exception) {
        throw VoiceSignalReplayException("Cannot enumerate isolated dispatch Keystore aliases", error)
    }

    override fun createEpoch(): String = try {
        val allocated = allocateUniqueEpochId()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                aliasPrefix + allocated,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        generator.generateKey()
        allocated
    } catch (error: Exception) {
        throw VoiceSignalReplayException("Cannot create isolated dispatch Keystore epoch", error)
    }

    override fun encrypt(epoch: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
        validate(epoch, aad)
        if (plaintext.isEmpty() || plaintext.size > MAX_PLAINTEXT_BYTES) {
            throw VoiceSignalReplayException("Dispatch epoch plaintext size invalid")
        }
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, requireExistingKey(epoch))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES) throw VoiceSignalReplayException("Invalid dispatch epoch IV")
            iv + ciphertext
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot seal isolated dispatch epoch", error)
        }
    }

    override fun decrypt(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        validate(epoch, aad)
        if (ciphertext.size !in (IV_BYTES + TAG_BYTES + 1)..MAX_ENVELOPE_BYTES) {
            throw VoiceSignalReplayException("Dispatch epoch ciphertext size invalid")
        }
        return try {
            Cipher.getInstance(AES_GCM).run {
                init(
                    Cipher.DECRYPT_MODE,
                    requireExistingKey(epoch),
                    GCMParameterSpec(TAG_BYTES * 8, ciphertext.copyOfRange(0, IV_BYTES)),
                )
                updateAAD(aad)
                doFinal(ciphertext.copyOfRange(IV_BYTES, ciphertext.size))
            }
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot authenticate isolated dispatch epoch", error)
        }
    }

    override fun retireEpoch(epoch: String) {
        checkEpoch(epoch)
        try {
            val alias = aliasPrefix + epoch
            if (!store.containsAlias(alias)) {
                throw VoiceSignalReplayException("Cannot retire missing dispatch epoch")
            }
            store.deleteEntry(alias)
            if (store.containsAlias(alias)) {
                throw VoiceSignalReplayException("Dispatch epoch deletion not confirmed")
            }
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot retire isolated dispatch epoch", error)
        }
    }

    private fun allocateUniqueEpochId(): String {
        repeat(4) {
            val candidate = ByteArray(16).also(random::nextBytes).joinToString("") {
                HEX[(it.toInt() and 0xff) ushr 4].toString() +
                    HEX[it.toInt() and 0x0f].toString()
            }
            if (!store.containsAlias(aliasPrefix + candidate)) return candidate
        }
        throw VoiceSignalReplayException("Cannot allocate an unused dispatch Keystore epoch")
    }

    private fun requireExistingKey(epoch: String): SecretKey =
        (store.getKey(aliasPrefix + epoch, null) as? SecretKey)
            ?: throw VoiceSignalReplayException("Isolated dispatch Keystore epoch missing")

    private fun validate(epoch: String, aad: ByteArray) {
        checkEpoch(epoch)
        val expected = AAD_PREFIX + epoch.toByteArray(Charsets.US_ASCII)
        if (!aad.contentEquals(expected)) {
            throw VoiceSignalReplayException("Dispatch epoch owner AAD is invalid")
        }
    }

    private fun checkEpoch(epoch: String) {
        if (!EPOCH_PATTERN.matches(epoch)) {
            throw VoiceSignalReplayException("Dispatch epoch alias identifier invalid")
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val HEX = "0123456789abcdef"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
        const val MAX_PLAINTEXT_BYTES = 70 * 1024
        const val MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + IV_BYTES + TAG_BYTES
        val AAD_PREFIX = "KENATO-M5-DISPATCH-EPOCH-V1\u0000".toByteArray(Charsets.UTF_8)
        val EPOCH_PATTERN = Regex("[0-9a-f]{32}")
        val ACCEPTANCE_PREFIX =
            Regex("com[.]sl[.]kenato[.]dispatch[.]epoch-acceptance[.]v1[.][0-9a-f]{32}[.]")
    }
}

/**
 * A disposable, no-backup AtomicFile for isolated KDL1 research.
 * No production journal or capability filename can be selected.
 */
internal class AndroidAtomicFileVoiceDispatchLedgerRawStore(
    context: Context,
    fileName: String,
) : VoiceDispatchLedgerRawStore {
    init {
        require(ACCEPTANCE_FILE.matches(fileName)) {
            "KDL1 probe requires its own random disposable no-backup file"
        }
    }
    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, fileName))

    override fun read(): ByteArray? {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot open isolated dispatch ledger file", error)
        }
        return try {
            input.use {
                val length = file.baseFile.length()
                if (length !in 1..MAX_FILE_BYTES.toLong()) {
                    throw VoiceSignalReplayException("Isolated dispatch file length invalid")
                }
                val output = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(4096)
                var count = 0
                while (true) {
                    val n = it.read(buffer)
                    if (n < 0) break
                    count += n
                    if (count > MAX_FILE_BYTES) {
                        throw VoiceSignalReplayException("Dispatch file exceeded bounded read")
                    }
                    output.write(buffer, 0, n)
                }
                output.toByteArray()
            }
        } catch (error: VoiceSignalReplayException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot read isolated dispatch ledger file", error)
        }
    }

    override fun write(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.size > MAX_FILE_BYTES) {
            throw VoiceSignalReplayException("Isolated dispatch write size invalid")
        }
        val output = try {
            file.startWrite()
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot start isolated dispatch atomic write", error)
        }
        return try {
            output.write(bytes)
            output.fd.sync()
            file.finishWrite(output)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(output) }
            throw VoiceSignalReplayException("Cannot commit isolated dispatch ledger file", error)
        }
    }

    private companion object {
        const val MAX_FILE_BYTES = 70 * 1024
        val ACCEPTANCE_FILE = Regex("kenato_m5_dispatch_probe_[0-9a-f]{32}[.]bin")
    }
}
