package com.sl.kenato.storage

/**
 * One owner per canonical app-private storage directory in this process.
 * Failed construction is never cached. No cross-process or cross-store
 * transaction is implied by this registry.
 */
internal class ProcessLocalOwnerRegistry<T : Any> {
    private val owners = HashMap<String, T>()

    @Synchronized
    fun getOrCreate(storageDirectory: String, create: () -> T): T {
        require(storageDirectory.isNotBlank()) { "Canonical storage directory is required" }
        return owners.getOrPut(storageDirectory, create)
    }
}
