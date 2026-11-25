package com.sl.kenato

/**
 * One process-local transport owner per private storage directory.
 * This gate is neither a cross-process lease nor durable rollback protection.
 * Runtime operations and transport callbacks take this monitor before WSS.
 */
internal class M45ProcessTransportGate {
    @Volatile var mutationEpoch: Long = 0L
        private set
    private var activeOwner: Any? = null
    private var generation = 0L
    private var callbacksEnabled = false
    private var poisoned = false

    @Synchronized
    fun requireAvailable(owner: Any) {
        check(!poisoned) { "Process WSS safety state is uncertain" }
        check(activeOwner == null || activeOwner === owner) {
            "Another acceptance runtime owns the process WSS transport"
        }
    }

    @Synchronized
    fun claim(owner: Any) {
        requireAvailable(owner)
        if (activeOwner === owner && callbacksEnabled) return
        check(generation < Long.MAX_VALUE) { "Transport callback generation exhausted" }
        generation++
        activeOwner = owner
        callbacksEnabled = true
    }

    @Synchronized
    fun suspendCallbacks(owner: Any) {
        if (activeOwner === owner) callbacksEnabled = false
    }

    @Synchronized
    fun release(owner: Any) {
        if (activeOwner === owner) {
            callbacksEnabled = false
            activeOwner = null
        }
    }

    @Synchronized
    fun poison() {
        poisoned = true
        callbacksEnabled = false
    }

    @Synchronized
    fun isPoisoned(): Boolean = poisoned

    @Synchronized
    fun captureCallbackPermission(owner: Any): () -> Boolean {
        val capturedGeneration = generation
        val admitted = !poisoned && callbacksEnabled && activeOwner === owner
        return {
            synchronized(this) {
                admitted && !poisoned && callbacksEnabled &&
                    activeOwner === owner && generation == capturedGeneration
            }
        }
    }

    @Synchronized
    fun beginMutation(owner: Any) {
        requireAvailable(owner)
        check(mutationEpoch % 2L == 0L && mutationEpoch < Long.MAX_VALUE - 1L) {
            "Process trust mutation generation unavailable"
        }
        mutationEpoch++
    }

    @Synchronized
    fun endMutation() {
        check(mutationEpoch % 2L == 1L) { "No process trust mutation in progress" }
        mutationEpoch++
    }
}
