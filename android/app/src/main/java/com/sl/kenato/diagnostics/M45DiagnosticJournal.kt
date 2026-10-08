package com.sl.kenato.diagnostics

import android.content.Context
import java.time.Instant

/**
 * Closed-cohort diagnostic codes only: no free-text exception messages, IP addresses,
 * identities, invitations, URLs, payloads, keys, plaintext or ciphertext are accepted.
 */
internal enum class M45DiagnosticEvent {
    TRANSPORT_STARTED,
    TRANSPORT_STOPPED,
    CONNECT_ATTEMPT,
    SOCKET_UPGRADED,
    AUTH_CHALLENGE_RECEIVED,
    AUTH_CHALLENGE_REJECTED,
    LOCAL_IDENTITY_INVALID,
    IDENTITY_SIGNING_FAILED,
    AUTH_RESPONSE_SENT,
    AUTHENTICATED,
    AUTH_CONFIRMATION_REJECTED,
    SERVER_FRAME_INVALID,
    SERVER_PROTOCOL_REJECTED,
    SOCKET_CLOSED,
    TRANSPORT_CERTIFICATE_ERROR,
    TRANSPORT_DNS_ERROR,
    TRANSPORT_TIMEOUT,
    TRANSPORT_CONNECT_ERROR,
    TRANSPORT_HTTP_4XX,
    TRANSPORT_HTTP_5XX,
    TRANSPORT_IO_ERROR,
    TRANSPORT_OTHER_ERROR,
    RECONNECT_SCHEDULED,
    RECONNECT_EXHAUSTED,
    RECOVERY_FAILED,
    TRANSPORT_FAILED_CLOSED,
}

/** Pure formatter for a strictly bounded, identifier-free diagnostic ring. */
internal object M45DiagnosticFormat {
    const val MAX_ENTRIES = 128

    fun append(current: String, timestamp: String, event: M45DiagnosticEvent): String {
        // Timestamp is generated locally, and event names come exclusively from an enum.
        val existing = current.lineSequence().filter { it.isNotBlank() }.toList()
        return (existing.takeLast(MAX_ENTRIES - 1) + "$timestamp ${event.name}").joinToString("\n")
    }
}

/**
 * App-private persistence. Android backup is disabled for Kenato; no external endpoint,
 * analytics package or background diagnostic upload is involved.
 */
internal class M45DiagnosticJournal(context: Context) {
    private val store = context.applicationContext.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)

    fun record(event: M45DiagnosticEvent) {
        synchronized(LOCK) {
            // Diagnostics are best effort and must never alter fail-closed transport behavior.
            runCatching {
                val current = store.getString(KEY_ENTRIES, "").orEmpty()
                val next = M45DiagnosticFormat.append(current, Instant.now().toString(), event)
                store.edit().putString(KEY_ENTRIES, next).commit()
            }
        }
    }

    fun snapshot(): List<String> = synchronized(LOCK) {
        runCatching {
            store.getString(KEY_ENTRIES, "").orEmpty()
                .lineSequence().filter { it.isNotBlank() }.toList()
                .takeLast(M45DiagnosticFormat.MAX_ENTRIES)
        }.getOrDefault(emptyList())
    }

    fun clear(): Boolean = synchronized(LOCK) {
        runCatching { store.edit().remove(KEY_ENTRIES).commit() }.getOrDefault(false)
    }

    private companion object {
        val LOCK = Any()
        const val STORE_NAME = "kenato_m45_diagnostics_v1"
        const val KEY_ENTRIES = "events"
    }
}
