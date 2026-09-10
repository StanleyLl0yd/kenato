package com.sl.kenato.identity

import android.content.Context
import java.util.Base64

internal interface IdentityStateStore {
    fun read(): ByteArray?

    fun write(value: ByteArray): Boolean

    fun clear(): Boolean
}

internal class SharedPreferencesIdentityStateStore(context: Context) : IdentityStateStore {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    override fun read(): ByteArray? {
        val encoded = preferences.getString(STATE_KEY, null) ?: return null
        if (encoded.length > MAX_ENCODED_STATE_CHARS) {
            throw IdentityStateException("Persisted identity state is too large")
        }

        return try {
            decoder.decode(encoded).also {
                if (it.isEmpty() || it.size > IdentityStateCodec.MAX_STATE_BYTES) {
                    throw IdentityStateException("Persisted identity state size is invalid")
                }
            }
        } catch (error: IdentityStateException) {
            throw error
        } catch (error: IllegalArgumentException) {
            throw IdentityStateException("Persisted identity state encoding is invalid", error)
        }
    }

    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > IdentityStateCodec.MAX_STATE_BYTES) {
            throw IdentityStateException("Identity state size is invalid")
        }
        return preferences.edit().putString(STATE_KEY, encoder.encodeToString(value)).commit()
    }

    override fun clear(): Boolean = preferences.edit().remove(STATE_KEY).commit()

    private companion object {
        const val PREFERENCES_NAME = "kenato_identity_v1"
        const val STATE_KEY = "state"
        const val MAX_ENCODED_STATE_CHARS = IdentityStateCodec.MAX_STATE_BYTES * 2
    }
}
