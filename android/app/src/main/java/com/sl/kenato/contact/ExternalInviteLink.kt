package com.sl.kenato.contact

/** Untrusted Android VIEW intent boundary. This only canonicalizes; redemption remains explicit. */
internal object ExternalInviteLink {
    fun canonicalOrNull(value: String?): String? {
        if (value == null) return null
        val invite = runCatching { InviteUriCodec.decode(value) }.getOrNull() ?: return null
        return runCatching { InviteUriCodec.encode(invite) }
            .getOrNull()
            ?.takeIf { it == value }
    }
}
