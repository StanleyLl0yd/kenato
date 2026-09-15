package com.sl.kenato.messaging

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssSocketPolicyTest {
    @Test
    fun factoryOwnedClientDoesNotFollowRedirectsOrInstallInterceptors() {
        val client = OkHttpMessagingSocketFactory.buildMessagingClient()

        assertFalse(client.followRedirects)
        assertFalse(client.followSslRedirects)
        assertTrue(client.interceptors.isEmpty())
        assertTrue(client.networkInterceptors.isEmpty())
    }
}
