package com.sl.kenato.contact

import java.net.URI
import org.junit.Assert.assertThrows
import org.junit.Test

class ContactTransportTest {
    @Test
    fun acceptsCanonicalHttpsOrigin() {
        HttpContactTransport(URI("https://example.test"))
        HttpContactTransport(URI("https://example.test:8443/"))
    }

    @Test
    fun rejectsNonHttpsOrNonOriginConfiguration() {
        val invalid = listOf(
            "http://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test/?query=1",
            "https://example.test/#fragment",
            "https:///missing-host",
        )

        invalid.forEach { raw ->
            assertThrows(ContactTransportException::class.java) {
                HttpContactTransport(URI(raw))
            }
        }
    }
}
