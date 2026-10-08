package com.sl.kenato.messaging

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingSocketDiagnosticClassificationTest {
    @Test
    fun explicitProtocolFailuresRetainFailClosedTypeEvenWithHttpResponse() {
        val protocol = MessagingWssException("protocol rejection")
        assertSame(protocol, classifyMessagingSocketFailure(protocol, 400))
    }

    @Test
    fun ordinaryHttpUpgradeRejectionRetainsOnlyStatusCode() {
        val original = IOException("Sensitive upstream error details")
        val categorized = classifyMessagingSocketFailure(original, 403)
        assertTrue(categorized is MessagingHttpUpgradeFailure)
        assertEquals(403, (categorized as MessagingHttpUpgradeFailure).statusCode)
        assertEquals("WebSocket upgrade rejected", categorized.message)
    }

    @Test
    fun absentHttpResponsePreservesOriginalTransportFailure() {
        val failure = IOException("transport failed")
        assertSame(failure, classifyMessagingSocketFailure(failure, null))
    }
}
