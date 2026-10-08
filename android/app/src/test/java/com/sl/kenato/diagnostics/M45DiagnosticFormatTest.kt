package com.sl.kenato.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class M45DiagnosticFormatTest {
    @Test
    fun ringRetainsOnlyTheNewestCodes() {
        var current = ""
        repeat(150) {
            current = M45DiagnosticFormat.append(
                current,
                "2026-10-08T12:00:00Z",
                if (it % 2 == 0) M45DiagnosticEvent.CONNECT_ATTEMPT else M45DiagnosticEvent.SOCKET_CLOSED,
            )
        }

        val rows = current.lines()
        assertEquals(M45DiagnosticFormat.MAX_ENTRIES, rows.size)
        assertEquals("2026-10-08T12:00:00Z CONNECT_ATTEMPT", rows.first())
        assertEquals("2026-10-08T12:00:00Z SOCKET_CLOSED", rows.last())
    }

    @Test
    fun onlyReviewedEventCodesCanEnterTheJournal() {
        val entry = M45DiagnosticFormat.append("", "2026-10-08T12:00:00Z", M45DiagnosticEvent.IDENTITY_SIGNING_FAILED)
        assertTrue(entry.endsWith(" IDENTITY_SIGNING_FAILED"))
        assertFalse(entry.contains("key="))
        assertFalse(entry.contains("identity="))
        assertFalse(entry.contains("http"))
    }
}
