package org.ratspeak.android.ethereum

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CustodyOperationSessionsTest {
    @Test
    fun terminalOwnershipAndDeliveryAreExactlyOnce() {
        val sessions = CustodyOperationSessions()
        var abandoned = 0
        var delivered = 0
        var discarded = 0
        val token = sessions.begin { abandoned++ }!!

        assertTrue(sessions.claim(token))
        assertFalse(sessions.claim(token))
        sessions.abandonClaimed(token)
        sessions.abandonClaimed(token)
        sessions.finishAndDeliver(token, "first", { discarded++ }) { delivered++ }
        sessions.finishAndDeliver(token, "stale", { discarded++ }) { delivered++ }

        assertEquals(1, abandoned)
        assertEquals(1, delivered)
        assertEquals(1, discarded)
        assertNotNull(sessions.begin {})
    }

    @Test
    fun staleTokenCannotClaimOrAffectNewOperation() {
        val sessions = CustodyOperationSessions()
        val first = sessions.begin {}!!
        assertTrue(sessions.claim(first))
        sessions.abandonClaimed(first)
        sessions.finishAndDeliver(first, Unit, {}, {})

        val second = sessions.begin {}!!
        var staleDiscarded = 0
        assertFalse(sessions.claim(first))
        sessions.finishAndDeliver(first, Unit, { staleDiscarded++ }) {
            throw AssertionError("stale result delivered")
        }

        assertEquals(1, staleDiscarded)
        assertTrue(sessions.claim(second))
    }

    @Test
    fun closeCancelsAndClearsAnUnclaimedOperation() {
        val sessions = CustodyOperationSessions()
        var cancelled = 0
        var abandoned = 0
        val token = sessions.begin { abandoned++ }!!
        assertTrue(sessions.attachCancellation(token) { cancelled++ })

        sessions.close()
        sessions.close()

        assertEquals(1, cancelled)
        assertEquals(1, abandoned)
        assertFalse(sessions.claim(token))
        assertNull(sessions.begin {})
    }

    @Test
    fun closeAfterClaimBlocksDeliveryAndDiscardsSensitiveResult() {
        val sessions = CustodyOperationSessions()
        val token = sessions.begin {}!!
        assertTrue(sessions.claim(token))
        sessions.close()
        val result = TrackingCloseable()

        sessions.finishAndDeliver(token, result, TrackingCloseable::close) {
            throw AssertionError("closed session delivered")
        }

        assertEquals(1, result.closeCount)
    }

    @Test
    fun callbackExceptionDiscardsResultAndDoesNotWedgeSessions() {
        val sessions = CustodyOperationSessions()
        val token = sessions.begin {}!!
        assertTrue(sessions.claim(token))
        val result = TrackingCloseable()

        sessions.finishAndDeliver(token, result, TrackingCloseable::close) {
            throw IllegalStateException("callback failed")
        }

        assertEquals(1, result.closeCount)
        assertNotNull(sessions.begin {})
    }

    @Test
    fun cleanupExceptionsDoNotEscapeClose() {
        val sessions = CustodyOperationSessions()
        val token = sessions.begin { throw IllegalStateException("abandon failed") }!!
        assertTrue(sessions.attachCancellation(token) { throw IllegalStateException("cancel failed") })

        sessions.close()

        assertFalse(sessions.claim(token))
    }

    private class TrackingCloseable : AutoCloseable {
        var closeCount = 0

        override fun close() {
            closeCount++
        }
    }
}
