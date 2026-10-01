package org.ratspeak.android.ethereum

import java.io.ByteArrayInputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumGatewayPairingTest {
    @Test
    fun checkpointAndGatewayPickersShareOneReservation() {
        val gateway = "c1".repeat(32)
        val checkpoint = "c2".repeat(32)
        assertTrue(EthereumGatewayCardFileImportLauncher.reserve(gateway))
        assertFalse(EthereumCheckpointFileImportLauncher.reserve(checkpoint))
        assertTrue(EthereumGatewayCardFileImportLauncher.release(gateway))
        assertTrue(EthereumCheckpointFileImportLauncher.reserve(checkpoint))
        assertTrue(EthereumCheckpointFileImportLauncher.release(checkpoint))
    }

    @Test
    fun cancelBeforeReaderStartsReleasesOnlyThatSession() {
        val first = "d1".repeat(32)
        val second = "d2".repeat(32)
        assertTrue(EthereumDocumentReadExecutor.reserveUnstartedForTest(first))
        assertTrue(EthereumDocumentReadExecutor.cancel(first))
        assertFalse(EthereumDocumentReadExecutor.isBusy())
        assertTrue(EthereumDocumentReadExecutor.reserveUnstartedForTest(second))
        assertTrue(EthereumDocumentReadExecutor.cancel(second))
        assertFalse(EthereumDocumentReadExecutor.isBusy())
    }

    @Test
    fun importReservationAllowsOnlyOneConcurrentPicker() {
        val start = CountDownLatch(1)
        val successes = AtomicInteger(0)
        val threads = (0 until 8).map { index ->
            Thread {
                start.await()
                if (EthereumGatewayCardFileImportLauncher.reserve("%02x".format(index).repeat(32))) {
                    successes.incrementAndGet()
                }
            }
        }
        threads.forEach(Thread::start)
        start.countDown()
        threads.forEach(Thread::join)
        assertEquals(1, successes.get())
        val active = synchronized(EthereumGatewayCardFileImportLauncher) {
            // The reservation token is intentionally not exposed to callers;
            // release each known candidate to clean up the test process state.
            (0 until 8).firstOrNull { index ->
                EthereumGatewayCardFileImportLauncher.release("%02x".format(index).repeat(32))
            }
        }
        assertNotNull(active)
    }

    @Test
    fun watchdogIsOneShotAndAllowsAFreshPicker() {
        val first = "aa".repeat(32)
        val second = "bb".repeat(32)
        assertTrue(EthereumGatewayCardFileImportLauncher.reserve(first))
        EthereumGatewayCardFileImportLauncher.timeoutForTest(first)
        EthereumGatewayCardFileImportLauncher.timeoutForTest(first)
        assertTrue(EthereumGatewayCardFileImportLauncher.reserve(second))
        assertTrue(EthereumGatewayCardFileImportLauncher.release(second))
    }

    @Test
    fun boundedReaderEnforcesRseg1Limit() {
        val exact = ByteArray(EthereumGatewayCardFileImportLauncher.MAX_FILE_BYTES) { 0x52 }
        assertEquals(exact.size, EthereumGatewayCardFileImportLauncher.readBounded(ByteArrayInputStream(exact))?.size)
        assertNull(
            EthereumGatewayCardFileImportLauncher.readBounded(
                ByteArrayInputStream(ByteArray(exact.size + 1) { 0x52 }),
            ),
        )
    }

    @Test
    fun projectionDecoderAcceptsOnlyExactPublicFrame() {
        val frame = "RSETHGR1".toByteArray().toMutableList().apply {
            addAll("11".repeat(16).toByteArray().toList())
            addAll("22".repeat(32).toByteArray().toList())
            addAll(ByteArray(8) { index -> if (index == 7) 9 else 0 }.toList())
        }.toByteArray()
        val projection = GatewayCardReviewProjection.decode(frame)
        assertNotNull(projection)
        assertEquals("0x${"11".repeat(16)}", projection!!.destinationHash)
        assertEquals("0x${"22".repeat(32)}", projection.publicKeyFingerprint)
        assertEquals(9L, projection.expiresAtUnix)
        assertNull(GatewayCardReviewProjection.decode(frame + byteArrayOf(0)))
        repeat(32) { frame[8 + it] = '0'.code.toByte() }
        assertNull(GatewayCardReviewProjection.decode(frame))
        assertTrue(EthereumGatewayCardFileImportLauncher.isValidToken("ab".repeat(32)))
    }
}
