package org.ratspeak.android.ethereum

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumBulkEvidenceReviewTest {
    @Test
    fun projectionContainsOnlyPublicReviewFieldsAndCheckpoint() {
        val projection = BulkEvidenceReviewProjection.decode(frame(withCheckpoint = true))

        assertNotNull(projection)
        assertEquals("0x" + "11".repeat(16), projection?.gateway)
        assertEquals("consensus", projection?.kind)
        assertEquals("0x" + "22".repeat(32), projection?.subject)
        assertEquals(42L, projection?.checkpointEpoch)
        assertEquals("0x" + "33".repeat(32), projection?.checkpointRoot)
        assertEquals("0x" + "44".repeat(32), projection?.manifestDigest)
        assertEquals(8192L, projection?.encodedSize)
        assertEquals(1_700_000_000_000L, projection?.expiresAtEpochMillis)
    }

    @Test
    fun forgedOrTamperedProjectionFieldsAreRejected() {
        val original = frame(withCheckpoint = false)
        assertNull(BulkEvidenceReviewProjection.decode(original + byteArrayOf(1)))

        val badMagic = original.copyOf().also { it[0] = 'X'.code.toByte() }
        assertNull(BulkEvidenceReviewProjection.decode(badMagic))

        // The first length-delimited field is the 16-byte gateway hash.
        val badGateway = original.copyOf().also { it[9] = 'z'.code.toByte() }
        assertNull(BulkEvidenceReviewProjection.decode(badGateway))
    }

    @Test
    fun decisionCallbackIsOneShotAndDoesNotCarryProjection() {
        val calls = AtomicInteger()
        var receivedToken = ""
        var receivedDecision = false
        val request = EthereumBulkEvidenceReviewLauncher.Request(
            token = "ab".repeat(32),
            projection = requireNotNull(BulkEvidenceReviewProjection.decode(frame(false))),
            onDecision = { token, approved ->
                calls.incrementAndGet()
                receivedToken = token
                receivedDecision = approved
            },
        )

        request.decide(true)
        request.decide(false)

        assertEquals(1, calls.get())
        assertEquals("ab".repeat(32), receivedToken)
        assertTrue(receivedDecision)
    }

    @Test
    fun abandonReleasesOnlyProcessSessionAndCannotBecomeDurableDenial() {
        val calls = AtomicInteger()
        val request = EthereumBulkEvidenceReviewLauncher.Request(
            token = "cd".repeat(32),
            projection = requireNotNull(BulkEvidenceReviewProjection.decode(frame(false))),
            onDecision = { _, _ -> calls.incrementAndGet() },
        )

        request.abandon()
        request.decide(false)

        assertEquals(0, calls.get())
    }

    @Test
    fun forgedOrReplayedLauncherTokensCannotBeConsumed() {
        assertNull(EthereumBulkEvidenceReviewLauncher.consume("not-a-token"))
        assertNull(EthereumBulkEvidenceReviewLauncher.consume("ab".repeat(32)))
    }

    private fun frame(withCheckpoint: Boolean): ByteArray {
        val output = ByteArrayOutputStream()
        output.write("RSETHBR1".toByteArray(StandardCharsets.US_ASCII))
        field(output, "11".repeat(16))
        field(output, "consensus")
        field(output, "22".repeat(32))
        if (withCheckpoint) {
            output.write(1)
            output.write(ByteBuffer.allocate(8).putLong(42).array())
            output.write("33".repeat(32).toByteArray(StandardCharsets.US_ASCII))
        } else {
            output.write(0)
        }
        field(output, "44".repeat(32))
        output.write(ByteBuffer.allocate(4).putInt(8192).array())
        output.write(ByteBuffer.allocate(8).putLong(1_700_000_000_000L).array())
        return output.toByteArray()
    }

    private fun field(output: ByteArrayOutputStream, value: String) {
        output.write(value.length)
        output.write(value.toByteArray(StandardCharsets.US_ASCII))
    }
}
