package org.ratspeak.android.ethereum

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumCheckpointReviewTest {
    @Test
    fun projectionContainsOnlyBoundedPublicCheckpointFields() {
        val projection = CheckpointReviewProjection.decode(frame())

        assertNotNull(projection)
        assertEquals("sepolia", projection?.network)
        assertEquals("qr", projection?.source)
        assertEquals("0x" + "11".repeat(32), projection?.sourceFingerprint)
        assertEquals(42L, projection?.checkpointEpoch)
        assertEquals("0x" + "22".repeat(32), projection?.checkpointRoot)
        assertEquals("0x" + "33".repeat(32), projection?.canonicalBootstrapHash)
        assertEquals(1_700_000_000L, projection?.observedAtUnix)
        assertEquals(1_700_000_600L, projection?.validUntilUnix)
        assertEquals(1_700_000_300L, projection?.expiresAtUnix)
    }

    @Test
    fun parserRejectsTamperingTruncationInvalidSourceAndExpiryOrder() {
        val original = frame()
        assertNull(CheckpointReviewProjection.decode(original.copyOf(original.size - 1)))
        assertNull(CheckpointReviewProjection.decode(original.copyOf().also { it[0] = 'X'.code.toByte() }))
        assertNull(CheckpointReviewProjection.decode(original.copyOf().also { it[19] = 'x'.code.toByte() }))

        val invalidOrder = frame(validUntil = 1_700_000_000L)
        assertNull(CheckpointReviewProjection.decode(invalidOrder))

        assertNull(CheckpointReviewProjection.decode(frame(sourceFingerprint = "0".repeat(64))))
        assertNull(CheckpointReviewProjection.decode(frame(checkpointRoot = "0".repeat(64))))
        assertNull(CheckpointReviewProjection.decode(frame(bootstrapHash = "0".repeat(64))))
    }

    @Test
    fun sourceKindsAreTheOnlyOutOfBandLabelsShownToTheUser() {
        for (source in listOf("url", "file", "qr")) {
            val projection = CheckpointReviewProjection.decode(frame(source = source))
            assertEquals(source, projection?.source)
        }
        assertNull(CheckpointReviewProjection.decode(frame(source = "gateway")))
    }

    @Test
    fun decisionCallbackIsExplicitAndExactlyOnce() {
        val calls = AtomicInteger()
        var decision = false
        val request = EthereumCheckpointReviewLauncher.Request(
            token = "ab".repeat(32),
            projection = requireNotNull(CheckpointReviewProjection.decode(frame())),
            onDecision = { _, approved ->
                calls.incrementAndGet()
                decision = approved
            },
        )

        request.decide(false)
        request.decide(true)

        assertEquals(1, calls.get())
        assertFalse(decision)
    }

    @Test
    fun abandonIsNotAnImplicitDenialAndCannotReplay() {
        val calls = AtomicInteger()
        val request = EthereumCheckpointReviewLauncher.Request(
            token = "cd".repeat(32),
            projection = requireNotNull(CheckpointReviewProjection.decode(frame())),
            onDecision = { _, _ -> calls.incrementAndGet() },
        )

        request.abandon()
        request.decide(false)

        assertEquals(0, calls.get())
    }

    @Test
    fun launcherRejectsWrongAndReplayedTokens() {
        assertNull(EthereumCheckpointReviewLauncher.consume("not-a-token"))
        assertNull(EthereumCheckpointReviewLauncher.consume("ab".repeat(32)))
    }

    private fun frame(
        source: String = "qr",
        sourceFingerprint: String = "11".repeat(32),
        checkpointRoot: String = "22".repeat(32),
        bootstrapHash: String = "33".repeat(32),
        validUntil: Long = 1_700_000_600L,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        output.write("RSETHCP1".toByteArray(StandardCharsets.US_ASCII))
        field(output, "sepolia")
        field(output, source)
        output.write(sourceFingerprint.toByteArray(StandardCharsets.US_ASCII))
        output.write(ByteBuffer.allocate(8).putLong(42).array())
        output.write(checkpointRoot.toByteArray(StandardCharsets.US_ASCII))
        output.write(bootstrapHash.toByteArray(StandardCharsets.US_ASCII))
        output.write(ByteBuffer.allocate(8).putLong(1_700_000_000L).array())
        output.write(ByteBuffer.allocate(8).putLong(validUntil).array())
        output.write(ByteBuffer.allocate(8).putLong(1_700_000_300L).array())
        return output.toByteArray()
    }

    private fun field(output: ByteArrayOutputStream, value: String) {
        output.write(value.length)
        output.write(value.toByteArray(StandardCharsets.US_ASCII))
    }
}
