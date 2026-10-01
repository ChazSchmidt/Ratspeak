package org.ratspeak.android.ethereum

import java.io.InputStream
import java.io.ByteArrayInputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumCheckpointFileImportTest {
    @Test
    fun tokenValidationRejectsForgedOrWrongLengthValues() {
        assertTrue(EthereumCheckpointFileImportLauncher.isValidToken("ab".repeat(32)))
        assertFalse(EthereumCheckpointFileImportLauncher.isValidToken("not-a-token"))
        assertFalse(EthereumCheckpointFileImportLauncher.isValidToken("ab".repeat(31)))
        assertFalse(EthereumCheckpointFileImportLauncher.isValidToken("zz".repeat(32)))
    }

    @Test
    fun boundedReaderRejectsRepeatedZeroReads() {
        val broken = object : InputStream() {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int = 0
            override fun read(): Int = 0
        }
        assertNull(EthereumCheckpointFileImportLauncher.readBounded(broken))
    }

    @Test
    fun boundedReaderAcceptsExactLimitAndRejectsOneByteOver() {
        val exact = ByteArray(EthereumCheckpointFileImportLauncher.MAX_FILE_BYTES) { 0x5a }
        assertTrue(
            EthereumCheckpointFileImportLauncher.readBounded(ByteArrayInputStream(exact))
                ?.size == EthereumCheckpointFileImportLauncher.MAX_FILE_BYTES
        )
        exact.fill(0)
        val over = ByteArray(EthereumCheckpointFileImportLauncher.MAX_FILE_BYTES + 1) { 0x5a }
        assertNull(EthereumCheckpointFileImportLauncher.readBounded(ByteArrayInputStream(over)))
        over.fill(0)
    }

    @Test
    fun resultClaimIsOneShotAndKeepsReservationUntilRelease() {
        val token = "ab".repeat(32)
        assertTrue(EthereumCheckpointFileImportLauncher.reserve(token))
        assertFalse(EthereumCheckpointFileImportLauncher.reserve("cd".repeat(32)))
        assertTrue(EthereumCheckpointFileImportLauncher.claimResult(token))
        assertFalse(EthereumCheckpointFileImportLauncher.claimResult(token))
        assertFalse(EthereumCheckpointFileImportLauncher.reserve("ef".repeat(32)))
        // A canceled or completed worker releases the reservation in finally;
        // emulate that lifecycle without invoking JNI in this unit test.
        assertTrue(EthereumCheckpointFileImportLauncher.release(token))
        assertTrue(EthereumCheckpointFileImportLauncher.reserve("ef".repeat(32)))
        EthereumCheckpointFileImportLauncher.release("ef".repeat(32))
    }

    @Test
    fun staleWatchdogCannotReleaseLaterImport() {
        val first = "11".repeat(32)
        val second = "22".repeat(32)
        assertTrue(EthereumCheckpointFileImportLauncher.reserve(first))
        assertTrue(EthereumCheckpointFileImportLauncher.release(first))
        assertTrue(EthereumCheckpointFileImportLauncher.reserve(second))
        EthereumCheckpointFileImportLauncher.timeoutForTest(first)
        assertFalse(EthereumCheckpointFileImportLauncher.reserve("33".repeat(32)))
        assertTrue(EthereumCheckpointFileImportLauncher.release(second))
    }
}
