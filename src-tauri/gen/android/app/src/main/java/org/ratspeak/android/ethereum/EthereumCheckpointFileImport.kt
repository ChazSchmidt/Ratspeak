package org.ratspeak.android.ethereum

import android.app.Activity
import android.content.ContentResolver
import android.content.Intent
import android.os.Handler
import android.os.Looper
import java.io.InputStream

/**
 * Native-only handoff for a user-selected checkpoint card.  The document URI
 * never crosses this boundary and is not persisted; only the process-local
 * Rust token and bounded bytes are passed to JNI.
 */
internal object EthereumCheckpointFileImportLauncher {
    /** Must remain equal to Rust's MAX_MANUAL_CHECKPOINT_FILE_BYTES (2 MiB). */
    internal const val MAX_FILE_BYTES = 2 * 1024 * 1024
    private const val READ_CHUNK_BYTES = 8 * 1024
    private val TOKEN = Regex("^[0-9a-fA-F]{64}$")
    private var activeToken: String? = null
    private var resultClaimed = false
    private val timeoutHandler: Handler by lazy { Handler(Looper.getMainLooper()) }
    private var timeoutRunnable: Runnable? = null

    @Synchronized
    internal fun reserve(token: String): Boolean {
        if (!TOKEN.matches(token) || activeToken != null ||
            !EthereumDocumentReadCoordinator.reserve(
                EthereumDocumentReadCoordinator.Kind.CHECKPOINT,
                token,
            )
        ) return false
        activeToken = token
        resultClaimed = false
        return true
    }

    @Synchronized
    private fun active(): String? = activeToken

    @Synchronized
    internal fun release(token: String): Boolean {
        if (activeToken != token) return false
        activeToken = null
        resultClaimed = false
        timeoutRunnable?.let(timeoutHandler::removeCallbacks)
        timeoutRunnable = null
        EthereumDocumentReadCoordinator.release(
            EthereumDocumentReadCoordinator.Kind.CHECKPOINT,
            token,
        )
        return true
    }

    @Synchronized
    internal fun claimResult(token: String): Boolean {
        if (activeToken != token || resultClaimed) return false
        resultClaimed = true
        return true
    }

    internal fun isValidToken(token: String): Boolean = TOKEN.matches(token)

    /** Starts an import after MainActivity has reserved the one concurrent slot. */
    internal fun launch(
        token: String,
        startPicker: (Intent) -> Unit,
    ): Boolean {
        if (!reserve(token)) return false
        return try {
            scheduleTimeout(token)
            startPicker(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            })
            true
        } catch (_: Throwable) {
            if (release(token)) RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
            false
        }
    }

    @Synchronized
    private fun scheduleTimeout(token: String) {
        val timeout = Runnable { timeout(token) }
        timeoutRunnable = timeout
        timeoutHandler.postDelayed(timeout, IMPORT_TIMEOUT_MILLIS)
    }

    private fun timeout(token: String) {
        if (release(token)) {
            EthereumDocumentReadExecutor.cancel(token)
            RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
        }
    }

    /** Deterministic lifecycle hook used by unit tests for the watchdog. */
    internal fun timeoutForTest(token: String) = timeout(token)

    /** Called by MainActivity's pre-registered ActivityResult launcher. */
    internal fun onResult(
        resolver: ContentResolver,
        resultCode: Int,
        data: Intent?,
    ) {
        val token = active() ?: return
        if (!claimResult(token)) return
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            if (release(token)) RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
            return
        }

        // The provider grant is transient.  Do not call takePersistableUriPermission
        // and do not retain the URI beyond this worker invocation.
        val submitted = synchronized(this) {
            if (activeToken != token) {
                false
            } else {
                EthereumDocumentReadExecutor.submit(
                    token,
                    resolver,
                    uri,
                    ::readBounded,
                    { bytes ->
                        synchronized(this) {
                            // Serialize the timeout decision with the JNI handoff:
                            // once the watchdog wins, bytes cannot be imported.
                            if (activeToken == token) {
                                if (bytes == null || bytes.isEmpty()) {
                                    if (release(token)) RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
                                } else if (!RustEthereumNativeWalletEngine.importCheckpointFile(token, bytes)) {
                                    // A failed JNI call consumes no durable state, but it must
                                    // still release any process-local import session.
                                    RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
                                }
                                release(token)
                            }
                        }
                        bytes?.fill(0)
                    },
                    {
                        if (release(token)) RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
                    },
                )
            }
        }
        if (!submitted && release(token)) {
            RustEthereumNativeWalletEngine.abandonCheckpointFileImport(token)
        }
    }

    /**
     * Reads at most MAX_FILE_BYTES+1 bytes in 8 KiB chunks.  A full mutable
     * buffer is wiped on every exit; the returned exact-sized copy is owned by
     * the caller and must be wiped after JNI returns.
     */
    internal fun readBounded(input: InputStream): ByteArray? {
        val buffer = ByteArray(READ_CHUNK_BYTES)
        val bounded = ByteArray(MAX_FILE_BYTES + 1)
        var total = 0
        return try {
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                // InputStream.read(byte[]) must make progress when given a
                // non-empty buffer. Reject a broken provider rather than
                // spinning forever on repeated zero-byte reads.
                if (count == 0) return null
                if (total > MAX_FILE_BYTES - count) return null
                System.arraycopy(buffer, 0, bounded, total, count)
                total += count
            }
            bounded.copyOf(total).takeIf { it.isNotEmpty() }
        } finally {
            buffer.fill(0)
            bounded.fill(0)
        }
    }

    private const val IMPORT_TIMEOUT_MILLIS = 5 * 60 * 1_000L
}
