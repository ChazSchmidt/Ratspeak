package org.ratspeak.android.ethereum

import android.app.Activity
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.ratspeak.android.R
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/** Native-only bounded import of an RSEG1 gateway card. */
internal object EthereumGatewayCardFileImportLauncher {
    internal const val MAX_FILE_BYTES = 256
    private const val READ_CHUNK_BYTES = 64
    private const val IMPORT_TIMEOUT_MILLIS = 5 * 60 * 1_000L
    private val TOKEN = Regex("^[0-9a-fA-F]{64}$")
    private var activeToken: String? = null
    private var resultClaimed = false
    private val timeoutHandler by lazy { Handler(Looper.getMainLooper()) }
    private var timeoutRunnable: Runnable? = null
    internal fun isValidToken(token: String): Boolean = TOKEN.matches(token)

    @Synchronized
    internal fun reserve(token: String): Boolean {
        if (!TOKEN.matches(token) || activeToken != null ||
            !EthereumDocumentReadCoordinator.reserve(
                EthereumDocumentReadCoordinator.Kind.GATEWAY,
                token,
            )
        ) return false
        activeToken = token
        resultClaimed = false
        return true
    }

    @Synchronized
    internal fun release(token: String): Boolean {
        if (activeToken != token) return false
        activeToken = null
        resultClaimed = false
        timeoutRunnable?.let(timeoutHandler::removeCallbacks)
        timeoutRunnable = null
        EthereumDocumentReadCoordinator.release(
            EthereumDocumentReadCoordinator.Kind.GATEWAY,
            token,
        )
        return true
    }

    private fun abandon(token: String) {
        if (release(token)) RustEthereumNativeWalletEngine.abandonGatewayCardImport(token)
    }

    private fun cancelReader(token: String) {
        EthereumDocumentReadExecutor.cancel(token)
    }

    private fun timeout(token: String) {
        val shouldAbandon = synchronized(this) {
            if (activeToken != token) return
            activeToken = null
            resultClaimed = false
            timeoutRunnable?.let(timeoutHandler::removeCallbacks)
            timeoutRunnable = null
            EthereumDocumentReadCoordinator.release(
                EthereumDocumentReadCoordinator.Kind.GATEWAY,
                token,
            )
            true
        }
        if (shouldAbandon) {
            cancelReader(token)
            RustEthereumNativeWalletEngine.abandonGatewayCardImport(token)
        }
    }

    @Synchronized
    private fun claim(token: String): Boolean {
        if (activeToken != token || resultClaimed) return false
        resultClaimed = true
        return true
    }

    internal fun launch(token: String, startPicker: (Intent) -> Unit): Boolean {
        if (!reserve(token)) return false
        return try {
            val timeout = Runnable {
                timeout(token)
            }
            synchronized(this) {
                timeoutRunnable = timeout
                timeoutHandler.postDelayed(timeout, IMPORT_TIMEOUT_MILLIS)
            }
            startPicker(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            })
            true
        } catch (_: Throwable) {
            abandon(token)
            false
        }
    }

    /** Deterministic watchdog hook used by JVM tests. */
    internal fun timeoutForTest(token: String) = timeout(token)

    internal fun onResult(resolver: ContentResolver, resultCode: Int, data: Intent?) {
        val token = synchronized(this) { activeToken } ?: return
        if (!claim(token)) return
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            abandon(token)
            return
        }

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
                        val card = bytes
                        synchronized(this) {
                            // Serialize the timeout decision with the JNI handoff:
                            // once the watchdog wins, bytes cannot be imported.
                            if (activeToken == token) {
                                if (card == null || card.isEmpty() ||
                                    !RustEthereumNativeWalletEngine.importGatewayCard(token, card)) {
                                    abandon(token)
                                }
                                release(token)
                            }
                        }
                        card?.fill(0)
                    },
                    { abandon(token) },
                )
            }
        }
        if (!submitted) {
            abandon(token)
        }
    }

    internal fun readBounded(input: InputStream): ByteArray? {
        val chunk = ByteArray(READ_CHUNK_BYTES)
        val bounded = ByteArray(MAX_FILE_BYTES + 1)
        var total = 0
        return try {
            while (true) {
                val count = input.read(chunk)
                if (count < 0) break
                if (count == 0 || count > MAX_FILE_BYTES - total) return null
                System.arraycopy(chunk, 0, bounded, total, count)
                total += count
            }
            bounded.copyOf(total).takeIf { it.isNotEmpty() }
        } finally {
            chunk.fill(0)
            bounded.fill(0)
        }
    }
}

/** Public display projection. It contains no gateway authority or key material. */
internal data class GatewayCardReviewProjection(
    val destinationHash: String,
    val publicKeyFingerprint: String,
    val expiresAtUnix: Long,
) {
    companion object {
        private const val MAGIC = "RSETHGR1"
        private val HEX = Regex("^[0-9a-fA-F]{64}$")
        private val DESTINATION = Regex("^[0-9a-fA-F]{32}$")

        fun decode(frame: ByteArray): GatewayCardReviewProjection? {
            if (frame.size != 112) return null
            return try {
                val cursor = GatewayProjectionCursor(frame)
                if (cursor.ascii(8) != MAGIC) return null
                val destination = cursor.ascii(32)
                val fingerprint = cursor.ascii(64)
                val expiry = cursor.long()
                if (!DESTINATION.matches(destination) || destination.all { it == '0' } ||
                    !HEX.matches(fingerprint) || fingerprint.all { it == '0' } ||
                    expiry <= 0 || !cursor.finished()
                ) return null
                GatewayCardReviewProjection("0x$destination", "0x$fingerprint", expiry)
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}

private class GatewayProjectionCursor(private val bytes: ByteArray) {
    private var offset = 0

    fun ascii(length: Int): String {
        if (offset + length > bytes.size) throw IllegalArgumentException("truncated")
        val value = String(bytes, offset, length, StandardCharsets.US_ASCII)
        if (value.any { it.code > 0x7f }) throw IllegalArgumentException("non-ascii")
        offset += length
        return value
    }

    fun long(): Long {
        var value = 0L
        repeat(8) { value = (value shl 8) or (bytes[offset++].toInt() and 0xff).toLong() }
        return value
    }

    fun finished(): Boolean = offset == bytes.size
}

/** Process-local, one-shot review request. The Activity Intent carries only token. */
internal object EthereumGatewayCardReviewLauncher {
    internal data class Request(
        val token: String,
        val projection: GatewayCardReviewProjection,
        private val used: AtomicBoolean = AtomicBoolean(false),
    ) {
        fun decide(approved: Boolean) {
            if (used.compareAndSet(false, true)) RustEthereumNativeWalletEngine.resolveGatewayCardReview(token, approved)
        }

        fun abandon() {
            if (used.compareAndSet(false, true)) RustEthereumNativeWalletEngine.abandonGatewayCardReview(token)
        }
    }

    private val requests = ConcurrentHashMap<String, Request>()
    private val TOKEN = Regex("^[0-9a-fA-F]{64}$")

    @Synchronized
    fun launch(activity: Activity, token: String, projection: GatewayCardReviewProjection): Boolean {
        if (!TOKEN.matches(token) || requests.containsKey(token)) return false
        val request = Request(token, projection)
        requests[token] = request
        return try {
            activity.startActivity(EthereumGatewayCardReviewActivity.intent(activity, token))
            true
        } catch (_: Throwable) {
            requests.remove(token, request)
            request.abandon()
            false
        }
    }

    @Synchronized
    fun consume(token: String?): Request? = token?.takeIf(TOKEN::matches)?.let(requests::remove)
}

internal class EthereumGatewayCardReviewActivity : Activity() {
    private var request: EthereumGatewayCardReviewLauncher.Request? = null
    private var decided = false
    private val handler = Handler(Looper.getMainLooper())
    private val expiryCheck = object : Runnable {
        override fun run() {
            val expiry = request?.projection?.expiresAtUnix ?: return
            if (System.currentTimeMillis() / 1_000 >= expiry) {
                decided = true
                request?.abandon()
                request = null
                finish()
            } else handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        request = EthereumGatewayCardReviewLauncher.consume(intent?.getStringExtra(EXTRA_TOKEN))
        val current = request ?: run { finish(); return }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        fun text(value: String) = root.addView(TextView(this).apply {
            this.text = value
            textSize = 16f
            setPadding(0, dp(8), 0, dp(8))
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.ethereum_gateway_review_title)
            textSize = 24f
        })
        text("Only approve a gateway card from your out-of-band source. This configures message routing; it does not authorize RPC, checkpoints, wallet custody, or signing.")
        text("Destination: ${current.projection.destinationHash}")
        text("Public-key fingerprint: ${current.projection.publicKeyFingerprint}")
        text("Review expires at Unix second: ${current.projection.expiresAtUnix}")
        button(root, "Approve gateway") { decide(true) }
        button(root, "Deny gateway") { decide(false) }
        setContentView(ScrollView(this).apply { addView(root) })
        handler.post(expiryCheck)
    }

    override fun onStop() {
        super.onStop()
        handler.removeCallbacks(expiryCheck)
        if (!decided) {
            request?.abandon()
            request = null
        }
    }

    private fun decide(approved: Boolean) {
        if (decided) return
        decided = true
        request?.decide(approved)
        request = null
        finish()
    }

    private fun button(root: LinearLayout, label: String, action: () -> Unit) {
        root.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val EXTRA_TOKEN = "org.ratspeak.android.ethereum.GATEWAY_REVIEW_TOKEN"
        internal fun intent(context: Context, token: String): Intent =
            Intent(context, EthereumGatewayCardReviewActivity::class.java).putExtra(EXTRA_TOKEN, token)
    }
}
