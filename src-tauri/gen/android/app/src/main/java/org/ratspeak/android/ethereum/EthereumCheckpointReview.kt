package org.ratspeak.android.ethereum

import android.app.Activity
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
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/** Public, non-authoritative values rendered by the native checkpoint UI. */
internal data class CheckpointReviewProjection(
    val network: String,
    val source: String,
    val sourceFingerprint: String,
    val checkpointEpoch: Long,
    val checkpointRoot: String,
    val canonicalBootstrapHash: String,
    val observedAtUnix: Long,
    val validUntilUnix: Long,
    val expiresAtUnix: Long,
) {
    companion object {
        private const val MAGIC = "RSETHCP1"
        private val HEX = Regex("^[0-9a-fA-F]{64}$")
        private val SOURCES = setOf("url", "file", "qr")

        fun decode(frame: ByteArray): CheckpointReviewProjection? {
            if (frame.size > MAX_FRAME_BYTES) return null
            val cursor = CheckpointProjectionCursor(frame)
            return try {
                if (cursor.readAscii(8) != MAGIC) return null
                val network = cursor.readField()?.takeIf { it == "sepolia" } ?: return null
                val source = cursor.readField()?.takeIf(SOURCES::contains) ?: return null
                val sourceFingerprint = cursor.readAscii(64).takeIf { nonZeroHex(it) } ?: return null
                val epoch = cursor.readLong().takeIf { it > 0 } ?: return null
                val root = cursor.readAscii(64).takeIf { nonZeroHex(it) } ?: return null
                val bootstrapHash = cursor.readAscii(64).takeIf { nonZeroHex(it) } ?: return null
                val observed = cursor.readLong().takeIf { it > 0 } ?: return null
                val validUntil = cursor.readLong().takeIf { it > 0 } ?: return null
                val expires = cursor.readLong().takeIf { it > 0 } ?: return null
                if (validUntil < observed || expires > validUntil || !cursor.finished()) return null
                CheckpointReviewProjection(
                    network = network,
                    source = source,
                    sourceFingerprint = "0x$sourceFingerprint",
                    checkpointEpoch = epoch,
                    checkpointRoot = "0x$root",
                    canonicalBootstrapHash = "0x$bootstrapHash",
                    observedAtUnix = observed,
                    validUntilUnix = validUntil,
                    expiresAtUnix = expires,
                )
            } catch (_: IllegalArgumentException) {
                null
            }
        }

        private fun nonZeroHex(value: String): Boolean =
            HEX.matches(value) && value.any { it != '0' }
    }
}

private const val MAX_FRAME_BYTES = 512

private class CheckpointProjectionCursor(private val bytes: ByteArray) {
    private var offset = 0

    fun readByte(): Int {
        if (offset >= bytes.size) throw IllegalArgumentException("projection truncated")
        return bytes[offset++].toInt() and 0xff
    }

    fun readAscii(length: Int): String {
        if (length < 0 || offset + length > bytes.size) throw IllegalArgumentException("projection truncated")
        val value = String(bytes, offset, length, StandardCharsets.US_ASCII)
        if (value.any { it.code > 0x7f }) throw IllegalArgumentException("projection non-ascii")
        offset += length
        return value
    }

    fun readField(): String? = readAscii(readByte()).takeIf { it.isNotEmpty() }

    fun readLong(): Long {
        var value = 0L
        repeat(8) { value = (value shl 8) or readByte().toLong() }
        return value
    }

    fun finished(): Boolean = offset == bytes.size
}

/** Process-memory one-shot launcher. The Intent carries only the opaque token. */
internal object EthereumCheckpointReviewLauncher {
    internal data class Request(
        val token: String,
        val projection: CheckpointReviewProjection,
        val onDecision: (String, Boolean) -> Unit,
        private val callbackUsed: AtomicBoolean = AtomicBoolean(false),
    ) {
        fun decide(approved: Boolean) {
            if (callbackUsed.compareAndSet(false, true)) {
                try {
                    onDecision(token, approved)
                } catch (_: Throwable) {
                    // Rust has already consumed the capability before I/O.
                }
            }
        }

        fun abandon() {
            if (callbackUsed.compareAndSet(false, true)) {
                RustEthereumNativeWalletEngine.abandonCheckpointReview(token)
            }
        }
    }

    private val requests = ConcurrentHashMap<String, Request>()
    private val TOKEN = Regex("^[0-9a-fA-F]{64}$")

    @Synchronized
    fun launch(activity: Activity, token: String, projection: CheckpointReviewProjection): Boolean {
        if (!TOKEN.matches(token) || requests.containsKey(token)) return false
        val request = Request(token, projection, RustEthereumNativeWalletEngine::resolveCheckpointReview)
        requests[token] = request
        return try {
            activity.startActivity(EthereumCheckpointReviewActivity.intent(activity, token))
            true
        } catch (_: Throwable) {
            requests.remove(token, request)
            request.abandon()
            false
        }
    }

    @Synchronized
    fun consume(token: String?): Request? {
        if (token == null || !TOKEN.matches(token)) return null
        return requests.remove(token)
    }
}

/** Native-only checkpoint review; no WebView, wallet, biometric, or gateway authority. */
internal class EthereumCheckpointReviewActivity : Activity() {
    private var request: EthereumCheckpointReviewLauncher.Request? = null
    private var content: LinearLayout? = null
    private var finishedDecision = false
    private val deadlineHandler = Handler(Looper.getMainLooper())
    private val deadlineCheck = object : Runnable {
        override fun run() {
            val expiry = request?.projection?.expiresAtUnix ?: return
            if (System.currentTimeMillis() / 1_000 >= expiry) {
                finishedDecision = true
                request?.abandon()
                request = null
                finish()
            } else {
                deadlineHandler.postDelayed(this, DEADLINE_POLL_MILLIS)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        request = EthereumCheckpointReviewLauncher.consume(intent?.getStringExtra(EXTRA_TOKEN))
        val projection = request?.projection
        if (request == null || projection == null) {
            finish()
            return
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        content = root
        setContentView(ScrollView(this).apply { addView(root) })
        title(getString(R.string.ethereum_checkpoint_review_title))
        body(getString(R.string.ethereum_checkpoint_review_warning))
        line(R.string.ethereum_checkpoint_review_network, "Sepolia")
        line(R.string.ethereum_checkpoint_review_source, projection.source)
        line(R.string.ethereum_checkpoint_review_source_fingerprint, projection.sourceFingerprint)
        line(R.string.ethereum_checkpoint_review_epoch, projection.checkpointEpoch.toString())
        line(R.string.ethereum_checkpoint_review_root, projection.checkpointRoot)
        line(R.string.ethereum_checkpoint_review_bootstrap_hash, projection.canonicalBootstrapHash)
        line(R.string.ethereum_checkpoint_review_observed, projection.observedAtUnix.toString())
        line(R.string.ethereum_checkpoint_review_valid_until, projection.validUntilUnix.toString())
        line(R.string.ethereum_checkpoint_review_expiry, projection.expiresAtUnix.toString())
        body(getString(R.string.ethereum_checkpoint_review_non_authority))
        button(getString(R.string.ethereum_checkpoint_review_approve)) { decide(true) }
        button(getString(R.string.ethereum_checkpoint_review_deny)) { decide(false) }
        deadlineHandler.post(deadlineCheck)
    }

    override fun onStop() {
        super.onStop()
        deadlineHandler.removeCallbacks(deadlineCheck)
        if (!finishedDecision) {
            request?.abandon()
            request = null
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(Bundle())
    }

    private fun decide(approved: Boolean) {
        if (finishedDecision) return
        finishedDecision = true
        request?.decide(approved)
        request = null
        finish()
    }

    private fun title(value: String) {
        content?.addView(TextView(this).apply { text = value; textSize = 24f; setPadding(0, 0, 0, dp(16)) })
    }

    private fun body(value: String) {
        content?.addView(TextView(this).apply { text = value; textSize = 16f; setPadding(0, dp(8), 0, dp(8)) })
    }

    private fun line(label: Int, value: String) = body(getString(R.string.ethereum_checkpoint_review_line, getString(label), value))

    private fun button(label: String, action: () -> Unit) {
        content?.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val EXTRA_TOKEN = "org.ratspeak.android.ethereum.CHECKPOINT_REVIEW_TOKEN"
        private const val DEADLINE_POLL_MILLIS = 500L

        internal fun intent(context: Context, token: String): Intent =
            Intent(context, EthereumCheckpointReviewActivity::class.java).putExtra(EXTRA_TOKEN, token)
    }
}
