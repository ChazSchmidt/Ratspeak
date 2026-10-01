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

/** Public, non-authoritative values rendered by the native bulk review UI. */
internal data class BulkEvidenceReviewProjection(
    val gateway: String,
    val kind: String,
    val subject: String,
    val checkpointEpoch: Long?,
    val checkpointRoot: String?,
    val manifestDigest: String,
    val encodedSize: Long,
    val expiresAtEpochMillis: Long,
) {
    companion object {
        private const val MAGIC = "RSETHBR1"
        private val HEX = Regex("^[0-9a-fA-F]+$")
        private val KINDS = setOf(
            "execution_header",
            "account_proof",
            "receipt_proof",
            "consensus",
            "account_state_package",
            "finalized_receipt_package",
        )

        fun decode(frame: ByteArray): BulkEvidenceReviewProjection? {
            val cursor = ProjectionCursor(frame)
            return try {
                if (cursor.readAscii(8) != MAGIC) return null
                val gateway = cursor.readField()?.takeIf { it.length == 32 && HEX.matches(it) }
                    ?: return null
                val kind = cursor.readField()?.takeIf(KINDS::contains) ?: return null
                val subject = cursor.readField()?.takeIf { it.length == 64 && HEX.matches(it) }
                    ?: return null
                val checkpoint = when (cursor.readByte()) {
                    0 -> null
                    1 -> {
                        val epoch = cursor.readLong().takeIf { it > 0 } ?: return null
                        val root = cursor.readAscii(64).takeIf { HEX.matches(it) } ?: return null
                        epoch to root
                    }
                    else -> return null
                }
                val digest = cursor.readField()?.takeIf { it.length == 64 && HEX.matches(it) }
                    ?: return null
                val encodedSize = cursor.readUnsignedInt().takeIf { it > 0 } ?: return null
                val expiry = cursor.readLong().takeIf { it > 0 } ?: return null
                if (!cursor.finished()) return null
                BulkEvidenceReviewProjection(
                    gateway = "0x$gateway",
                    kind = kind,
                    subject = "0x$subject",
                    checkpointEpoch = checkpoint?.first,
                    checkpointRoot = checkpoint?.second?.let { "0x$it" },
                    manifestDigest = "0x$digest",
                    encodedSize = encodedSize,
                    expiresAtEpochMillis = expiry,
                )
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}

private class ProjectionCursor(private val bytes: ByteArray) {
    private var offset = 0

    fun readByte(): Int {
        if (offset >= bytes.size) throw IllegalArgumentException("projection truncated")
        return bytes[offset++].toInt() and 0xff
    }

    fun readAscii(length: Int): String {
        if (length < 0 || offset + length > bytes.size) {
            throw IllegalArgumentException("projection truncated")
        }
        val value = String(bytes, offset, length, StandardCharsets.US_ASCII)
        if (value.any { it.code > 0x7f }) throw IllegalArgumentException("projection non-ascii")
        offset += length
        return value
    }

    fun readField(): String? {
        val length = readByte()
        return readAscii(length).takeIf { it.isNotEmpty() }
    }

    fun readLong(): Long {
        var value = 0L
        repeat(8) { value = (value shl 8) or readByte().toLong() }
        return value
    }

    fun readUnsignedInt(): Long {
        var value = 0L
        repeat(4) { value = (value shl 8) or readByte().toLong() }
        return value
    }

    fun finished(): Boolean = offset == bytes.size
}

/** Process-memory, one-shot launcher for the dedicated native review screen. */
internal object EthereumBulkEvidenceReviewLauncher {
    internal data class Request(
        val token: String,
        val projection: BulkEvidenceReviewProjection,
        val onDecision: (String, Boolean) -> Unit,
        private val callbackUsed: AtomicBoolean = AtomicBoolean(false),
    ) {
        fun decide(approved: Boolean) {
            if (callbackUsed.compareAndSet(false, true)) {
                try {
                    onDecision(token, approved)
                } catch (_: Throwable) {
                    // Rust consumes the token before durable I/O; callback
                    // failures cannot turn this into a reusable approval.
                }
            }
        }

        /** Releases only the process-memory session; it does not deny the
         * durable review. Used when the screen is backgrounded or rotated. */
        fun abandon() {
            if (callbackUsed.compareAndSet(false, true)) {
                RustEthereumNativeWalletEngine.abandonBulkEvidenceReview(token)
            }
        }
    }

    private val requests = ConcurrentHashMap<String, Request>()
    private val TOKEN = Regex("^[0-9a-fA-F]{64}$")

    @Synchronized
    fun launch(
        activity: Activity,
        token: String,
        projection: BulkEvidenceReviewProjection,
    ): Boolean {
        if (!TOKEN.matches(token) || requests.containsKey(token)) return false
        val request = Request(token, projection, RustEthereumNativeWalletEngine::resolveBulkEvidenceReview)
        requests[token] = request
        return try {
            activity.startActivity(EthereumBulkEvidenceReviewActivity.intent(activity, token))
            true
        } catch (_: Throwable) {
            requests.remove(token, request)
            false
        }
    }

    @Synchronized
    fun consume(token: String?): Request? {
        if (token == null || !TOKEN.matches(token)) return null
        return requests.remove(token)
    }
}

/**
 * Native-only evidence review. This Activity has no WebView, wallet custody,
 * biometric prompt, or exported entry point. Rotation and backgrounding
 * abandon the process session without denying the durable review.
 */
internal class EthereumBulkEvidenceReviewActivity : Activity() {
    private var request: EthereumBulkEvidenceReviewLauncher.Request? = null
    private var content: LinearLayout? = null
    private var finishedDecision = false
    private val deadlineHandler = Handler(Looper.getMainLooper())
    private val deadlineCheck = object : Runnable {
        override fun run() {
            val expiry = request?.projection?.expiresAtEpochMillis ?: return
            if (System.currentTimeMillis() >= expiry) {
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
        val token = intent?.getStringExtra(EXTRA_TOKEN)
        request = EthereumBulkEvidenceReviewLauncher.consume(token)
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
        title(getString(R.string.ethereum_bulk_review_title))
        body(getString(R.string.ethereum_bulk_review_warning))
        line(R.string.ethereum_bulk_review_gateway, projection.gateway)
        line(R.string.ethereum_bulk_review_kind, projection.kind)
        line(R.string.ethereum_bulk_review_subject, projection.subject)
        line(
            R.string.ethereum_bulk_review_checkpoint,
            projection.checkpointEpoch?.let { epoch ->
                getString(
                    R.string.ethereum_bulk_review_checkpoint_value,
                    epoch,
                    projection.checkpointRoot ?: "",
                )
            } ?: getString(R.string.ethereum_bulk_review_not_present),
        )
        line(R.string.ethereum_bulk_review_digest, projection.manifestDigest)
        line(R.string.ethereum_bulk_review_encoded_size, projection.encodedSize.toString())
        line(R.string.ethereum_bulk_review_expiry, projection.expiresAtEpochMillis.toString())
        body(getString(R.string.ethereum_bulk_review_non_authority))
        button(getString(R.string.ethereum_bulk_review_approve)) { decide(true) }
        button(getString(R.string.ethereum_bulk_review_deny)) { decide(false) }
        deadlineHandler.post(deadlineCheck)
    }

    override fun onStop() {
        super.onStop()
        deadlineHandler.removeCallbacks(deadlineCheck)
        // This covers rotation, task backgrounding, and process-driven stop.
        // Abandoning releases only Rust's process-memory session; the
        // durable row remains pending for a bounded retry.
        if (!finishedDecision) {
            request?.abandon()
            request = null
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        // Do not restore a token or a decision after rotation.
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
        content?.addView(TextView(this).apply {
            text = value
            textSize = 24f
            setPadding(0, 0, 0, dp(16))
        })
    }

    private fun body(value: String) {
        content?.addView(TextView(this).apply {
            text = value
            textSize = 16f
            setPadding(0, dp(8), 0, dp(8))
        })
    }

    private fun line(label: Int, value: String) = body(getString(R.string.ethereum_bulk_review_line, getString(label), value))

    private fun button(label: String, action: () -> Unit) {
        content?.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val EXTRA_TOKEN = "org.ratspeak.android.ethereum.BULK_REVIEW_TOKEN"
        private const val DEADLINE_POLL_MILLIS = 500L

        internal fun intent(context: Context, token: String): Intent =
            Intent(context, EthereumBulkEvidenceReviewActivity::class.java)
                .putExtra(EXTRA_TOKEN, token)
    }
}
