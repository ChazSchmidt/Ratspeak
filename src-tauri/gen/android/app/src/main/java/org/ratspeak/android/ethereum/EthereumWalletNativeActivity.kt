package org.ratspeak.android.ethereum

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Canvas
import android.graphics.Paint
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.text.InputFilter
import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.ratspeak.android.R
import java.math.BigInteger
import java.util.concurrent.ConcurrentHashMap
import java.util.UUID

/**
 * Native wallet ceremony host. It is non-exported and accepts only a one-shot,
 * process-memory request from trusted native code. No Intent carries wallet or
 * transaction material, and this activity has no WebView.
 */
internal class EthereumWalletNativeActivity : Activity() {
    private var controller: EthereumNativeWalletController? = null
    private var phraseView: SensitivePhraseView? = null
    private lateinit var content: LinearLayout
    private var request: EthereumNativeWalletLauncher.Request? = null
    private var ceremonyToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        setContentView(ScrollView(this).apply { addView(content) })

        val requestToken = intent?.getStringExtra(EXTRA_REQUEST_TOKEN)
        val launchRequest = EthereumNativeWalletLauncher.consume(requestToken)
        ceremonyToken = requestToken.takeIf { launchRequest != null }
        request = launchRequest
        val engine = launchRequest?.engine ?: UnavailableNativeWalletEngine
        val nativeController = EthereumNativeWalletController(
            apiLevel = Build.VERSION.SDK_INT,
            clockMillis = System::currentTimeMillis,
            engine = engine,
            custody = AndroidEthereumNativeCustody(this),
            observer = ::render,
        )
        controller = nativeController
        launchRequest?.activeAddress?.let(nativeController::markExistingWalletActive)
        launchRequest?.review?.let(nativeController::beginTransferReview)
        launchRequest?.clearSignReview?.let(nativeController::beginClearSignedReview)
    }

    override fun onStop() {
        super.onStop()
        // BiometricPrompt does not stop its owning activity. Actual background,
        // replacement, and configuration changes close the one-shot session.
        controller?.close()
        controller = null
        ceremonyToken?.let(EthereumNativeWalletLauncher::release)
        ceremonyToken = null
        try {
            request?.onClosed?.invoke()
        } catch (_: Throwable) {
            // A native callback cannot weaken ceremony cleanup.
        }
        request = null
        phraseView?.close()
        phraseView = null
        finish()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        // Deliberately save no wallet ceremony or input state. Rotation cancels.
        super.onSaveInstanceState(Bundle())
    }

    private fun render(state: EthereumNativeWalletController.State) {
        if (!::content.isInitialized) return
        phraseView?.close()
        phraseView = null
        content.removeAllViews()
        title(getString(R.string.ethereum_native_wallet_title))
        when (state) {
            is EthereumNativeWalletController.State.Unavailable -> {
                body(state.reason)
                button(getString(android.R.string.ok)) { finish() }
            }
            EthereumNativeWalletController.State.Ready -> renderReady()
            is EthereumNativeWalletController.State.BackupDisplay -> renderBackup(state)
            is EthereumNativeWalletController.State.BackupConfirmation -> renderConfirmation(state)
            is EthereumNativeWalletController.State.Authorizing ->
                body(getString(R.string.ethereum_native_authorizing))
            is EthereumNativeWalletController.State.Active -> {
                body(getString(R.string.ethereum_native_active_address, state.address))
                button(getString(R.string.ethereum_native_reveal_backup)) {
                    controller?.beginRevealBackup()
                }
                cancelButton()
            }
            is EthereumNativeWalletController.State.Reviewing -> renderReview(state.review)
            is EthereumNativeWalletController.State.ClearSigningReviewing ->
                renderClearSignReview(state.review)
            is EthereumNativeWalletController.State.Signed -> {
                body(getString(R.string.ethereum_native_signed_hash, state.transactionHash))
                val callback = request?.onSigned
                request = null
                try {
                    callback?.invoke(state.transactionHash)
                } catch (_: Throwable) {
                    // Rust has already persisted the signed transaction.
                }
                button(getString(android.R.string.ok)) { finish() }
            }
            is EthereumNativeWalletController.State.RecoveryRequired -> {
                body(getString(R.string.ethereum_native_recovery_required, state.expectedAddress))
                body(getString(R.string.ethereum_native_recovery_reason, state.reason))
                val restore = secretInput(
                    getString(R.string.ethereum_native_recovery_phrase_hint),
                    multiline = true,
                )
                content.addView(restore)
                button(getString(R.string.ethereum_native_restore_same_wallet)) {
                    val chars = restore.takeAndClearChars()
                    controller?.submitRestorePhrase(chars) ?: chars.fill('\u0000')
                }
                cancelButton()
            }
            is EthereumNativeWalletController.State.Failed -> {
                body(getString(R.string.ethereum_native_failed, state.reason))
                button(getString(android.R.string.ok)) { finish() }
            }
        }
    }

    private fun renderReady() {
        body(getString(R.string.ethereum_native_experimental_notice))
        button(getString(R.string.ethereum_native_create)) { controller?.beginCreate() }
        val restore = secretInput(getString(R.string.ethereum_native_recovery_phrase_hint), multiline = true)
        content.addView(restore)
        button(getString(R.string.ethereum_native_restore)) {
            val chars = restore.takeAndClearChars()
            controller?.submitRestorePhrase(chars) ?: chars.fill('\u0000')
        }
        cancelButton()
    }

    private fun renderBackup(state: EthereumNativeWalletController.State.BackupDisplay) {
        body(getString(R.string.ethereum_native_backup_warning))
        val phrase = controller?.copyPhraseForDisplay()
        if (phrase == null) {
            controller?.cancel()
            return
        }
        val view = SensitivePhraseView(this).apply { takeOwnership(phrase) }
        phraseView = view
        content.addView(
            view,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(220)),
        )
        body(getString(R.string.ethereum_native_active_address, state.address))
        button(getString(R.string.ethereum_native_backup_continue)) {
            view.close()
            controller?.beginBackupConfirmation()
        }
        cancelButton()
    }

    private fun renderConfirmation(state: EthereumNativeWalletController.State.BackupConfirmation) {
        body(getString(R.string.ethereum_native_backup_confirm_intro))
        val fields = state.wordIndexes.associateWith { index ->
            secretInput(getString(R.string.ethereum_native_backup_word_hint, index)).also(content::addView)
        }
        button(getString(R.string.ethereum_native_confirm)) {
            val answers = fields.mapValues { (_, field) -> field.takeAndClearChars() }
            controller?.confirmBackupWords(answers) ?: answers.values.forEach { it.fill('\u0000') }
        }
        cancelButton()
    }

    private fun renderReview(review: ExactSepoliaTransferReview) {
        body(getString(R.string.ethereum_native_review_warning))
        reviewLine(R.string.ethereum_native_network, getString(R.string.ethereum_native_sepolia))
        reviewLine(R.string.ethereum_native_sender, review.sender)
        reviewLine(R.string.ethereum_native_recipient, review.recipient)
        reviewLine(
            R.string.ethereum_native_value,
            getString(R.string.ethereum_native_eth_and_wei, review.valueEth, review.valueWei),
        )
        reviewLine(R.string.ethereum_native_nonce, review.nonce)
        reviewLine(R.string.ethereum_native_gas, review.gasLimit.toString())
        reviewLine(R.string.ethereum_native_max_fee, review.maxFeePerGasWei)
        reviewLine(R.string.ethereum_native_priority_fee, review.maxPriorityFeePerGasWei)
        reviewLine(R.string.ethereum_native_maximum_total_fee, review.maximumFeeWei)
        reviewLine(R.string.ethereum_native_expiry, review.expiresAtEpochMillis.toString())
        body(getString(R.string.ethereum_native_no_data))
        button(getString(R.string.ethereum_native_approve_and_sign)) { controller?.approveTransfer() }
        cancelButton()
    }

    private fun renderClearSignReview(review: ExactClearSignedReview) {
        body(getString(R.string.ethereum_native_review_warning))
        reviewLine(R.string.ethereum_native_network, review.network)
        reviewLine(R.string.ethereum_native_sender, review.sender)
        reviewLine(R.string.ethereum_native_recipient, review.recipient)
        reviewLine(
            R.string.ethereum_native_value,
            "${review.displayAmount} ${review.assetSymbol}",
        )
        reviewLine(R.string.ethereum_native_nonce, review.nonce)
        reviewLine(R.string.ethereum_native_gas, review.gasLimit.toString())
        reviewLine(R.string.ethereum_native_max_fee, review.maxFeePerGasWei)
        reviewLine(R.string.ethereum_native_priority_fee, review.maxPriorityFeePerGasWei)
        val maximumFee = try {
            BigInteger(review.maxFeePerGasWei)
                .multiply(BigInteger.valueOf(review.gasLimit))
                .toString()
        } catch (_: Throwable) {
            ""
        }
        if (maximumFee.isNotEmpty()) {
            reviewLine(R.string.ethereum_native_maximum_total_fee, maximumFee)
        }
        reviewLine(R.string.ethereum_native_expiry, review.expiresAtEpochMillis.toString())
        button(getString(R.string.ethereum_native_approve_and_sign)) {
            controller?.approveClearSignedOperation()
        }
        cancelButton()
    }

    private fun title(value: String) {
        content.addView(TextView(this).apply {
            text = value
            textSize = 24f
            setPadding(0, 0, 0, dp(16))
        })
    }

    private fun body(value: String) {
        content.addView(TextView(this).apply {
            text = value
            textSize = 16f
            setPadding(0, dp(8), 0, dp(8))
        })
    }

    private fun reviewLine(labelResource: Int, value: String) {
        body(getString(R.string.ethereum_native_review_line, getString(labelResource), value))
    }

    private fun button(label: String, action: () -> Unit) {
        content.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        })
    }

    private fun cancelButton() = button(getString(android.R.string.cancel)) {
        controller?.cancel()
        finish()
    }

    private fun secretInput(hintText: String, multiline: Boolean = false): EditText = EditText(this).apply {
        hint = hintText
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
            if (multiline) InputType.TYPE_TEXT_FLAG_MULTI_LINE else 0
        isSaveEnabled = false
        setFreezesText(false)
        filters = arrayOf(InputFilter.LengthFilter(if (multiline) 256 else 32))
        isLongClickable = false
        setTextIsSelectable(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setAutofillHints(null)
            imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            context.getSystemService(AutofillManager::class.java)?.cancel()
        }
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        contentDescription = getString(R.string.ethereum_native_secret_input_hidden)
    }

    private fun EditText.takeAndClearChars(): CharArray {
        val editable = text
        val chars = CharArray(editable?.length ?: 0)
        for (index in chars.indices) chars[index] = editable[index]
        editable?.clear()
        clearComposingText()
        return chars
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val EXTRA_REQUEST_TOKEN = "org.ratspeak.android.ethereum.REQUEST_TOKEN"

        internal fun intent(context: Context, token: String): Intent =
            Intent(context, EthereumWalletNativeActivity::class.java)
                .putExtra(EXTRA_REQUEST_TOKEN, token)
    }
}

/**
 * Trusted native launch boundary. The unguessable token is a one-shot lookup
 * capability, expires quickly, and contains no wallet data in the Intent.
 */
internal object EthereumNativeWalletLauncher {
    internal data class Request(
        val engine: EthereumNativeWalletEngine = RustEthereumNativeWalletEngine,
        val activeAddress: String? = null,
        val review: ExactSepoliaTransferReview? = null,
        val clearSignReview: ExactClearSignedReview? = null,
        val onSigned: ((String) -> Unit)? = null,
        val onClosed: (() -> Unit)? = null,
    )

    private class PendingRequest(val request: Request) {
        private val closeOnce = NativeWalletCloseOnce { request.onClosed?.invoke() }

        fun expire() {
            request.review?.close()
            request.clearSignReview?.close()
            closeOnce.close()
        }
    }

    private val requests = ConcurrentHashMap<String, PendingRequest>()
    private val ceremonyLease = EthereumNativeCeremonyLease(SystemClock::elapsedRealtime)

    @Synchronized
    fun launch(activity: Activity, request: Request): Boolean {
        purgeExpiredLocked()
        if (!request.engine.isAvailable || (request.review != null && request.clearSignReview != null)) {
            request.review?.close()
            request.clearSignReview?.close()
            return false
        }
        val token = UUID.randomUUID().toString()
        val expiresAt = SystemClock.elapsedRealtime() + REQUEST_LIFETIME_MILLIS
        if (!ceremonyLease.acquire(token, expiresAt)) {
            request.review?.close()
            request.clearSignReview?.close()
            return false
        }
        requests[token] = PendingRequest(request)
        return try {
            activity.startActivity(EthereumWalletNativeActivity.intent(activity, token))
            true
        } catch (_: Throwable) {
            requests.remove(token)?.request?.let { failed ->
                failed.review?.close()
                failed.clearSignReview?.close()
            }
            ceremonyLease.release(token)
            false
        }
    }

    @Synchronized
    fun consume(token: String?): Request? {
        if (token == null) return null
        purgeExpiredLocked()
        if (!ceremonyLease.claim(token)) return null
        val pending = requests.remove(token) ?: run {
            ceremonyLease.release(token)
            return null
        }
        return pending.request
    }

    @Synchronized
    fun release(token: String) {
        requests.remove(token)?.expire()
        ceremonyLease.release(token)
    }

    private fun purgeExpiredLocked() {
        ceremonyLease.expirePending()?.let { expired ->
            requests.remove(expired)?.expire()
        }
    }

    private const val REQUEST_LIFETIME_MILLIS = 60_000L
}

internal class NativeWalletCloseOnce(private val callback: () -> Unit) {
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    fun close() {
        if (!closed.compareAndSet(false, true)) return
        try {
            callback()
        } catch (_: Throwable) {
            // Cleanup callbacks cannot weaken launcher lease cleanup.
        }
    }
}

/** Process-wide lease: the single Android vault may serve only one ceremony. */
internal class EthereumNativeCeremonyLease(private val elapsedMillis: () -> Long) {
    private var token: String? = null
    private var expiresAtElapsedMillis = 0L
    private var claimed = false

    @Synchronized
    fun acquire(candidate: String, expiresAt: Long): Boolean {
        if (candidate.isEmpty() || token != null || expiresAt <= elapsedMillis()) return false
        token = candidate
        expiresAtElapsedMillis = expiresAt
        claimed = false
        return true
    }

    @Synchronized
    fun claim(candidate: String): Boolean {
        if (token != candidate || claimed || expiresAtElapsedMillis <= elapsedMillis()) return false
        claimed = true
        return true
    }

    @Synchronized
    fun expirePending(): String? {
        val current = token ?: return null
        if (claimed || expiresAtElapsedMillis > elapsedMillis()) return null
        clear()
        return current
    }

    @Synchronized
    fun release(candidate: String): Boolean {
        if (token != candidate) return false
        clear()
        return true
    }

    private fun clear() {
        token = null
        expiresAtElapsedMillis = 0
        claimed = false
    }
}

private object UnavailableNativeWalletEngine : EthereumNativeWalletEngine {
    override val isAvailable = false

    override fun createWallet() = NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun restoreWallet(recoveryPhrase: CharArray) =
        NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun activateWallet(handle: PendingWalletHandle) =
        NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun discardPendingWallet(handle: PendingWalletHandle) = Unit

    override fun recoverWallet(
        handle: PendingWalletHandle,
        expectedAddress: String,
    ) = NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun revealRecoveryPhrase(secret: SensitiveWalletBytes) =
        NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun signExactTransfer(
        review: ExactSepoliaTransferReview,
        secret: SensitiveWalletBytes,
    ) = NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)

    override fun signClearSignedOperation(
        review: ExactClearSignedReview,
        secret: SensitiveWalletBytes,
    ) = NativeWalletResult.Failure(NativeWalletFailure.UNAVAILABLE)
}

/** Draws recovery words without creating an immutable String containing them. */
private class SensitivePhraseView(context: Context) : View(context), AutoCloseable {
    private var phrase: SensitiveChars? = null
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = android.graphics.Color.BLACK
        textSize = resources.displayMetrics.density * resources.configuration.fontScale * 18f
    }

    init {
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        isSaveEnabled = false
        contentDescription = context.getString(R.string.ethereum_native_recovery_phrase_hidden)
    }

    fun takeOwnership(value: SensitiveChars) {
        close()
        phrase = value
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val value = phrase ?: return
        val chars = value.copyChars()
        try {
            var word = 1
            var start = 0
            val lineHeight = paint.fontSpacing * 1.35f
            for (index in 0..chars.size) {
                if (index == chars.size || chars[index] == ' ') {
                    val column = (word - 1) % 2
                    val row = (word - 1) / 2
                    val x = paddingLeft + column * (width / 2f)
                    val y = paddingTop + (row + 1) * lineHeight
                    canvas.drawText("$word.", x, y, paint)
                    canvas.drawText(chars, start, index - start, x + paint.textSize * 2.2f, y, paint)
                    word++
                    start = index + 1
                }
            }
        } finally {
            chars.fill('\u0000')
        }
    }

    override fun onDetachedFromWindow() {
        close()
        super.onDetachedFromWindow()
    }

    override fun close() {
        phrase?.close()
        phrase = null
        invalidate()
    }
}
