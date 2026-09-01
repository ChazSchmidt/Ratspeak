package org.ratspeak.android.ethereum

import android.content.Intent
import android.os.Looper
import org.ratspeak.android.MainActivity
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-native caller for the non-exported wallet Activity.
 *
 * Rust supplies only immutable public review data retained behind its opaque
 * prepared-transfer state. Nothing in this object is installed in a WebView.
 */
internal object EthereumNativeWalletBridge {
    private val lock = Any()
    private var activity = WeakReference<MainActivity>(null)
    private var resumed = false

    @JvmStatic
    fun isAvailable(): Boolean = RustEthereumNativeWalletEngine.isAvailable

    fun attach(candidate: MainActivity) {
        synchronized(lock) { activity = WeakReference(candidate) }
    }

    fun resumed(candidate: MainActivity) {
        synchronized(lock) {
            if (activity.get() === candidate) resumed = true
        }
    }

    fun paused(candidate: MainActivity) {
        synchronized(lock) {
            if (activity.get() === candidate) resumed = false
        }
    }

    fun detach(candidate: MainActivity) {
        synchronized(lock) {
            if (activity.get() === candidate) {
                resumed = false
                activity.clear()
            }
        }
    }

    @JvmStatic
    fun launchWallet(identityHash: ByteArray, identitySessionGeneration: Long, activeAddress: String?): Boolean {
        if (identityHash.size != IDENTITY_BYTES || identityHash.all { it == 0.toByte() } ||
            identitySessionGeneration < 0L ||
            activeAddress != null && !ADDRESS.matches(activeAddress)
        ) {
            identityHash.fill(0)
            return false
        }
        val identity = identityHash.copyOf()
        identityHash.fill(0)
        val launched = onResumedActivity { owner ->
            EthereumNativeWalletLauncher.launch(
                owner,
                EthereumNativeWalletLauncher.Request(
                    activeAddress = activeAddress,
                    onClosed = {
                        RustEthereumNativeWalletEngine.endWalletCeremony(
                            identity,
                            identitySessionGeneration,
                        )
                    },
                ),
            )
        }
        if (!launched) {
            RustEthereumNativeWalletEngine.endWalletCeremony(identity, identitySessionGeneration)
        }
        return launched
    }

    @JvmStatic
    fun launchExactTransfer(
        identityHash: ByteArray,
        identitySessionGeneration: Long,
        operationId: ByteArray,
        sender: String,
        recipient: String,
        valueWei: String,
        nonce: String,
        maxFeePerGasWei: String,
        maxPriorityFeePerGasWei: String,
        expiresAtEpochMillis: Long,
        canonicalSigningPayload: ByteArray,
    ): Boolean {
        if (identityHash.size != IDENTITY_BYTES || identityHash.all { it == 0.toByte() } ||
            identitySessionGeneration < 0L ||
            operationId.size != OPERATION_BYTES || operationId.all { it == 0.toByte() }
        ) {
            identityHash.fill(0)
            operationId.fill(0)
            canonicalSigningPayload.fill(0)
            return false
        }
        val identity = identityHash.copyOf()
        val operation = operationId.copyOf()
        identityHash.fill(0)
        operationId.fill(0)
        val review = ExactSepoliaTransferReview.checked(
            ExactSepoliaTransferReview.SEPOLIA_CHAIN_ID,
            sender,
            recipient,
            valueWei,
            nonce,
            ExactSepoliaTransferReview.NATIVE_TRANSFER_GAS,
            maxFeePerGasWei,
            maxPriorityFeePerGasWei,
            expiresAtEpochMillis,
            operation,
            canonicalSigningPayload,
        )
        canonicalSigningPayload.fill(0)
        if (review == null) {
            identity.fill(0)
            operation.fill(0)
            return false
        }
        val launched = onResumedActivity { owner ->
            EthereumNativeWalletLauncher.launch(
                owner,
                EthereumNativeWalletLauncher.Request(
                    activeAddress = sender,
                    review = review,
                    onSigned = {
                        identity.fill(0)
                        operation.fill(0)
                    },
                    onClosed = {
                        RustEthereumNativeWalletEngine.cancelExactTransfer(
                            identity,
                            identitySessionGeneration,
                            operation,
                        )
                        identity.fill(0)
                        operation.fill(0)
                    },
                ),
            )
        }
        if (!launched) {
            review.close()
            identity.fill(0)
            operation.fill(0)
        }
        return launched
    }

    /**
     * Starts the native-only bulk evidence review. Rust supplies a public
     * display projection plus an opaque process-local token; the Activity
     * Intent contains only that token. The callback returns only token and
     * approve/deny, never display fields or evidence bytes. A launch failure
     * leaves the durable review pending; Rust only drops its process session.
     */
    @JvmStatic
    fun launchBulkEvidenceReview(token: String, projectionFrame: ByteArray): Boolean {
        val projection = BulkEvidenceReviewProjection.decode(projectionFrame)
        projectionFrame.fill(0)
        if (projection == null || !BULK_TOKEN.matches(token)) return false
        val launched = onResumedActivity { owner ->
            EthereumBulkEvidenceReviewLauncher.launch(owner, token, projection)
        }
        return launched
    }

    /** Starts native checkpoint trust review; no gateway or wallet data crosses this seam. */
    @JvmStatic
    fun launchCheckpointReview(token: String, projectionFrame: ByteArray): Boolean {
        val projection = CheckpointReviewProjection.decode(projectionFrame)
        projectionFrame.fill(0)
        if (projection == null || !CHECKPOINT_TOKEN.matches(token)) return false
        return onResumedActivity { owner ->
            EthereumCheckpointReviewLauncher.launch(owner, token, projection)
        }
    }

    /** Starts the pre-registered native document picker using only the token. */
    @JvmStatic
    fun launchCheckpointFileImport(token: String): Boolean {
        if (!EthereumCheckpointFileImportLauncher.isValidToken(token)) return false
        return onResumedActivity { owner -> owner.launchEthereumCheckpointFileImport(token) }
    }

    /** Starts the native-only RSEG1 gateway card picker; URI and bytes stay native. */
    @JvmStatic
    fun launchGatewayCardImport(token: String): Boolean {
        if (!EthereumGatewayCardFileImportLauncher.isValidToken(token)) return false
        return onResumedActivity { owner -> owner.launchEthereumGatewayCardImport(token) }
    }

    /** Starts the native-only gateway review from an immutable public projection. */
    @JvmStatic
    fun launchGatewayCardReview(token: String, projectionFrame: ByteArray): Boolean {
        val projection = GatewayCardReviewProjection.decode(projectionFrame)
        projectionFrame.fill(0)
        if (projection == null || !EthereumGatewayCardFileImportLauncher.isValidToken(token)) return false
        return onResumedActivity { owner -> EthereumGatewayCardReviewLauncher.launch(owner, token, projection) }
    }

    /** Delivers only the system picker result to the bounded native reader. */
    internal fun handleCheckpointFileResult(
        owner: MainActivity,
        resultCode: Int,
        data: Intent?,
    ) {
        EthereumCheckpointFileImportLauncher.onResult(owner.contentResolver, resultCode, data)
    }

    internal fun handleGatewayCardResult(
        owner: MainActivity,
        resultCode: Int,
        data: Intent?,
    ) {
        EthereumGatewayCardFileImportLauncher.onResult(owner.contentResolver, resultCode, data)
    }

    private fun onResumedActivity(operation: (MainActivity) -> Boolean): Boolean {
        val owner = synchronized(lock) {
            activity.get()?.takeIf { resumed && !it.isFinishing && !it.isDestroyed }
        } ?: return false
        if (Looper.myLooper() == Looper.getMainLooper()) return operation(owner)
        val latch = CountDownLatch(1)
        val admitted = AtomicBoolean(true)
        var result = false
        owner.runOnUiThread {
            result = synchronized(lock) {
                if (admitted.get() && resumed && activity.get() === owner &&
                    !owner.isFinishing && !owner.isDestroyed
                ) {
                    operation(owner)
                } else {
                    false
                }
            }
            latch.countDown()
        }
        return try {
            val completed = latch.await(MAIN_THREAD_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            if (!completed) admitted.set(false)
            completed && result
        } catch (_: InterruptedException) {
            admitted.set(false)
            Thread.currentThread().interrupt()
            false
        }
    }

    private const val IDENTITY_BYTES = 16
    private const val OPERATION_BYTES = 16
    private const val MAIN_THREAD_TIMEOUT_MILLIS = 2_000L
    private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")
    private val BULK_TOKEN = Regex("^[0-9a-fA-F]{64}$")
    private val CHECKPOINT_TOKEN = Regex("^[0-9a-fA-F]{64}$")
}
