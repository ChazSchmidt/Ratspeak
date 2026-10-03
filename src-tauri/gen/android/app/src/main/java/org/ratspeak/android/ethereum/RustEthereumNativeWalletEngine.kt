package org.ratspeak.android.ethereum

import android.os.Build
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets

/**
 * JNI implementation of the native-only wallet contract.
 *
 * Recovery material crosses only the Kotlin/Rust process boundary and is held
 * in mutable buffers. This object is not a JavaScript interface, Tauri command,
 * Android component, or exported service.
 */
internal object RustEthereumNativeWalletEngine : EthereumNativeWalletEngine {
    override val isAvailable: Boolean
        get() = Build.VERSION.SDK_INT >= EthereumCustodyPolicy.MIN_API_LEVEL && try {
            nativeIsAvailable()
        } catch (_: UnsatisfiedLinkError) {
            false
        }

    override fun createWallet(): NativeWalletResult<PendingNativeWallet> =
        decodePending(callFrame(::nativeCreateWallet))

    override fun restoreWallet(recoveryPhrase: CharArray): NativeWalletResult<PendingNativeWallet> {
        val encoded = recoveryPhrase.toAsciiSecretBytes()
            ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_RECOVERY_PHRASE)
        return try {
            decodePending(callFrame { nativeRestoreWallet(encoded) })
        } finally {
            encoded.fill(0)
        }
    }

    override fun activateWallet(handle: PendingWalletHandle): NativeWalletResult<String> =
        decodePublicValue(callFrame { nativeActivateWallet(handle.nativeValue()) }, ADDRESS)

    override fun discardPendingWallet(handle: PendingWalletHandle) {
        try {
            nativeDiscardPendingWallet(handle.nativeValue())
        } catch (_: UnsatisfiedLinkError) {
            // Rust process state is already unavailable.
        }
    }

    override fun recoverWallet(
        handle: PendingWalletHandle,
        expectedAddress: String,
    ): NativeWalletResult<String> {
        if (!ADDRESS.matches(expectedAddress)) {
            discardPendingWallet(handle)
            return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
        }
        return decodePublicValue(
            callFrame { nativeRecoverWallet(handle.nativeValue(), expectedAddress) },
            ADDRESS,
        )
    }

    override fun revealRecoveryPhrase(
        secret: SensitiveWalletBytes,
    ): NativeWalletResult<SensitiveRecoveryPhrase> = try {
        secret.consume { bytes -> decodeRecoveryPhrase(callFrame { nativeRevealRecoveryPhrase(bytes) }) }
    } catch (_: Throwable) {
        NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
    }

    override fun signExactTransfer(
        review: ExactSepoliaTransferReview,
        secret: SensitiveWalletBytes,
    ): NativeWalletResult<String> {
        if (!review.isStillBound()) {
            secret.close()
            return NativeWalletResult.Failure(NativeWalletFailure.REVIEW_MISMATCH)
        }
        val frame = NativeReviewFrame.encode(review)
            ?: run {
                secret.close()
                return NativeWalletResult.Failure(NativeWalletFailure.REVIEW_MISMATCH)
            }
        return try {
            secret.consume { bytes ->
                decodePublicValue(
                    callFrame { nativeSignExactTransfer(frame, bytes) },
                    TRANSACTION_HASH,
                )
            }
        } catch (_: Throwable) {
            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
        } finally {
            frame.fill(0)
        }
    }

    override fun signClearSignedOperation(
        review: ExactClearSignedReview,
        secret: SensitiveWalletBytes,
    ): NativeWalletResult<String> {
        if (!review.isStillBound()) {
            secret.close()
            return NativeWalletResult.Failure(NativeWalletFailure.REVIEW_MISMATCH)
        }
        val frame = NativeClearSignReviewFrame.encode(review)
            ?: run {
                secret.close()
                return NativeWalletResult.Failure(NativeWalletFailure.REVIEW_MISMATCH)
            }
        return try {
            secret.consume { bytes ->
                decodePublicValue(
                    callFrame { nativeSignClearSignedOperation(frame, bytes) },
                    TRANSACTION_HASH,
                )
            }
        } catch (_: Throwable) {
            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
        } finally {
            frame.fill(0)
        }
    }

    /** Cancels one exact Rust-owned preparation when its native ceremony closes. */
    internal fun cancelExactTransfer(
        identityHash: ByteArray,
        identitySessionGeneration: Long,
        operationId: ByteArray,
    ) {
        try {
            if (identityHash.size == 16 && operationId.size == 16) {
                nativeCancelExactTransfer(identityHash, identitySessionGeneration, operationId)
            }
        } catch (_: UnsatisfiedLinkError) {
            // Process teardown already made the preparation unusable.
        } finally {
            identityHash.fill(0)
            operationId.fill(0)
        }
    }

    /** Releases one identity-bound wallet-management ceremony. */
    internal fun endWalletCeremony(identityHash: ByteArray, identitySessionGeneration: Long) {
        try {
            if (identityHash.size == 16) {
                nativeEndWalletCeremony(identityHash, identitySessionGeneration)
            }
        } catch (_: UnsatisfiedLinkError) {
            // Process teardown already released Rust process state.
        } finally {
            identityHash.fill(0)
        }
    }

    /** Supplies only the opaque token and the user's approve/deny decision. */
    internal fun resolveBulkEvidenceReview(token: String, approved: Boolean) {
        if (!BULK_TOKEN.matches(token)) return
        try {
            nativeResolveBulkEvidenceReview(token, approved)
        } catch (_: UnsatisfiedLinkError) {
            // Process teardown fails closed; durable review state remains
            // pending and can be offered again under a fresh bounded token.
        }
    }

    /** Releases only Rust's process-memory token; the durable review remains pending. */
    internal fun abandonBulkEvidenceReview(token: String) {
        if (!BULK_TOKEN.matches(token)) return
        try {
            nativeAbandonBulkEvidenceReview(token)
        } catch (_: UnsatisfiedLinkError) {
            // Process death already discarded the in-memory session.
        }
    }

    /** Supplies only the opaque checkpoint token and explicit approve/deny. */
    internal fun resolveCheckpointReview(token: String, approved: Boolean) {
        if (!CHECKPOINT_TOKEN.matches(token)) return
        try {
            nativeResolveCheckpointReview(token, approved)
        } catch (_: UnsatisfiedLinkError) {
            // Rust consumes the one-shot session before durable resolution.
        }
    }

    /** Releases only Rust's process-memory checkpoint session. */
    internal fun abandonCheckpointReview(token: String) {
        if (!CHECKPOINT_TOKEN.matches(token)) return
        try {
            nativeAbandonCheckpointReview(token)
        } catch (_: UnsatisfiedLinkError) {
            // Process death already discarded the in-memory session.
        }
    }

    /** Supplies only an opaque import token and bounded card bytes to Rust. */
    internal fun importCheckpointFile(token: String, bytes: ByteArray): Boolean {
        if (!CHECKPOINT_TOKEN.matches(token) || bytes.isEmpty() ||
            bytes.size > EthereumCheckpointFileImportLauncher.MAX_FILE_BYTES
        ) {
            bytes.fill(0)
            return false
        }
        return try {
            nativeImportCheckpointFile(token, bytes)
        } catch (_: UnsatisfiedLinkError) {
            false
        } finally {
            bytes.fill(0)
        }
    }

    /** Releases only Rust's process-memory import session. */
    internal fun abandonCheckpointFileImport(token: String) {
        if (!CHECKPOINT_TOKEN.matches(token)) return
        try {
            nativeAbandonCheckpointFileImport(token)
        } catch (_: UnsatisfiedLinkError) {
            // Process teardown already discarded the in-memory session.
        }
    }

    internal fun importGatewayCard(token: String, bytes: ByteArray): Boolean {
        if (!GATEWAY_TOKEN.matches(token) || bytes.isEmpty() ||
            bytes.size > EthereumGatewayCardFileImportLauncher.MAX_FILE_BYTES
        ) {
            bytes.fill(0)
            return false
        }
        return try {
            nativeImportGatewayCard(token, bytes)
        } catch (_: UnsatisfiedLinkError) {
            false
        } finally {
            bytes.fill(0)
        }
    }

    internal fun abandonGatewayCardImport(token: String) {
        if (!GATEWAY_TOKEN.matches(token)) return
        try { nativeAbandonGatewayCardImport(token) } catch (_: UnsatisfiedLinkError) { }
    }

    internal fun resolveGatewayCardReview(token: String, approved: Boolean) {
        if (!GATEWAY_TOKEN.matches(token)) return
        try { nativeResolveGatewayCardReview(token, approved) } catch (_: UnsatisfiedLinkError) { }
    }

    internal fun abandonGatewayCardReview(token: String) {
        if (!GATEWAY_TOKEN.matches(token)) return
        try { nativeAbandonGatewayCardReview(token) } catch (_: UnsatisfiedLinkError) { }
    }

    private fun decodePending(frame: ByteArray): NativeWalletResult<PendingNativeWallet> {
        val cursor = NativeFrameCursor(frame)
        var phrase: SensitiveRecoveryPhrase? = null
        var secret: SensitiveWalletBytes? = null
        var stagedHandle: PendingWalletHandle? = null
        var accepted = false
        return try {
            cursor.failure()?.let { return NativeWalletResult.Failure(it) }
            val handle = cursor.readLong().takeIf { it > 0 }
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            stagedHandle = PendingWalletHandle(handle)
            val address = cursor.readAscii(42).takeIf(ADDRESS::matches)
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            val phraseBytes = cursor.readSizedBytes()
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            val phraseChars = phraseBytes.toSecretChars()
            phraseBytes.fill(0)
            phrase = phraseChars?.let(SensitiveRecoveryPhrase::takeOwnership)
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            val secretBytes = cursor.readSizedBytes()
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            secret = SensitiveWalletBytes.takeOwnership(secretBytes)
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            if (!cursor.finished()) {
                return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            }
            val result = PendingNativeWallet(
                address,
                phrase,
                secret,
                stagedHandle,
            )
            phrase = null
            secret = null
            accepted = true
            NativeWalletResult.Success(result)
        } finally {
            if (!accepted) stagedHandle?.let(::discardPendingWallet)
            phrase?.close()
            secret?.close()
            frame.fill(0)
        }
    }

    private fun decodeRecoveryPhrase(
        frame: ByteArray,
    ): NativeWalletResult<SensitiveRecoveryPhrase> {
        val cursor = NativeFrameCursor(frame)
        return try {
            cursor.failure()?.let { return NativeWalletResult.Failure(it) }
            val phraseBytes = cursor.readSizedBytes()
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            val phraseChars = phraseBytes.toSecretChars()
            phraseBytes.fill(0)
            if (!cursor.finished() || phraseChars == null) {
                phraseChars?.fill('\u0000')
                return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            }
            val phrase = SensitiveRecoveryPhrase.takeOwnership(phraseChars)
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            NativeWalletResult.Success(phrase)
        } finally {
            frame.fill(0)
        }
    }

    private fun decodePublicValue(
        frame: ByteArray,
        allowed: Regex,
    ): NativeWalletResult<String> {
        val cursor = NativeFrameCursor(frame)
        return try {
            cursor.failure()?.let { return NativeWalletResult.Failure(it) }
            val value = cursor.readAscii(frame.size - 1)
            if (!cursor.finished() || !allowed.matches(value)) {
                NativeWalletResult.Failure(NativeWalletFailure.INVALID_WALLET_MATERIAL)
            } else {
                NativeWalletResult.Success(value)
            }
        } finally {
            frame.fill(0)
        }
    }

    private fun callFrame(call: () -> ByteArray): ByteArray = try {
        call().takeIf { it.isNotEmpty() && it.size <= MAX_RESULT_FRAME_BYTES }
            ?: byteArrayOf(NativeWalletFailure.OPERATION_FAILED.nativeCode)
    } catch (_: Throwable) {
        byteArrayOf(NativeWalletFailure.OPERATION_FAILED.nativeCode)
    }

    @JvmStatic private external fun nativeIsAvailable(): Boolean
    @JvmStatic private external fun nativeCreateWallet(): ByteArray
    @JvmStatic private external fun nativeRestoreWallet(recoveryPhrase: ByteArray): ByteArray
    @JvmStatic private external fun nativeActivateWallet(handle: Long): ByteArray
    @JvmStatic private external fun nativeRecoverWallet(handle: Long, expectedAddress: String): ByteArray
    @JvmStatic private external fun nativeDiscardPendingWallet(handle: Long)
    @JvmStatic private external fun nativeRevealRecoveryPhrase(secret: ByteArray): ByteArray
    @JvmStatic private external fun nativeSignExactTransfer(review: ByteArray, secret: ByteArray): ByteArray
    @JvmStatic private external fun nativeSignClearSignedOperation(
        review: ByteArray,
        secret: ByteArray,
    ): ByteArray
    @JvmStatic private external fun nativeCancelExactTransfer(
        identityHash: ByteArray,
        identitySessionGeneration: Long,
        operationId: ByteArray,
    )
    @JvmStatic private external fun nativeEndWalletCeremony(
        identityHash: ByteArray,
        identitySessionGeneration: Long,
    )
    @JvmStatic private external fun nativeResolveBulkEvidenceReview(
        token: String,
        approved: Boolean,
    )
    @JvmStatic private external fun nativeAbandonBulkEvidenceReview(token: String)
    @JvmStatic private external fun nativeResolveCheckpointReview(
        token: String,
        approved: Boolean,
    )
    @JvmStatic private external fun nativeAbandonCheckpointReview(token: String)

    @JvmStatic private external fun nativeImportCheckpointFile(
        token: String,
        bytes: ByteArray,
    ): Boolean

    @JvmStatic private external fun nativeAbandonCheckpointFileImport(token: String)

    private const val MAX_RESULT_FRAME_BYTES = 1_024
    private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")
    private val TRANSACTION_HASH = Regex("^0x[0-9a-fA-F]{64}$")
    private val BULK_TOKEN = Regex("^[0-9a-fA-F]{64}$")
    private val CHECKPOINT_TOKEN = Regex("^[0-9a-fA-F]{64}$")
    private val GATEWAY_TOKEN = Regex("^[0-9a-fA-F]{64}$")

    @JvmStatic private external fun nativeImportGatewayCard(token: String, bytes: ByteArray): Boolean
    @JvmStatic private external fun nativeAbandonGatewayCardImport(token: String)
    @JvmStatic private external fun nativeResolveGatewayCardReview(token: String, approved: Boolean)
    @JvmStatic private external fun nativeAbandonGatewayCardReview(token: String)
}

private class NativeFrameCursor(private val frame: ByteArray) {
    private var offset = 0

    fun failure(): NativeWalletFailure? {
        if (frame.isEmpty()) return NativeWalletFailure.OPERATION_FAILED
        val code = frame[offset++].toInt() and 0xff
        return if (code == 0) null else nativeFailure(code)
    }

    fun readLong(): Long {
        if (offset + 8 > frame.size) return 0
        var value = 0L
        repeat(8) { value = (value shl 8) or (frame[offset++].toLong() and 0xff) }
        return value
    }

    fun readAscii(length: Int): String {
        if (length < 0 || offset + length > frame.size) return ""
        val value = String(frame, offset, length, StandardCharsets.US_ASCII)
        offset += length
        return value
    }

    fun readSizedBytes(): ByteArray? {
        if (offset + 2 > frame.size) return null
        val length = ((frame[offset++].toInt() and 0xff) shl 8) or
            (frame[offset++].toInt() and 0xff)
        if (length == 0 || offset + length > frame.size) return null
        return frame.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun finished(): Boolean = offset == frame.size
}

private object NativeClearSignReviewFrame {
    fun encode(review: ExactClearSignedReview): ByteArray? = try {
        val operation = review.copyOperationId()
        val definitionHash = review.copyDefinitionHash()
        val operationHash = review.copyOperationHash()
        val payload = review.copySigningPayload()
        try {
            val network = review.network.toByteArray(StandardCharsets.US_ASCII)
            val symbol = review.assetSymbol.toByteArray(StandardCharsets.US_ASCII)
            val amount = review.amount.toByteArray(StandardCharsets.US_ASCII)
            ByteArrayOutputStream(384 + payload.size).apply {
                write(3)
                write(operation)
                writeUnsigned(BigInteger.valueOf(review.chainId), 8)
                write(review.sender.toByteArray(StandardCharsets.US_ASCII))
                writeU16(network.size)
                write(network)
                write(definitionHash)
                write(operationHash)
                writeU16(symbol.size)
                write(symbol)
                write(review.assetDecimals)
                write(review.recipient.toByteArray(StandardCharsets.US_ASCII))
                writeU16(amount.size)
                write(amount)
                writeUnsigned(BigInteger(review.nonce), 8)
                writeUnsigned(BigInteger.valueOf(review.gasLimit), 8)
                writeUnsigned(BigInteger(review.maxFeePerGasWei), 16)
                writeUnsigned(BigInteger(review.maxPriorityFeePerGasWei), 16)
                writeUnsigned(BigInteger.valueOf(review.expiresAtEpochMillis), 8)
                writeU16(payload.size)
                write(payload)
            }.toByteArray()
        } finally {
            operation.fill(0)
            definitionHash.fill(0)
            operationHash.fill(0)
            payload.fill(0)
        }
    } catch (_: Throwable) {
        null
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        require(value in 0..UShort.MAX_VALUE.toInt())
        write((value ushr 8) and 0xff)
        write(value and 0xff)
    }

    private fun ByteArrayOutputStream.writeUnsigned(value: BigInteger, width: Int) {
        require(value.signum() >= 0 && value.bitLength() <= width * 8)
        val encoded = value.toByteArray()
        val start = if (encoded.size > width && encoded[0] == 0.toByte()) 1 else 0
        require(encoded.size - start <= width)
        repeat(width - (encoded.size - start)) { write(0) }
        write(encoded, start, encoded.size - start)
        encoded.fill(0)
    }
}

private object NativeReviewFrame {
    fun encode(review: ExactSepoliaTransferReview): ByteArray? = try {
        val payload = review.copySigningPayload()
        val operation = review.copyOperationId()
        try {
            ByteArrayOutputStream(256 + payload.size).apply {
                write(2)
                write(operation)
                writeUnsigned(BigInteger.valueOf(review.chainId), 8)
                write(review.sender.toByteArray(StandardCharsets.US_ASCII))
                write(review.recipient.toByteArray(StandardCharsets.US_ASCII))
                val value = review.valueWei.toByteArray(StandardCharsets.US_ASCII)
                writeU16(value.size)
                write(value)
                writeUnsigned(BigInteger(review.nonce), 8)
                writeUnsigned(BigInteger.valueOf(review.gasLimit), 8)
                writeUnsigned(BigInteger(review.maxFeePerGasWei), 16)
                writeUnsigned(BigInteger(review.maxPriorityFeePerGasWei), 16)
                writeUnsigned(BigInteger.valueOf(review.expiresAtEpochMillis), 8)
                writeU16(payload.size)
                write(payload)
            }.toByteArray()
        } finally {
            operation.fill(0)
            payload.fill(0)
        }
    } catch (_: Throwable) {
        null
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        require(value in 0..UShort.MAX_VALUE.toInt())
        write((value ushr 8) and 0xff)
        write(value and 0xff)
    }

    private fun ByteArrayOutputStream.writeUnsigned(value: BigInteger, width: Int) {
        require(value.signum() >= 0 && value.bitLength() <= width * 8)
        val encoded = value.toByteArray()
        val start = if (encoded.size > width && encoded[0] == 0.toByte()) 1 else 0
        require(encoded.size - start <= width)
        repeat(width - (encoded.size - start)) { write(0) }
        write(encoded, start, encoded.size - start)
        encoded.fill(0)
    }
}

private val NativeWalletFailure.nativeCode: Byte
    get() = when (this) {
        NativeWalletFailure.UNAVAILABLE -> 1
        NativeWalletFailure.INVALID_RECOVERY_PHRASE -> 2
        NativeWalletFailure.INVALID_WALLET_MATERIAL -> 3
        NativeWalletFailure.REVIEW_MISMATCH -> 4
        NativeWalletFailure.SIGNING_FAILED -> 5
        NativeWalletFailure.OPERATION_FAILED -> 6
    }

private fun nativeFailure(code: Int): NativeWalletFailure = when (code) {
    1 -> NativeWalletFailure.UNAVAILABLE
    2 -> NativeWalletFailure.INVALID_RECOVERY_PHRASE
    3 -> NativeWalletFailure.INVALID_WALLET_MATERIAL
    4 -> NativeWalletFailure.REVIEW_MISMATCH
    5 -> NativeWalletFailure.SIGNING_FAILED
    else -> NativeWalletFailure.OPERATION_FAILED
}

private fun CharArray.toAsciiSecretBytes(): ByteArray? {
    if (isEmpty() || size > EthereumCustodyPolicy.MAX_SECRET_BYTES) return null
    val bytes = ByteArray(size)
    for (index in indices) {
        val char = this[index]
        if (char.code !in 1..0x7f) {
            bytes.fill(0)
            return null
        }
        bytes[index] = char.code.toByte()
    }
    return bytes
}

private fun ByteArray.toSecretChars(): CharArray? {
    if (isEmpty() || size > EthereumCustodyPolicy.MAX_SECRET_BYTES) return null
    val chars = CharArray(size)
    for (index in indices) {
        val value = this[index].toInt() and 0xff
        if (value != 0x20 && value !in 0x61..0x7a) {
            chars.fill('\u0000')
            return null
        }
        chars[index] = value.toChar()
    }
    return chars
}
