package org.ratspeak.android.ethereum

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/** Native-only boundary to the Rust wallet. It is never installed in a WebView. */
internal interface EthereumNativeWalletEngine {
    val isAvailable: Boolean

    fun createWallet(): NativeWalletResult<PendingNativeWallet>

    /** The implementation must validate BIP-39 and consume no value after returning. */
    fun restoreWallet(recoveryPhrase: CharArray): NativeWalletResult<PendingNativeWallet>

    /** Makes public wallet metadata active only after Android custody succeeds. */
    fun activateWallet(handle: PendingWalletHandle): NativeWalletResult<String>

    /** Invalidates an unused process-local creation/restoration capability. */
    fun discardPendingWallet(handle: PendingWalletHandle)

    /**
     * Replaces invalidated custody only when the restored wallet derives the
     * already-persisted address. Rust must atomically rebind its custody marker.
     */
    fun recoverWallet(
        handle: PendingWalletHandle,
        expectedAddress: String,
    ): NativeWalletResult<String>

    /** Returns words only to the native backup screen. */
    fun revealRecoveryPhrase(secret: SensitiveWalletBytes): NativeWalletResult<SensitiveRecoveryPhrase>

    /**
     * Signs only the canonical payload bound to [review]. The Rust adapter must
     * independently decode it, reject field/payload disagreement, verify the
     * recovered sender, and durably persist the signed transaction before it
     * returns the transaction hash.
     */
    fun signExactTransfer(
        review: ExactSepoliaTransferReview,
        secret: SensitiveWalletBytes,
    ): NativeWalletResult<String>

    /** Signs only one Rust-retained clear-signed EVM operation after native review. */
    fun signClearSignedOperation(
        review: ExactClearSignedReview,
        secret: SensitiveWalletBytes,
    ): NativeWalletResult<String>
}

internal sealed class NativeWalletResult<out T> {
    data class Success<T>(val value: T) : NativeWalletResult<T>()
    data class Failure(val reason: NativeWalletFailure) : NativeWalletResult<Nothing>()
}

internal enum class NativeWalletFailure {
    UNAVAILABLE,
    INVALID_RECOVERY_PHRASE,
    INVALID_WALLET_MATERIAL,
    REVIEW_MISMATCH,
    SIGNING_FAILED,
    OPERATION_FAILED,
}

/** Opaque, process-local activation capability returned by Rust. */
internal class PendingWalletHandle internal constructor(private val value: Long) {
    init {
        require(value > 0)
    }

    internal fun nativeValue(): Long = value
}

/** Secret-bearing wallet creation/restoration result; all owned buffers are wipeable. */
internal class PendingNativeWallet(
    val publicAddress: String,
    val recoveryPhrase: SensitiveRecoveryPhrase,
    private var secret: SensitiveWalletBytes?,
    val activationHandle: PendingWalletHandle,
) : AutoCloseable {
    fun takeSecret(): SensitiveWalletBytes? = secret.also { secret = null }

    override fun close() {
        recoveryPhrase.close()
        secret?.close()
        secret = null
    }
}

/** Recovery words stay in a mutable native buffer and are never stringified here. */
internal class SensitiveRecoveryPhrase private constructor(private var chars: CharArray?) : AutoCloseable {
    val wordCount: Int
        get() = chars?.let(::countWords) ?: 0

    fun copyForNativeDisplay(): SensitiveChars? =
        chars?.copyOf()?.let(SensitiveChars::takeOwnership)

    fun matchesWord(oneBasedIndex: Int, candidate: CharArray): Boolean {
        val phrase = chars ?: return false
        if (oneBasedIndex !in 1..countWords(phrase)) return false
        var currentWord = 1
        var start = 0
        var end = phrase.size
        for (index in phrase.indices) {
            if (phrase[index] == ' ') {
                if (currentWord == oneBasedIndex) {
                    end = index
                    break
                }
                currentWord++
                start = index + 1
            }
        }
        val length = end - start
        var difference = length xor candidate.size
        for (index in 0 until maxOf(length, candidate.size)) {
            val expected = if (index < length) phrase[start + index].code else 0
            val actual = if (index < candidate.size) candidate[index].lowercaseChar().code else 0
            difference = difference or (expected xor actual)
        }
        return difference == 0
    }

    override fun close() {
        chars?.fill('\u0000')
        chars = null
    }

    companion object {
        private val WORD_COUNTS = setOf(12, 15, 18, 21, 24)

        fun takeOwnership(chars: CharArray): SensitiveRecoveryPhrase? {
            val normalized = normalizeAsciiSpaces(chars)
            chars.fill('\u0000')
            if (normalized == null || !isSafePhraseShape(normalized)) {
                normalized?.fill('\u0000')
                return null
            }
            return SensitiveRecoveryPhrase(normalized)
        }

        private fun isSafePhraseShape(chars: CharArray): Boolean {
            if (chars.isEmpty() || chars.size > 256 || countWords(chars) !in WORD_COUNTS) return false
            return chars.all { it == ' ' || it in 'a'..'z' }
        }

        private fun normalizeAsciiSpaces(chars: CharArray): CharArray? {
            val normalized = CharArray(chars.size)
            var write = 0
            var pendingSpace = false
            for (char in chars) {
                when {
                    char.isWhitespace() -> if (write > 0) pendingSpace = true
                    char in 'A'..'Z' || char in 'a'..'z' -> {
                        if (pendingSpace && write > 0) normalized[write++] = ' '
                        normalized[write++] = char.lowercaseChar()
                        pendingSpace = false
                    }
                    else -> {
                        normalized.fill('\u0000')
                        return null
                    }
                }
            }
            return normalized.copyOf(write).also { normalized.fill('\u0000') }
        }

        private fun countWords(chars: CharArray): Int {
            var words = 0
            var inWord = false
            for (char in chars) {
                if (char == '\u0000') break
                if (char == ' ') {
                    inWord = false
                } else if (!inWord) {
                    words++
                    inWord = true
                }
            }
            return words
        }
    }
}

/** Generic wipeable native character buffer used by the Android screen. */
internal class SensitiveChars private constructor(private var chars: CharArray?) : AutoCloseable, CharSequence {
    override val length: Int
        get() = chars?.indexOfFirst { it == '\u0000' }?.let { if (it < 0) chars?.size ?: 0 else it } ?: 0

    override fun get(index: Int): Char = chars?.get(index) ?: throw IndexOutOfBoundsException()

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
        chars?.copyOfRange(startIndex, endIndex)?.let(::SensitiveChars)
            ?: throw IndexOutOfBoundsException()

    fun copyChars(): CharArray = chars?.copyOfRange(0, length) ?: CharArray(0)

    override fun close() {
        chars?.fill('\u0000')
        chars = null
    }

    companion object {
        fun takeOwnership(chars: CharArray): SensitiveChars = SensitiveChars(chars)
    }
}

/** Immutable native-transfer review bound to canonical Rust signing bytes. */
internal class ExactSepoliaTransferReview private constructor(
    val sender: String,
    val recipient: String,
    val valueWei: String,
    val nonce: String,
    val maxFeePerGasWei: String,
    val maxPriorityFeePerGasWei: String,
    val expiresAtEpochMillis: Long,
    operationId: ByteArray,
    canonicalSigningPayload: ByteArray,
) : AutoCloseable {
    val chainId: Long = SEPOLIA_CHAIN_ID
    val gasLimit: Long = NATIVE_TRANSFER_GAS
    val valueEth: String = formatEth(valueWei)
    val maximumFeeWei: String = BigInteger(maxFeePerGasWei)
        .multiply(BigInteger.valueOf(NATIVE_TRANSFER_GAS))
        .toString()

    private var payload: ByteArray? = canonicalSigningPayload.copyOf()
    val displayAmount: String = formatUnits(amount, assetDecimals)

    private var operation: ByteArray? = operationId.copyOf()
    private val boundDigest = computeDigest(operationId, canonicalSigningPayload)

    fun copyOperationId(): ByteArray = operation?.copyOf()
        ?: throw IllegalStateException("transfer review is closed")

    fun copySigningPayload(): ByteArray = payload?.copyOf()
        ?: throw IllegalStateException("transfer review is closed")

    fun isStillBound(): Boolean {
        val bytes = payload ?: return false
        val operationId = operation ?: return false
        return MessageDigest.isEqual(boundDigest, computeDigest(operationId, bytes))
    }

    fun hasSameBinding(other: ExactSepoliaTransferReview): Boolean =
        MessageDigest.isEqual(boundDigest, other.boundDigest)

    override fun close() {
        payload?.fill(0)
        payload = null
        operation?.fill(0)
        operation = null
        boundDigest.fill(0)
    }

    private fun computeDigest(operationId: ByteArray, signingPayload: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        listOf(
            DOMAIN,
            chainId.toString(),
            sender,
            recipient,
            valueWei,
            nonce,
            gasLimit.toString(),
            maxFeePerGasWei,
            maxPriorityFeePerGasWei,
            expiresAtEpochMillis.toString(),
        ).forEach { field ->
            val bytes = field.toByteArray(StandardCharsets.US_ASCII)
            digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
            digest.update(bytes)
        }
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(operationId.size).array())
        digest.update(operationId)
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(signingPayload.size).array())
        digest.update(signingPayload)
        return digest.digest()
    }

    companion object {
        const val SEPOLIA_CHAIN_ID = 11_155_111L
        const val NATIVE_TRANSFER_GAS = 21_000L
        const val MAX_SIGNING_PAYLOAD_BYTES = 4_096
        private const val DOMAIN = "ratspeak.android.ethereum.review.v1"
        private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")
        private val MAX_U256 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
        private val MAX_U64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

        fun checked(
            chainId: Long,
            sender: String,
            recipient: String,
            valueWei: String,
            nonce: String,
            gasLimit: Long,
            maxFeePerGasWei: String,
            maxPriorityFeePerGasWei: String,
            expiresAtEpochMillis: Long,
            operationId: ByteArray,
            canonicalSigningPayload: ByteArray,
        ): ExactSepoliaTransferReview? {
            if (chainId != SEPOLIA_CHAIN_ID || gasLimit != NATIVE_TRANSFER_GAS) return null
            if (!ADDRESS.matches(sender) || !ADDRESS.matches(recipient)) return null
            if (operationId.size != 16 || operationId.all { it == 0.toByte() }) return null
            if (canonicalSigningPayload.isEmpty() || canonicalSigningPayload.size > MAX_SIGNING_PAYLOAD_BYTES) return null
            val value = parseCanonicalUnsigned(valueWei, MAX_U256) ?: return null
            val parsedNonce = parseCanonicalUnsigned(nonce, MAX_U64) ?: return null
            val maxFee = parseCanonicalUnsigned(maxFeePerGasWei, MAX_U256) ?: return null
            val priorityFee = parseCanonicalUnsigned(maxPriorityFeePerGasWei, MAX_U256) ?: return null
            if (priorityFee > maxFee || expiresAtEpochMillis <= 0 || value.signum() < 0 || parsedNonce.signum() < 0) {
                return null
            }
            return ExactSepoliaTransferReview(
                sender,
                recipient,
                valueWei,
                nonce,
                maxFeePerGasWei,
                maxPriorityFeePerGasWei,
                expiresAtEpochMillis,
                operationId,
                canonicalSigningPayload,
            )
        }

        private fun formatUnits(value: String, decimals: Int): String {
            if (decimals == 0) return value
            val padded = value.padStart(decimals + 1, '0')
            val whole = padded.dropLast(decimals).trimStart('0').ifEmpty { "0" }
            val fractional = padded.takeLast(decimals).trimEnd('0')
            return if (fractional.isEmpty()) whole else "$whole.$fractional"
        }

        private fun parseCanonicalUnsigned(value: String, maximum: BigInteger): BigInteger? {
            if (!Regex("^(0|[1-9][0-9]*)$").matches(value)) return null
            val number = try {
                BigInteger(value)
            } catch (_: NumberFormatException) {
                return null
            }
            return number.takeIf { it <= maximum }
        }

        private fun formatEth(valueWei: String): String {
            val padded = valueWei.padStart(19, '0')
            val whole = padded.dropLast(18).trimStart('0').ifEmpty { "0" }
            val fractional = padded.takeLast(18).trimEnd('0')
            return if (fractional.isEmpty()) whole else "$whole.$fractional"
        }
    }
}

/** Immutable multichain clear-sign review bound to one Rust-retained operation. */
internal class ExactClearSignedReview private constructor(
    val chainId: Long,
    val sender: String,
    val network: String,
    val assetSymbol: String,
    val assetDecimals: Int,
    val recipient: String,
    val amount: String,
    val nonce: String,
    val gasLimit: Long,
    val maxFeePerGasWei: String,
    val maxPriorityFeePerGasWei: String,
    val expiresAtEpochMillis: Long,
    operationId: ByteArray,
    definitionHash: ByteArray,
    operationHash: ByteArray,
    canonicalSigningPayload: ByteArray,
) : AutoCloseable {
    private var operation: ByteArray? = operationId.copyOf()
    private var definition: ByteArray? = definitionHash.copyOf()
    private var operationDigest: ByteArray? = operationHash.copyOf()
    private var payload: ByteArray? = canonicalSigningPayload.copyOf()
    private val boundDigest = computeDigest(
        operationId,
        definitionHash,
        operationHash,
        canonicalSigningPayload,
    )

    fun copyOperationId(): ByteArray = operation?.copyOf()
        ?: throw IllegalStateException("clear-sign review is closed")

    fun copyDefinitionHash(): ByteArray = definition?.copyOf()
        ?: throw IllegalStateException("clear-sign review is closed")

    fun copyOperationHash(): ByteArray = operationDigest?.copyOf()
        ?: throw IllegalStateException("clear-sign review is closed")

    fun copySigningPayload(): ByteArray = payload?.copyOf()
        ?: throw IllegalStateException("clear-sign review is closed")

    fun isStillBound(): Boolean {
        val op = operation ?: return false
        val def = definition ?: return false
        val opHash = operationDigest ?: return false
        val signing = payload ?: return false
        return MessageDigest.isEqual(
            boundDigest,
            computeDigest(op, def, opHash, signing),
        )
    }

    override fun close() {
        operation?.fill(0)
        definition?.fill(0)
        operationDigest?.fill(0)
        payload?.fill(0)
        operation = null
        definition = null
        operationDigest = null
        payload = null
        boundDigest.fill(0)
    }

    private fun computeDigest(
        operationId: ByteArray,
        definitionHash: ByteArray,
        operationHash: ByteArray,
        signingPayload: ByteArray,
    ): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        listOf(
            DOMAIN,
            chainId.toString(),
            sender,
            network,
            assetSymbol,
            assetDecimals.toString(),
            recipient,
            amount,
            nonce,
            gasLimit.toString(),
            maxFeePerGasWei,
            maxPriorityFeePerGasWei,
            expiresAtEpochMillis.toString(),
        ).forEach { field ->
            val bytes = field.toByteArray(StandardCharsets.US_ASCII)
            digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
            digest.update(bytes)
        }
        listOf(operationId, definitionHash, operationHash, signingPayload).forEach { bytes ->
            digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
            digest.update(bytes)
        }
        return digest.digest()
    }

    companion object {
        private const val DOMAIN = "ratspeak.android.ethereum.clear-sign-review.v1"
        const val MAX_SIGNING_PAYLOAD_BYTES = 4_096
        private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")
        private val SYMBOL = Regex("^[A-Za-z0-9._-]{1,32}$")
        private val NETWORKS = mapOf(
            11_155_111L to "Ethereum Sepolia",
            84_532L to "Base Sepolia",
            11_155_420L to "OP Sepolia",
            421_614L to "Arbitrum Sepolia",
            46_630L to "Robinhood Chain Testnet",
        )
        private val MAX_U256 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
        private val MAX_U64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

        fun checked(
            chainId: Long,
            sender: String,
            network: String,
            definitionHash: ByteArray,
            operationHash: ByteArray,
            assetSymbol: String,
            assetDecimals: Int,
            recipient: String,
            amount: String,
            nonce: String,
            gasLimit: Long,
            maxFeePerGasWei: String,
            maxPriorityFeePerGasWei: String,
            expiresAtEpochMillis: Long,
            operationId: ByteArray,
            canonicalSigningPayload: ByteArray,
        ): ExactClearSignedReview? {
            if (NETWORKS[chainId] != network) return null
            if (!ADDRESS.matches(sender) || !ADDRESS.matches(recipient)) return null
            if (!SYMBOL.matches(assetSymbol) || assetDecimals !in 0..36) return null
            if (operationId.size != 16 || operationId.all { it == 0.toByte() }) return null
            if (definitionHash.size != 32 || definitionHash.all { it == 0.toByte() }) return null
            if (operationHash.size != 32 || operationHash.all { it == 0.toByte() }) return null
            if (canonicalSigningPayload.isEmpty() ||
                canonicalSigningPayload.size > MAX_SIGNING_PAYLOAD_BYTES
            ) return null
            if (gasLimit <= 0 || expiresAtEpochMillis <= 0) return null
            val parsedAmount = parseCanonicalUnsigned(amount, MAX_U256) ?: return null
            val parsedNonce = parseCanonicalUnsigned(nonce, MAX_U64) ?: return null
            val maxFee = parseCanonicalUnsigned(maxFeePerGasWei, MAX_U256) ?: return null
            val priorityFee =
                parseCanonicalUnsigned(maxPriorityFeePerGasWei, MAX_U256) ?: return null
            if (priorityFee > maxFee || parsedAmount.signum() < 0 || parsedNonce.signum() < 0) {
                return null
            }
            return ExactClearSignedReview(
                chainId,
                sender.lowercase(Locale.ROOT),
                network,
                assetSymbol,
                assetDecimals,
                recipient.lowercase(Locale.ROOT),
                amount,
                nonce,
                gasLimit,
                maxFeePerGasWei,
                maxPriorityFeePerGasWei,
                expiresAtEpochMillis,
                operationId,
                definitionHash,
                operationHash,
                canonicalSigningPayload,
            )
        }

        private fun parseCanonicalUnsigned(value: String, maximum: BigInteger): BigInteger? {
            if (!Regex("^(0|[1-9][0-9]*)$").matches(value)) return null
            val number = try {
                BigInteger(value)
            } catch (_: NumberFormatException) {
                return null
            }
            return number.takeIf { it <= maximum }
        }
    }
}

internal fun ethereumAddressesEqual(first: String, second: String): Boolean =
    first.lowercase(Locale.ROOT) == second.lowercase(Locale.ROOT)
