package org.ratspeak.android.ethereum

import java.nio.charset.StandardCharsets
import java.util.Locale

/** Policy values shared by the Android custody adapter and local unit tests. */
internal object EthereumCustodyPolicy {
    const val MIN_API_LEVEL = 30
    const val KEY_ALIAS = "org.ratspeak.ethereum.wallet-wrap.v1"
    const val MAX_SECRET_BYTES = 512
    const val GCM_IV_BYTES = 12
    const val GCM_TAG_BITS = 128
    const val AES_KEY_BITS = 256
    const val REQUIRED_KEY_PURPOSES = 3 // KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT
    private const val ACCOUNT_BINDING_DOMAIN = "ratspeak.android.ethereum.custody.v1:"
    private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")

    /** Public AEAD associated data binds the one app-profile vault to an account. */
    fun accountBindingAad(address: String): ByteArray? = address
        .takeIf(ADDRESS::matches)
        ?.lowercase(Locale.ROOT)
        ?.let { (ACCOUNT_BINDING_DOMAIN + it).toByteArray(StandardCharsets.US_ASCII) }

    enum class SecurityLevel {
        SOFTWARE,
        HARDWARE,
        TRUSTED_ENVIRONMENT,
        STRONGBOX,
        UNKNOWN_SECURE,
        UNKNOWN,
    }

    fun supportsApi(apiLevel: Int): Boolean = apiLevel >= MIN_API_LEVEL

    fun acceptsSecurityLevel(level: SecurityLevel): Boolean = when (level) {
        SecurityLevel.HARDWARE,
        SecurityLevel.TRUSTED_ENVIRONMENT,
        SecurityLevel.STRONGBOX,
        -> true
        SecurityLevel.SOFTWARE,
        SecurityLevel.UNKNOWN_SECURE,
        SecurityLevel.UNKNOWN,
        -> false
    }

    data class ObservableKeyPolicy(
        val securityLevel: SecurityLevel,
        val keySizeBits: Int,
        val purposes: Int,
        val blockModes: Set<String>,
        val encryptionPaddings: Set<String>,
        val userAuthenticationRequired: Boolean,
        val authenticationValiditySeconds: Int,
        val authenticationType: Int,
        val authenticationEnforcedBySecureHardware: Boolean,
        val invalidatedByBiometricEnrollment: Boolean,
        val generatedInsideKeystore: Boolean,
    )

    fun acceptsObservableKeyPolicy(policy: ObservableKeyPolicy): Boolean =
        acceptsSecurityLevel(policy.securityLevel) &&
            policy.keySizeBits == AES_KEY_BITS &&
            policy.purposes == REQUIRED_KEY_PURPOSES &&
            policy.blockModes == setOf("GCM") &&
            policy.encryptionPaddings == setOf("NoPadding") &&
            policy.userAuthenticationRequired &&
            policy.authenticationValiditySeconds == 0 &&
            policy.authenticationType == 2 && // KeyProperties.AUTH_BIOMETRIC_STRONG
            policy.authenticationEnforcedBySecureHardware &&
            policy.invalidatedByBiometricEnrollment &&
            policy.generatedInsideKeystore

    fun validSecretLength(length: Int): Boolean = length in 1..MAX_SECRET_BYTES

    fun validEnvelopeLengths(ivLength: Int, ciphertextLength: Int): Boolean =
        ivLength == GCM_IV_BYTES && ciphertextLength in 16..(MAX_SECRET_BYTES + 16)
}

/** Non-sensitive failure states safe to show outside the custody implementation. */
internal enum class EthereumCustodyFailure {
    UNSUPPORTED_ANDROID,
    HARDWARE_SECURITY_UNAVAILABLE,
    BIOMETRIC_UNAVAILABLE,
    AUTHENTICATION_CANCELLED,
    KEY_INVALIDATED_RECOVERY_REQUIRED,
    INVALID_SECRET_LENGTH,
    INVALID_ENVELOPE,
    BUSY,
    OPERATION_FAILED,
}

/** Ciphertext-only value; it never contains a mnemonic, seed, DEK, or private key. */
internal class WrappedWalletSecret private constructor(
    private val ivBytes: ByteArray,
    private val ciphertextBytes: ByteArray,
) {
    fun copyIv(): ByteArray = ivBytes.copyOf()

    fun copyCiphertext(): ByteArray = ciphertextBytes.copyOf()

    companion object {
        fun checked(iv: ByteArray, ciphertext: ByteArray): WrappedWalletSecret? {
            if (!EthereumCustodyPolicy.validEnvelopeLengths(iv.size, ciphertext.size)) return null
            return WrappedWalletSecret(iv.copyOf(), ciphertext.copyOf())
        }
    }
}

/** Fixed, bounded encoding for ciphertext stored only in Android's no-backup directory. */
internal object WrappedWalletSecretCodec {
    private val MAGIC = byteArrayOf(0x52, 0x53, 0x45, 0x54, 0x48, 0x57, 0x01, 0x00)
    const val MAX_ENCODED_BYTES = 8 + EthereumCustodyPolicy.GCM_IV_BYTES +
        EthereumCustodyPolicy.MAX_SECRET_BYTES + 16

    fun encode(envelope: WrappedWalletSecret): ByteArray {
        val iv = envelope.copyIv()
        val ciphertext = envelope.copyCiphertext()
        return MAGIC + iv + ciphertext
    }

    fun decode(encoded: ByteArray): WrappedWalletSecret? {
        if (encoded.size !in (MAGIC.size + EthereumCustodyPolicy.GCM_IV_BYTES + 16)..MAX_ENCODED_BYTES) {
            return null
        }
        if (!encoded.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) return null
        val ivStart = MAGIC.size
        val ciphertextStart = ivStart + EthereumCustodyPolicy.GCM_IV_BYTES
        return WrappedWalletSecret.checked(
            encoded.copyOfRange(ivStart, ciphertextStart),
            encoded.copyOfRange(ciphertextStart, encoded.size),
        )
    }
}

/** Native-only secret holder whose owned byte buffer is cleared on close. */
internal class SensitiveWalletBytes private constructor(private var value: ByteArray?) : AutoCloseable {
    fun <T> consume(block: (ByteArray) -> T): T {
        val bytes = value ?: throw IllegalStateException("wallet secret already consumed")
        value = null
        return try {
            block(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    override fun close() {
        value?.fill(0)
        value = null
    }

    companion object {
        fun takeOwnership(bytes: ByteArray): SensitiveWalletBytes? {
            if (!EthereumCustodyPolicy.validSecretLength(bytes.size)) {
                bytes.fill(0)
                return null
            }
            return SensitiveWalletBytes(bytes)
        }
    }
}
