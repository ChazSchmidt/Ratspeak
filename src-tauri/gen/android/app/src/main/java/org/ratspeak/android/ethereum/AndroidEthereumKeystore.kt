package org.ratspeak.android.ethereum

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore owner for the wallet-wrapping key.
 *
 * This type is deliberately package-internal and has no Tauri, JNI, WebView,
 * logging, export, or backup surface. API 30 can attest only that a symmetric
 * key is inside secure hardware; API 31+ additionally reports TEE/StrongBox.
 */
@RequiresApi(Build.VERSION_CODES.R)
internal class AndroidEthereumKeystore(private val context: Context) {
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun encryptionCipher(): Cipher {
        val cipher = newCipher()
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey())
        return cipher
    }

    fun decryptionCipher(envelope: WrappedWalletSecret): Cipher {
        val cipher = newCipher()
        cipher.init(
            Cipher.DECRYPT_MODE,
            requireExistingWrappingKey(),
            GCMParameterSpec(EthereumCustodyPolicy.GCM_TAG_BITS, envelope.copyIv()),
        )
        return cipher
    }

    fun deleteInvalidatedKeyBestEffort() {
        try {
            keyStore.deleteEntry(EthereumCustodyPolicy.KEY_ALIAS)
        } catch (_: Throwable) {
            // Recovery-required must not be masked by cleanup failure.
        }
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        val existing = keyStore.getKey(EthereumCustodyPolicy.KEY_ALIAS, null) as? SecretKey
        if (existing != null) {
            enforceHardwarePolicy(existing)
            return existing
        }
        return generateWrappingKey()
    }

    private fun requireExistingWrappingKey(): SecretKey {
        val existing = try {
            keyStore.getKey(EthereumCustodyPolicy.KEY_ALIAS, null) as? SecretKey
        } catch (error: Throwable) {
            throw ExistingKeyUnavailableException(error)
        } ?: throw ExistingKeyUnavailableException()
        try {
            enforceHardwarePolicy(existing)
        } catch (error: Throwable) {
            throw ExistingKeyUnavailableException(error)
        }
        return existing
    }

    private fun generateWrappingKey(): SecretKey {
        val strongBoxAvailable = context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
        val generated = if (strongBoxAvailable) {
            try {
                generate(strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                generate(strongBox = false)
            }
        } else {
            generate(strongBox = false)
        }
        return try {
            enforceHardwarePolicy(generated)
            generated
        } catch (error: Throwable) {
            deleteInvalidatedKeyBestEffort()
            throw error
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            EthereumCustodyPolicy.KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(EthereumCustodyPolicy.AES_KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
            .setInvalidatedByBiometricEnrollment(true)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        generator.init(builder.build())
        return generator.generateKey()
    }

    @Suppress("DEPRECATION")
    private fun enforceHardwarePolicy(key: SecretKey) {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val level = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> EthereumCustodyPolicy.SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                    EthereumCustodyPolicy.SecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> EthereumCustodyPolicy.SecurityLevel.SOFTWARE
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE ->
                    EthereumCustodyPolicy.SecurityLevel.UNKNOWN_SECURE
                else -> EthereumCustodyPolicy.SecurityLevel.UNKNOWN
            }
        // API 30 exposes only this coarser hardware-backed answer.
        } else if (info.isInsideSecureHardware) {
            EthereumCustodyPolicy.SecurityLevel.HARDWARE
        } else {
            EthereumCustodyPolicy.SecurityLevel.SOFTWARE
        }
        val observablePolicy = EthereumCustodyPolicy.ObservableKeyPolicy(
            securityLevel = level,
            keySizeBits = info.keySize,
            purposes = info.purposes,
            blockModes = info.blockModes.toSet(),
            encryptionPaddings = info.encryptionPaddings.toSet(),
            userAuthenticationRequired = info.isUserAuthenticationRequired,
            authenticationValiditySeconds = info.userAuthenticationValidityDurationSeconds,
            authenticationType = info.userAuthenticationType,
            authenticationEnforcedBySecureHardware =
                info.isUserAuthenticationRequirementEnforcedBySecureHardware,
            invalidatedByBiometricEnrollment = info.isInvalidatedByBiometricEnrollment,
            generatedInsideKeystore = info.origin == KeyProperties.ORIGIN_GENERATED,
        )
        // Android exposes no KeyInfo getter for randomized-encryption-required;
        // generation sets it true above, while all observable policy is checked.
        if (!EthereumCustodyPolicy.acceptsObservableKeyPolicy(observablePolicy)) {
            throw HardwareSecurityUnavailableException()
        }
    }

    private fun newCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    internal class HardwareSecurityUnavailableException : Exception()
    internal class ExistingKeyUnavailableException(cause: Throwable? = null) : Exception(cause)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        fun isInvalidated(error: Throwable): Boolean {
            var cause: Throwable? = error
            while (cause != null) {
                if (cause is KeyPermanentlyInvalidatedException) return true
                cause = cause.cause
            }
            return false
        }
    }
}
