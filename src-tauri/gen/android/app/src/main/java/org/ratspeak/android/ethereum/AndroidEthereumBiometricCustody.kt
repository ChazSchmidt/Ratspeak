package org.ratspeak.android.ethereum

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

/** Result callback used only by native Android wallet screens and future JNI glue. */
internal sealed class EthereumCustodyResult<out T> {
    data class Success<T>(val value: T) : EthereumCustodyResult<T>()
    data class Failure(val reason: EthereumCustodyFailure) : EthereumCustodyResult<Nothing>()
}

/**
 * Per-operation biometric authorization for wrapping and unwrapping wallet bytes.
 *
 * No method is annotated with `JavascriptInterface`, registered with Tauri, or
 * reachable from the existing native bridge. Each operation binds BiometricPrompt
 * to the exact Keystore Cipher and clears plaintext buffers after use.
 *
 * This stage authorizes custody wrap/unlock operations only. It does not display
 * or authorize an Ethereum transaction and must not implement the Rust
 * `TransferAuthorizer` boundary until a native review screen and narrow JNI call
 * bind one reviewed transaction to one prompt.
 */
internal class AndroidEthereumBiometricCustody(private val activity: Activity) : AutoCloseable {
    private val sessions = CustodyOperationSessions()
    private val store = AndroidEthereumSecretStore(activity.applicationContext)

    fun wrapAndStore(
        accountAddress: String,
        secret: SensitiveWalletBytes,
        callback: (EthereumCustodyResult<Unit>) -> Unit,
    ) {
        val token = sessions.begin(secret::close)
        if (token == null) {
            secret.close()
            deliverUntracked(
                EthereumCustodyResult.Failure(EthereumCustodyFailure.BUSY),
                callback,
            )
            return
        }
        if (Build.VERSION.SDK_INT < EthereumCustodyPolicy.MIN_API_LEVEL) {
            finishFailure(
                token,
                EthereumCustodyFailure.UNSUPPORTED_ANDROID,
                callback,
            )
            return
        }
        val custodyAad = EthereumCustodyPolicy.accountBindingAad(accountAddress)
        if (custodyAad == null) {
            finishFailure(token, EthereumCustodyFailure.INVALID_ENVELOPE, callback)
            return
        }
        val keyStore: AndroidEthereumKeystore
        val cipher: Cipher
        try {
            keyStore = AndroidEthereumKeystore(activity.applicationContext)
            cipher = keyStore.encryptionCipher()
        } catch (error: Throwable) {
            finishFailure(token, failureForEncryption(error), callback)
            return
        }
        authenticate(
            token,
            cipher,
            callback,
            cryptoFailure = { error -> failureAfterCrypto(keyStore, error) },
        ) { authorizedCipher ->
            authorizedCipher.updateAAD(custodyAad)
            val encrypted = secret.consume(authorizedCipher::doFinal)
            val envelope = WrappedWalletSecret.checked(authorizedCipher.iv, encrypted)
                ?: throw IllegalStateException("invalid encrypted wallet envelope")
            store.write(envelope)
        }
    }

    fun authorizeAndLoad(
        accountAddress: String,
        callback: (EthereumCustodyResult<SensitiveWalletBytes>) -> Unit,
    ) {
        val token = sessions.begin {}
        if (token == null) {
            deliverUntracked(
                EthereumCustodyResult.Failure(EthereumCustodyFailure.BUSY),
                callback,
            )
            return
        }
        if (Build.VERSION.SDK_INT < EthereumCustodyPolicy.MIN_API_LEVEL) {
            finishFailure(
                token,
                EthereumCustodyFailure.UNSUPPORTED_ANDROID,
                callback,
            )
            return
        }
        val custodyAad = EthereumCustodyPolicy.accountBindingAad(accountAddress)
        if (custodyAad == null) {
            finishFailure(token, EthereumCustodyFailure.INVALID_ENVELOPE, callback)
            return
        }
        val envelope = try {
            store.read()
        } catch (_: Throwable) {
            null
        }
        if (envelope == null) {
            finishFailure(token, EthereumCustodyFailure.INVALID_ENVELOPE, callback)
            return
        }
        var keyStore: AndroidEthereumKeystore? = null
        val cipher: Cipher
        try {
            val existingKeyStore = AndroidEthereumKeystore(activity.applicationContext)
            keyStore = existingKeyStore
            cipher = existingKeyStore.decryptionCipher(envelope)
        } catch (_: Throwable) {
            recoverAfterUnavailableKey(keyStore)
            finishFailure(
                token,
                EthereumCustodyFailure.KEY_INVALIDATED_RECOVERY_REQUIRED,
                callback,
            )
            return
        }
        authenticate(
            token,
            cipher,
            callback,
            cryptoFailure = { error -> failureAfterCrypto(keyStore, error) },
        ) { authorizedCipher ->
            authorizedCipher.updateAAD(custodyAad)
            val plaintext = authorizedCipher.doFinal(envelope.copyCiphertext())
            SensitiveWalletBytes.takeOwnership(plaintext)
                ?: throw IllegalStateException("invalid decrypted wallet secret")
        }
    }

    override fun close() {
        sessions.close()
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun <T> authenticate(
        token: CustodyOperationSessions.Token,
        cipher: Cipher,
        callback: (EthereumCustodyResult<T>) -> Unit,
        cryptoFailure: (Throwable) -> EthereumCustodyFailure,
        operation: (Cipher) -> T,
    ) {
        try {
            val manager = activity.getSystemService(BiometricManager::class.java)
            if (manager?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
                BiometricManager.BIOMETRIC_SUCCESS
            ) {
                finishFailure(token, EthereumCustodyFailure.BIOMETRIC_UNAVAILABLE, callback)
                return
            }
            val signal = CancellationSignal()
            if (!sessions.attachCancellation(token, signal::cancel)) return
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle(activity.getString(org.ratspeak.android.R.string.ethereum_wallet_authorize_title))
                .setSubtitle(activity.getString(org.ratspeak.android.R.string.ethereum_wallet_authorize_subtitle))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .setNegativeButton(
                    activity.getString(android.R.string.cancel),
                    activity.mainExecutor,
                ) { _, _ ->
                    finishFailure(
                        token,
                        EthereumCustodyFailure.AUTHENTICATION_CANCELLED,
                        callback,
                    )
                }
                .build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(cipher),
                signal,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        finishFailure(
                            token,
                            EthereumCustodyFailure.AUTHENTICATION_CANCELLED,
                            callback,
                        )
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!sessions.claim(token)) return
                        val authorizedCipher = result.cryptoObject?.cipher
                        if (authorizedCipher == null || authorizedCipher !== cipher) {
                            sessions.abandonClaimed(token)
                            deliverClaimed(
                                token,
                                EthereumCustodyResult.Failure(EthereumCustodyFailure.OPERATION_FAILED),
                                callback,
                            )
                            return
                        }
                        val terminal = try {
                            EthereumCustodyResult.Success(operation(authorizedCipher))
                        } catch (error: Throwable) {
                            sessions.abandonClaimed(token)
                            val reason = cryptoFailure(error)
                            EthereumCustodyResult.Failure(reason)
                        }
                        deliverClaimed(token, terminal, callback)
                    }
                },
            )
        } catch (_: Throwable) {
            finishFailure(token, EthereumCustodyFailure.OPERATION_FAILED, callback)
        }
    }

    private fun failureForEncryption(error: Throwable): EthereumCustodyFailure = when {
        error is AndroidEthereumKeystore.HardwareSecurityUnavailableException ->
            EthereumCustodyFailure.HARDWARE_SECURITY_UNAVAILABLE
        else -> EthereumCustodyFailure.OPERATION_FAILED
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun failureAfterCrypto(
        keyStore: AndroidEthereumKeystore?,
        error: Throwable,
    ): EthereumCustodyFailure = when {
        AndroidEthereumKeystore.isInvalidated(error) -> {
            recoverAfterUnavailableKey(keyStore)
            EthereumCustodyFailure.KEY_INVALIDATED_RECOVERY_REQUIRED
        }
        error is AEADBadTagException -> EthereumCustodyFailure.INVALID_ENVELOPE
        else -> EthereumCustodyFailure.OPERATION_FAILED
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun recoverAfterUnavailableKey(keyStore: AndroidEthereumKeystore?) {
        try {
            keyStore?.deleteInvalidatedKeyBestEffort()
        } catch (_: Throwable) {
            // Recovery-required remains authoritative even if cleanup fails.
        }
        store.deleteBestEffort()
    }

    private fun <T> finishFailure(
        token: CustodyOperationSessions.Token,
        reason: EthereumCustodyFailure,
        callback: (EthereumCustodyResult<T>) -> Unit,
    ) {
        if (!sessions.claim(token)) return
        sessions.abandonClaimed(token)
        deliverClaimed(token, EthereumCustodyResult.Failure(reason), callback)
    }

    private fun <T> deliverClaimed(
        token: CustodyOperationSessions.Token,
        result: EthereumCustodyResult<T>,
        callback: (EthereumCustodyResult<T>) -> Unit,
    ) {
        sessions.finishAndDeliver(token, result, ::discardResult, callback)
    }

    private fun <T> deliverUntracked(
        result: EthereumCustodyResult<T>,
        callback: (EthereumCustodyResult<T>) -> Unit,
    ) {
        try {
            callback(result)
        } catch (_: Throwable) {
            discardResult(result)
        }
    }

    private fun discardResult(result: EthereumCustodyResult<*>) {
        val value = (result as? EthereumCustodyResult.Success<*>)?.value
        if (value is AutoCloseable) {
            try {
                value.close()
            } catch (_: Throwable) {
                // Sensitive-result cleanup is best effort and never re-delivered.
            }
        }
    }
}
