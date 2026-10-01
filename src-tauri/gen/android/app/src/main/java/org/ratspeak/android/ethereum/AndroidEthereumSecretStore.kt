package org.ratspeak.android.ethereum

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.IOException

/**
 * Ciphertext persistence confined to `Context.noBackupFilesDir`.
 *
 * The Keystore key itself is non-exportable and Android does not back it up.
 * This store deliberately has no SharedPreferences, database, external-storage,
 * document-provider, logging, WebView, or Tauri surface.
 */
internal class AndroidEthereumSecretStore(context: Context) {
    private val directory = File(context.noBackupFilesDir, DIRECTORY)
    private val file = AtomicFile(File(directory, FILE_NAME))

    fun write(envelope: WrappedWalletSecret) {
        val encoded = WrappedWalletSecretCodec.encode(envelope)
        check(encoded.size <= WrappedWalletSecretCodec.MAX_ENCODED_BYTES)
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("could not create native custody directory")
        }
        val output = file.startWrite()
        try {
            output.write(encoded)
            file.finishWrite(output)
        } catch (error: Throwable) {
            file.failWrite(output)
            throw error
        } finally {
            encoded.fill(0)
        }
    }

    fun read(): WrappedWalletSecret? {
        val base = file.baseFile
        if (!base.exists()) return null
        if (base.length() > WrappedWalletSecretCodec.MAX_ENCODED_BYTES) {
            deleteBestEffort()
            return null
        }
        val encoded = file.readFully()
        return try {
            WrappedWalletSecretCodec.decode(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    fun deleteBestEffort() {
        try {
            file.delete()
        } catch (_: Throwable) {
            // Recovery-required must not be masked by cleanup failure.
        }
    }

    companion object {
        private const val DIRECTORY = "ethereum-custody"
        private const val FILE_NAME = "wallet-secret.v1"
    }
}
