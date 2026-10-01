package org.ratspeak.android.ethereum

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumCustodyPolicyTest {
    @Test
    fun custodyRequiresAndroidThirtyOrNewer() {
        assertFalse(EthereumCustodyPolicy.supportsApi(29))
        assertTrue(EthereumCustodyPolicy.supportsApi(30))
        assertTrue(EthereumCustodyPolicy.supportsApi(36))
    }

    @Test
    fun custodyAssociatedDataIsCanonicalAndAccountBound() {
        val lower = EthereumCustodyPolicy.accountBindingAad(
            "0x11111111111111111111111111111111111111aa",
        )!!
        val upper = EthereumCustodyPolicy.accountBindingAad(
            "0x11111111111111111111111111111111111111AA",
        )!!
        val other = EthereumCustodyPolicy.accountBindingAad(
            "0x22222222222222222222222222222222222222aa",
        )!!
        assertArrayEquals(lower, upper)
        assertFalse(lower.contentEquals(other))
        assertNull(EthereumCustodyPolicy.accountBindingAad("not-an-address"))
    }

    @Test
    fun onlyHardwareSecurityLevelsAreAccepted() {
        assertFalse(EthereumCustodyPolicy.acceptsSecurityLevel(EthereumCustodyPolicy.SecurityLevel.SOFTWARE))
        assertFalse(
            EthereumCustodyPolicy.acceptsSecurityLevel(
                EthereumCustodyPolicy.SecurityLevel.UNKNOWN_SECURE,
            ),
        )
        assertFalse(EthereumCustodyPolicy.acceptsSecurityLevel(EthereumCustodyPolicy.SecurityLevel.UNKNOWN))
        assertTrue(EthereumCustodyPolicy.acceptsSecurityLevel(EthereumCustodyPolicy.SecurityLevel.HARDWARE))
        assertTrue(
            EthereumCustodyPolicy.acceptsSecurityLevel(
                EthereumCustodyPolicy.SecurityLevel.TRUSTED_ENVIRONMENT,
            ),
        )
        assertTrue(EthereumCustodyPolicy.acceptsSecurityLevel(EthereumCustodyPolicy.SecurityLevel.STRONGBOX))
    }

    @Test
    fun observableWrappingKeyPolicyMustMatchEveryAvailableProperty() {
        val valid = validObservableKeyPolicy()
        assertTrue(EthereumCustodyPolicy.acceptsObservableKeyPolicy(valid))

        val mutations = listOf(
            valid.copy(securityLevel = EthereumCustodyPolicy.SecurityLevel.UNKNOWN_SECURE),
            valid.copy(keySizeBits = 128),
            valid.copy(purposes = 1),
            valid.copy(blockModes = setOf("CBC")),
            valid.copy(encryptionPaddings = setOf("PKCS7Padding")),
            valid.copy(userAuthenticationRequired = false),
            valid.copy(authenticationValiditySeconds = 1),
            valid.copy(authenticationType = 1),
            valid.copy(authenticationEnforcedBySecureHardware = false),
            valid.copy(invalidatedByBiometricEnrollment = false),
            valid.copy(generatedInsideKeystore = false),
        )
        assertTrue(mutations.all { !EthereumCustodyPolicy.acceptsObservableKeyPolicy(it) })
    }

    @Test
    fun secretAndEnvelopeLengthsFailClosed() {
        assertFalse(EthereumCustodyPolicy.validSecretLength(0))
        assertTrue(EthereumCustodyPolicy.validSecretLength(EthereumCustodyPolicy.MAX_SECRET_BYTES))
        assertFalse(EthereumCustodyPolicy.validSecretLength(EthereumCustodyPolicy.MAX_SECRET_BYTES + 1))
        assertTrue(EthereumCustodyPolicy.validEnvelopeLengths(12, 16))
        assertFalse(EthereumCustodyPolicy.validEnvelopeLengths(11, 16))
        assertFalse(EthereumCustodyPolicy.validEnvelopeLengths(12, 0))
    }

    @Test
    fun rejectedSecretOwnershipClearsCallerBuffer() {
        val bytes = ByteArray(EthereumCustodyPolicy.MAX_SECRET_BYTES + 1) { 0x5a }
        assertNull(SensitiveWalletBytes.takeOwnership(bytes))
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun consumedSecretIsClearedAndCannotBeConsumedTwice() {
        val original = byteArrayOf(1, 2, 3, 4)
        val secret = SensitiveWalletBytes.takeOwnership(original)!!
        val copied = secret.consume { it.copyOf() }
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), copied)
        assertTrue(original.all { it == 0.toByte() })
        var failed = false
        try {
            secret.consume { }
        } catch (_: IllegalStateException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun wrappedEnvelopeDefensivelyCopiesCiphertext() {
        val iv = ByteArray(12) { 1 }
        val ciphertext = ByteArray(16) { 2 }
        val wrapped = WrappedWalletSecret.checked(iv, ciphertext)!!
        iv.fill(9)
        ciphertext.fill(9)
        assertTrue(wrapped.copyIv().all { it == 1.toByte() })
        assertTrue(wrapped.copyCiphertext().all { it == 2.toByte() })
    }

    @Test
    fun wrappedEnvelopeCodecIsBoundedAndRejectsMutation() {
        val wrapped = WrappedWalletSecret.checked(ByteArray(12) { 1 }, ByteArray(16) { 2 })!!
        val encoded = WrappedWalletSecretCodec.encode(wrapped)
        val decoded = WrappedWalletSecretCodec.decode(encoded)!!
        assertArrayEquals(wrapped.copyIv(), decoded.copyIv())
        assertArrayEquals(wrapped.copyCiphertext(), decoded.copyCiphertext())

        encoded[0] = 0
        assertNull(WrappedWalletSecretCodec.decode(encoded))
        assertNull(WrappedWalletSecretCodec.decode(ByteArray(WrappedWalletSecretCodec.MAX_ENCODED_BYTES + 1)))
    }

    private fun validObservableKeyPolicy() = EthereumCustodyPolicy.ObservableKeyPolicy(
        securityLevel = EthereumCustodyPolicy.SecurityLevel.STRONGBOX,
        keySizeBits = 256,
        purposes = EthereumCustodyPolicy.REQUIRED_KEY_PURPOSES,
        blockModes = setOf("GCM"),
        encryptionPaddings = setOf("NoPadding"),
        userAuthenticationRequired = true,
        authenticationValiditySeconds = 0,
        authenticationType = 2,
        authenticationEnforcedBySecureHardware = true,
        invalidatedByBiometricEnrollment = true,
        generatedInsideKeystore = true,
    )
}
