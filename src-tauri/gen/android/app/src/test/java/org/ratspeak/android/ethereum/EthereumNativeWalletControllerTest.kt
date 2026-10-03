package org.ratspeak.android.ethereum

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EthereumNativeWalletControllerTest {
    @Test
    fun expiredLauncherCleanupInvokesNativeCancellationExactlyOnce() {
        var cancellations = 0
        val closeOnce = NativeWalletCloseOnce { cancellations += 1 }

        closeOnce.close()
        closeOnce.close()

        assertEquals(1, cancellations)
    }

    @Test
    fun processWideCeremonyLeaseSerializesTheSingleWalletVault() {
        var now = 100L
        val lease = EthereumNativeCeremonyLease { now }

        assertTrue(lease.acquire("first", 200))
        assertTrue(lease.claim("first"))
        now = 300
        assertFalse(lease.acquire("second", 400))
        assertNull(lease.expirePending())
        assertTrue(lease.release("first"))
        assertTrue(lease.acquire("second", 400))
    }

    @Test
    fun unclaimedCeremonyLeaseExpiresFailClosed() {
        var now = 100L
        val lease = EthereumNativeCeremonyLease { now }

        assertTrue(lease.acquire("first", 200))
        now = 200
        assertEquals("first", lease.expirePending())
        assertFalse(lease.claim("first"))
        assertTrue(lease.acquire("second", 300))
    }

    @Test
    fun createRequiresExactBackupConfirmationBeforeCustodyAndActivation() {
        val fixture = Fixture()

        fixture.controller.beginCreate()
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.BackupDisplay)
        assertEquals(0, fixture.custody.wrapCalls)
        assertEquals(0, fixture.engine.activationCalls)
        assertEquals(0, fixture.engine.discardCalls)

        fixture.controller.beginBackupConfirmation()
        fixture.controller.confirmBackupWords(correctAnswers())
        assertEquals(1, fixture.custody.wrapCalls)
        assertEquals(ADDRESS, fixture.custody.wrappedAccount)
        assertEquals(0, fixture.engine.activationCalls)
        assertEquals(
            EthereumNativeWalletController.Purpose.ACTIVATE_WALLET,
            (fixture.lastState as EthereumNativeWalletController.State.Authorizing).purpose,
        )

        fixture.custody.completeWrap(EthereumCustodyResult.Success(Unit))
        assertEquals(1, fixture.engine.activationCalls)
        assertEquals(ADDRESS, (fixture.lastState as EthereumNativeWalletController.State.Active).address)
    }

    @Test
    fun failedBackupConfirmationWipesMaterialAndNeverTouchesCustody() {
        val fixture = Fixture()
        fixture.controller.beginCreate()
        val secret = fixture.engine.lastCreatedSecret!!
        fixture.controller.beginBackupConfirmation()

        fixture.controller.confirmBackupWords(
            mapOf(
                1 to "wrong".toCharArray(),
                6 to "abandon".toCharArray(),
                12 to "about".toCharArray(),
            ),
        )

        assertEquals(0, fixture.custody.wrapCalls)
        assertEquals(0, fixture.engine.activationCalls)
        assertEquals(1, fixture.engine.discardCalls)
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.Failed)
        assertThrows(IllegalStateException::class.java) { secret.consume { } }
    }

    @Test
    fun restoreInputIsWipedAndAlsoRequiresBackupConfirmation() {
        val fixture = Fixture()
        val input = "  ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n"
            .toCharArray()

        fixture.controller.submitRestorePhrase(input)

        assertTrue(input.all { it == '\u0000' })
        assertTrue(fixture.engine.restoreInputWipedAfterReturn)
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.BackupDisplay)
        assertEquals(0, fixture.custody.wrapCalls)
    }

    @Test
    fun exactReviewSignsOnceOnlyAfterBiometricCustodyReturns() {
        val fixture = Fixture()
        fixture.activateExisting()
        val review = checkedReview(expiresAt = 2_000)

        fixture.controller.beginTransferReview(review)
        fixture.controller.approveTransfer()
        assertEquals(0, fixture.engine.signCalls)

        fixture.custody.completeLoad(secretResult())

        assertEquals(1, fixture.engine.signCalls)
        assertEquals(TX_HASH, (fixture.lastState as EthereumNativeWalletController.State.Signed).transactionHash)
        assertEquals(1, fixture.custody.loadCalls)
        assertEquals(ADDRESS, fixture.custody.loadedAccount)
    }

    @Test
    fun expirationWhileBiometricPromptIsOpenNeverSigns() {
        var now = 1_000L
        val fixture = Fixture(clock = { now })
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 1_500))
        fixture.controller.approveTransfer()
        now = 1_500
        val secret = SensitiveWalletBytes.takeOwnership(byteArrayOf(7, 8, 9))!!

        fixture.custody.completeLoad(EthereumCustodyResult.Success(secret))

        assertEquals(0, fixture.engine.signCalls)
        assertThrows(IllegalStateException::class.java) { secret.consume { } }
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.Active)
    }

    @Test
    fun cancellationAndReplacementCannotDeliverAnOldSigningSession() {
        val fixture = Fixture()
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 3_000, nonce = "1"))
        fixture.controller.approveTransfer()
        fixture.controller.cancel()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 3_000, nonce = "2"))
        fixture.controller.approveTransfer()
        val staleSecret = SensitiveWalletBytes.takeOwnership(byteArrayOf(1, 2, 3))!!

        fixture.custody.completeLoadAt(0, EthereumCustodyResult.Success(staleSecret))
        assertEquals(0, fixture.engine.signCalls)
        assertThrows(IllegalStateException::class.java) { staleSecret.consume { } }

        fixture.custody.completeLoadAt(0, secretResult())
        assertEquals(1, fixture.engine.signCalls)
        assertEquals("2", fixture.engine.signedNonce)
    }

    @Test
    fun activityDestructionBarrierDiscardsLateSecretAndNeverSigns() {
        val fixture = Fixture()
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 2_000))
        fixture.controller.approveTransfer()
        fixture.controller.close()
        val lateSecret = SensitiveWalletBytes.takeOwnership(byteArrayOf(1, 2, 3))!!

        fixture.custody.completeLoad(EthereumCustodyResult.Success(lateSecret))

        assertEquals(0, fixture.engine.signCalls)
        assertTrue(fixture.custody.closed)
        assertThrows(IllegalStateException::class.java) { lateSecret.consume { } }
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.Unavailable)
    }

    @Test
    fun invalidatedKeystoreRequiresRecoveryWithoutSigningFallback() {
        val fixture = Fixture()
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 2_000))
        fixture.controller.approveTransfer()

        fixture.custody.completeLoad(
            EthereumCustodyResult.Failure(EthereumCustodyFailure.KEY_INVALIDATED_RECOVERY_REQUIRED),
        )

        assertEquals(0, fixture.engine.signCalls)
        val recovery = fixture.lastState as EthereumNativeWalletController.State.RecoveryRequired
        assertEquals(ADDRESS, recovery.expectedAddress)
    }

    @Test
    fun invalidatedKeystoreRecoveryMustRestoreAndRebindTheSameAddress() {
        val fixture = Fixture()
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 2_000))
        fixture.controller.approveTransfer()
        fixture.custody.completeLoad(
            EthereumCustodyResult.Failure(EthereumCustodyFailure.KEY_INVALIDATED_RECOVERY_REQUIRED),
        )
        fixture.engine.restoreAddress = OTHER_ADDRESS

        fixture.controller.submitRestorePhrase(PHRASE.toCharArray())

        assertTrue(fixture.lastState is EthereumNativeWalletController.State.RecoveryRequired)
        assertEquals(0, fixture.custody.wrapCalls)
        assertEquals(0, fixture.engine.recoveryCalls)
        assertEquals(1, fixture.engine.discardCalls)

        fixture.engine.restoreAddress = ADDRESS
        fixture.controller.submitRestorePhrase(PHRASE.toCharArray())
        fixture.controller.beginBackupConfirmation()
        fixture.controller.confirmBackupWords(correctAnswers())
        fixture.custody.completeWrap(EthereumCustodyResult.Success(Unit))

        assertEquals(1, fixture.engine.recoveryCalls)
        assertEquals(ADDRESS, fixture.engine.recoveryExpectedAddress)
        assertTrue(fixture.lastState is EthereumNativeWalletController.State.Active)
    }

    @Test
    fun corruptEnvelopeUsesAddressBoundRecoveryInsteadOfLoopingActive() {
        val fixture = Fixture()
        fixture.activateExisting()
        fixture.controller.beginRevealBackup()

        fixture.custody.completeLoad(EthereumCustodyResult.Failure(EthereumCustodyFailure.INVALID_ENVELOPE))

        val recovery = fixture.lastState as EthereumNativeWalletController.State.RecoveryRequired
        assertEquals(ADDRESS, recovery.expectedAddress)
        assertEquals("INVALID_ENVELOPE", recovery.reason)
    }

    @Test
    fun wrongSenderOrUnsupportedAndroidCannotEnterReviewOrCustody() {
        val oldAndroid = Fixture(apiLevel = 29)
        assertTrue(oldAndroid.lastState is EthereumNativeWalletController.State.Unavailable)
        oldAndroid.controller.beginCreate()
        assertEquals(0, oldAndroid.custody.wrapCalls)

        val fixture = Fixture()
        fixture.activateExisting()
        val wrongSender = checkedReview(sender = OTHER_ADDRESS, expiresAt = 2_000)
        fixture.controller.beginTransferReview(wrongSender)

        assertTrue(fixture.lastState is EthereumNativeWalletController.State.Active)
        assertFalse(wrongSender.isStillBound())
        assertEquals(0, fixture.custody.loadCalls)
    }

    @Test
    fun malformedOrBroadenedTransferReviewsAreRejected() {
        val payload = byteArrayOf(1, 2, 3)
        assertNull(reviewOrNull(chainId = 1, payload = payload))
        assertNull(reviewOrNull(gas = 21_001, payload = payload))
        assertNull(reviewOrNull(recipient = "", payload = payload))
        assertNull(reviewOrNull(value = "01", payload = payload))
        assertNull(reviewOrNull(maxFee = "2", priorityFee = "3", payload = payload))
        assertNull(reviewOrNull(payload = ByteArray(4_097)))
        assertNotNull(reviewOrNull(payload = payload))
    }

    @Test
    fun invalidTransactionHashFromNativeEngineIsNotReportedAsSigned() {
        val fixture = Fixture()
        fixture.engine.transactionHash = "not-a-transaction-hash"
        fixture.activateExisting()
        fixture.controller.beginTransferReview(checkedReview(expiresAt = 2_000))
        fixture.controller.approveTransfer()

        fixture.custody.completeLoad(secretResult())

        assertEquals(1, fixture.engine.signCalls)
        assertEquals(
            "INVALID_TRANSACTION_HASH",
            (fixture.lastState as EthereumNativeWalletController.State.Failed).reason,
        )
    }

    private class Fixture(
        apiLevel: Int = 30,
        clock: () -> Long = { 1_000L },
    ) {
        val engine = FakeEngine()
        val custody = FakeCustody()
        val states = mutableListOf<EthereumNativeWalletController.State>()
        val controller = EthereumNativeWalletController(apiLevel, clock, engine, custody, states::add)
        val lastState: EthereumNativeWalletController.State
            get() = states.last()

        fun activateExisting() {
            controller.markExistingWalletActive(ADDRESS)
            assertTrue(lastState is EthereumNativeWalletController.State.Active)
        }
    }

    private class FakeCustody : EthereumNativeCustody {
        var wrapCalls = 0
        var loadCalls = 0
        var wrappedAccount: String? = null
        var loadedAccount: String? = null
        var closed = false
        private val wrapCallbacks = mutableListOf<(EthereumCustodyResult<Unit>) -> Unit>()
        private val loadCallbacks = mutableListOf<(EthereumCustodyResult<SensitiveWalletBytes>) -> Unit>()

        override fun wrapAndStore(
            accountAddress: String,
            secret: SensitiveWalletBytes,
            callback: (EthereumCustodyResult<Unit>) -> Unit,
        ) {
            wrapCalls++
            wrappedAccount = accountAddress
            secret.close()
            wrapCallbacks += callback
        }

        override fun authorizeAndLoad(
            accountAddress: String,
            callback: (EthereumCustodyResult<SensitiveWalletBytes>) -> Unit,
        ) {
            loadCalls++
            loadedAccount = accountAddress
            loadCallbacks += callback
        }

        fun completeWrap(result: EthereumCustodyResult<Unit>) = wrapCallbacks.removeAt(0)(result)

        fun completeLoad(result: EthereumCustodyResult<SensitiveWalletBytes>) = completeLoadAt(0, result)

        fun completeLoadAt(index: Int, result: EthereumCustodyResult<SensitiveWalletBytes>) =
            loadCallbacks.removeAt(index)(result)

        override fun close() {
            closed = true
        }
    }

    private class FakeEngine : EthereumNativeWalletEngine {
        override val isAvailable = true
        var activationCalls = 0
        var discardCalls = 0
        var signCalls = 0
        var recoveryCalls = 0
        var recoveryExpectedAddress: String? = null
        var signedNonce: String? = null
        var transactionHash = TX_HASH
        var restoreAddress = ADDRESS
        var lastCreatedSecret: SensitiveWalletBytes? = null
        var restoreInputWipedAfterReturn = false

        override fun createWallet(): NativeWalletResult<PendingNativeWallet> {
            val secret = SensitiveWalletBytes.takeOwnership(byteArrayOf(1, 2, 3))!!
            lastCreatedSecret = secret
            return NativeWalletResult.Success(pendingWallet(secret))
        }

        override fun restoreWallet(recoveryPhrase: CharArray): NativeWalletResult<PendingNativeWallet> {
            // The controller owns and wipes this input immediately after return.
            restoreInputWipedAfterReturn = recoveryPhrase.any { it != '\u0000' }
            val normalized = SensitiveRecoveryPhrase.takeOwnership(recoveryPhrase.copyOf())
                ?: return NativeWalletResult.Failure(NativeWalletFailure.INVALID_RECOVERY_PHRASE)
            val secret = SensitiveWalletBytes.takeOwnership(byteArrayOf(4, 5, 6))!!
            return NativeWalletResult.Success(
                PendingNativeWallet(restoreAddress, normalized, secret, PendingWalletHandle(2)),
            )
        }

        override fun activateWallet(handle: PendingWalletHandle): NativeWalletResult<String> {
            activationCalls++
            return NativeWalletResult.Success(ADDRESS)
        }

        override fun discardPendingWallet(handle: PendingWalletHandle) {
            discardCalls++
        }

        override fun recoverWallet(
            handle: PendingWalletHandle,
            expectedAddress: String,
        ): NativeWalletResult<String> {
            recoveryCalls++
            recoveryExpectedAddress = expectedAddress
            return NativeWalletResult.Success(restoreAddress)
        }

        override fun revealRecoveryPhrase(secret: SensitiveWalletBytes): NativeWalletResult<SensitiveRecoveryPhrase> =
            NativeWalletResult.Success(phrase())

        override fun signExactTransfer(
            review: ExactSepoliaTransferReview,
            secret: SensitiveWalletBytes,
        ): NativeWalletResult<String> {
            signCalls++
            signedNonce = review.nonce
            return NativeWalletResult.Success(transactionHash)
        }

        override fun signClearSignedOperation(
            review: ExactClearSignedReview,
            secret: SensitiveWalletBytes,
        ): NativeWalletResult<String> {
            signCalls++
            signedNonce = review.nonce
            return NativeWalletResult.Success(transactionHash)
        }

        private fun pendingWallet(secret: SensitiveWalletBytes) =
            PendingNativeWallet(ADDRESS, phrase(), secret, PendingWalletHandle(1))
    }

    companion object {
        private const val ADDRESS = "0x1111111111111111111111111111111111111111"
        private const val OTHER_ADDRESS = "0x2222222222222222222222222222222222222222"
        private const val TX_HASH =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        private const val PHRASE =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        private fun phrase(): SensitiveRecoveryPhrase =
            SensitiveRecoveryPhrase.takeOwnership(PHRASE.toCharArray())!!

        private fun correctAnswers(): Map<Int, CharArray> = mapOf(
            1 to "abandon".toCharArray(),
            6 to "abandon".toCharArray(),
            12 to "about".toCharArray(),
        )

        private fun secretResult(): EthereumCustodyResult<SensitiveWalletBytes> =
            EthereumCustodyResult.Success(SensitiveWalletBytes.takeOwnership(byteArrayOf(7, 8, 9))!!)

        private fun checkedReview(
            sender: String = ADDRESS,
            nonce: String = "0",
            expiresAt: Long,
        ): ExactSepoliaTransferReview = reviewOrNull(
            sender = sender,
            nonce = nonce,
            expiresAt = expiresAt,
            payload = byteArrayOf(2, 1, 0, 0),
        )!!

        private fun reviewOrNull(
            chainId: Long = ExactSepoliaTransferReview.SEPOLIA_CHAIN_ID,
            sender: String = ADDRESS,
            recipient: String = OTHER_ADDRESS,
            value: String = "1000000000000000",
            nonce: String = "0",
            gas: Long = ExactSepoliaTransferReview.NATIVE_TRANSFER_GAS,
            maxFee: String = "2000000000",
            priorityFee: String = "1000000000",
            expiresAt: Long = 2_000,
            payload: ByteArray,
        ): ExactSepoliaTransferReview? = ExactSepoliaTransferReview.checked(
            chainId,
            sender,
            recipient,
            value,
            nonce,
            gas,
            maxFee,
            priorityFee,
            expiresAt,
            ByteArray(16) { 7 },
            payload,
        )
    }
}
