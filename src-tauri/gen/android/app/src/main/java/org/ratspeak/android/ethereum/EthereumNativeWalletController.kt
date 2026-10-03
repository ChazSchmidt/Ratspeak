package org.ratspeak.android.ethereum

/** Asynchronous custody seam implemented by Android Keystore + BiometricPrompt. */
internal interface EthereumNativeCustody : AutoCloseable {
    fun wrapAndStore(
        accountAddress: String,
        secret: SensitiveWalletBytes,
        callback: (EthereumCustodyResult<Unit>) -> Unit,
    )

    fun authorizeAndLoad(
        accountAddress: String,
        callback: (EthereumCustodyResult<SensitiveWalletBytes>) -> Unit,
    )
}

internal class AndroidEthereumNativeCustody(activity: android.app.Activity) : EthereumNativeCustody {
    private val delegate = AndroidEthereumBiometricCustody(activity)

    override fun wrapAndStore(
        accountAddress: String,
        secret: SensitiveWalletBytes,
        callback: (EthereumCustodyResult<Unit>) -> Unit,
    ) = delegate.wrapAndStore(accountAddress, secret, callback)

    override fun authorizeAndLoad(
        accountAddress: String,
        callback: (EthereumCustodyResult<SensitiveWalletBytes>) -> Unit,
    ) = delegate.authorizeAndLoad(accountAddress, callback)

    override fun close() = delegate.close()
}

/** Native-only, one-operation-at-a-time wallet ceremony state machine. */
internal class EthereumNativeWalletController(
    private val apiLevel: Int,
    private val clockMillis: () -> Long,
    private val engine: EthereumNativeWalletEngine,
    private val custody: EthereumNativeCustody,
    private val observer: (State) -> Unit,
) : AutoCloseable {
    internal sealed class State {
        data class Unavailable(val reason: String) : State()
        data object Ready : State()
        data class BackupDisplay(val address: String, val wordCount: Int, val revealOnly: Boolean) : State()
        data class BackupConfirmation(val address: String, val wordIndexes: List<Int>, val revealOnly: Boolean) : State()
        data class Authorizing(val purpose: Purpose) : State()
        data class Active(val address: String) : State()
        data class Reviewing(val review: ExactSepoliaTransferReview) : State()
        data class ClearSigningReviewing(val review: ExactClearSignedReview) : State()
        data class Signed(val transactionHash: String) : State()
        data class RecoveryRequired(val expectedAddress: String, val reason: String) : State()
        data class Failed(val reason: String) : State()
    }

    internal enum class Purpose {
        ACTIVATE_WALLET,
        REVEAL_BACKUP,
        SIGN_TRANSFER,
        SIGN_CLEAR_SIGNED,
    }

    private var state: State
    private var operationGeneration = 0L
    private var pendingWallet: PendingNativeWallet? = null
    private var revealedPhrase: SensitiveRecoveryPhrase? = null
    private var activeAddress: String? = null
    private var recoveryExpectedAddress: String? = null
    private var review: ExactSepoliaTransferReview? = null
    private var clearSignReview: ExactClearSignedReview? = null
    private var closed = false

    init {
        state = when {
            !EthereumCustodyPolicy.supportsApi(apiLevel) -> State.Unavailable("Android 11 or newer is required")
            !engine.isAvailable -> State.Unavailable("Native Ethereum wallet support is not installed")
            else -> State.Ready
        }
        observer(state)
    }

    fun beginCreate() {
        if (state !is State.Ready || closed) return
        replacePending(
            try {
                engine.createWallet()
            } catch (_: Throwable) {
                NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
            },
        )
    }

    fun submitRestorePhrase(recoveryPhrase: CharArray) {
        val restoringRecovery = state is State.RecoveryRequired
        if ((state !is State.Ready && !restoringRecovery) || closed) {
            recoveryPhrase.fill('\u0000')
            return
        }
        val result = try {
            engine.restoreWallet(recoveryPhrase)
        } catch (_: Throwable) {
            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
        } finally {
            recoveryPhrase.fill('\u0000')
        }
        if (restoringRecovery && result is NativeWalletResult.Success) {
            val expected = recoveryExpectedAddress
            if (expected == null || !ethereumAddressesEqual(expected, result.value.publicAddress)) {
                discardPendingWallet(result.value)
                result.value.close()
                transition(
                    State.RecoveryRequired(
                        expected ?: "",
                        "RECOVERY_ADDRESS_MISMATCH",
                    ),
                )
                return
            }
        }
        if (restoringRecovery && result is NativeWalletResult.Failure) {
            transition(
                State.RecoveryRequired(
                    recoveryExpectedAddress ?: "",
                    result.reason.name,
                ),
            )
            return
        }
        replacePending(result)
    }

    private fun replacePending(result: NativeWalletResult<PendingNativeWallet>) {
        when (result) {
            is NativeWalletResult.Failure -> transition(State.Failed(result.reason.name))
            is NativeWalletResult.Success -> {
                if (!ADDRESS.matches(result.value.publicAddress) ||
                    result.value.recoveryPhrase.wordCount !in setOf(12, 15, 18, 21, 24)
                ) {
                    result.value.close()
                    transition(State.Failed("INVALID_WALLET_MATERIAL"))
                    return
                }
                cancelSensitiveState()
                pendingWallet = result.value
                transition(
                    State.BackupDisplay(
                        result.value.publicAddress,
                        result.value.recoveryPhrase.wordCount,
                        revealOnly = false,
                    ),
                )
            }
        }
    }

    fun copyPhraseForDisplay(): SensitiveChars? = when (state) {
        is State.BackupDisplay -> pendingWallet?.recoveryPhrase?.copyForNativeDisplay()
            ?: revealedPhrase?.copyForNativeDisplay()
        else -> null
    }

    fun beginBackupConfirmation() {
        val display = state as? State.BackupDisplay ?: return
        val phrase = pendingWallet?.recoveryPhrase ?: revealedPhrase ?: return
        transition(
            State.BackupConfirmation(
                display.address,
                challengeIndexes(phrase.wordCount),
                display.revealOnly,
            ),
        )
    }

    fun confirmBackupWords(answers: Map<Int, CharArray>) {
        val confirmation = state as? State.BackupConfirmation
        val phrase = pendingWallet?.recoveryPhrase ?: revealedPhrase
        val matched = confirmation != null && phrase != null &&
            confirmation.wordIndexes.all { index ->
                answers[index]?.let { phrase.matchesWord(index, it) } == true
            }
        answers.values.forEach { it.fill('\u0000') }
        if (!matched || confirmation == null) {
            cancelSensitiveState()
            val expectedRecovery = recoveryExpectedAddress
            if (expectedRecovery != null) {
                transition(State.RecoveryRequired(expectedRecovery, "BACKUP_CONFIRMATION_FAILED"))
            } else {
                transition(State.Failed("BACKUP_CONFIRMATION_FAILED"))
            }
            return
        }
        if (confirmation.revealOnly) {
            revealedPhrase?.close()
            revealedPhrase = null
            activeAddress?.let { transition(State.Active(it)) } ?: transition(State.Failed("NO_ACTIVE_WALLET"))
            return
        }
        val wallet = pendingWallet ?: return
        val secret = wallet.takeSecret() ?: run {
            transition(State.Failed("INVALID_WALLET_MATERIAL"))
            cancelSensitiveState()
            return
        }
        val generation = nextOperation()
        transition(State.Authorizing(Purpose.ACTIVATE_WALLET))
        try {
            custody.wrapAndStore(wallet.publicAddress, secret) { result ->
                if (!owns(generation, Purpose.ACTIVATE_WALLET)) return@wrapAndStore
                when (result) {
                    is EthereumCustodyResult.Failure -> failCustody(result.reason)
                    is EthereumCustodyResult.Success -> activatePendingWallet(wallet)
                }
            }
        } catch (_: Throwable) {
            secret.close()
            if (owns(generation, Purpose.ACTIVATE_WALLET)) failCustody(EthereumCustodyFailure.OPERATION_FAILED)
        }
    }

    private fun activatePendingWallet(wallet: PendingNativeWallet) {
        val expectedRecovery = recoveryExpectedAddress
        val activation = try {
            if (expectedRecovery == null) {
                engine.activateWallet(wallet.activationHandle)
            } else {
                engine.recoverWallet(wallet.activationHandle, expectedRecovery)
            }
        } catch (_: Throwable) {
            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
        }
        when (val result = activation) {
            is NativeWalletResult.Failure -> {
                if (expectedRecovery != null) {
                    transition(State.RecoveryRequired(expectedRecovery, result.reason.name))
                } else {
                    transition(State.Failed(result.reason.name))
                }
            }
            is NativeWalletResult.Success -> {
                if (!ethereumAddressesEqual(result.value, wallet.publicAddress)) {
                    if (expectedRecovery != null) {
                        transition(State.RecoveryRequired(expectedRecovery, "RECOVERED_ADDRESS_MISMATCH"))
                    } else {
                        transition(State.Failed("ACTIVATED_ADDRESS_MISMATCH"))
                    }
                } else {
                    activeAddress = result.value
                    recoveryExpectedAddress = null
                    transition(State.Active(result.value))
                }
            }
        }
        pendingWallet?.close()
        discardPendingWallet(wallet)
        pendingWallet = null
    }

    fun markExistingWalletActive(address: String) {
        if (state !is State.Ready || closed || !ADDRESS.matches(address)) return
        recoveryExpectedAddress = null
        activeAddress = address
        transition(State.Active(address))
    }

    fun beginRevealBackup() {
        if (state !is State.Active || closed) return
        val generation = nextOperation()
        transition(State.Authorizing(Purpose.REVEAL_BACKUP))
        try {
            custody.authorizeAndLoad(activeAddress ?: "") { result ->
                if (!owns(generation, Purpose.REVEAL_BACKUP)) {
                    closeCustodyResult(result)
                    return@authorizeAndLoad
                }
                when (result) {
                    is EthereumCustodyResult.Failure -> failCustody(result.reason)
                    is EthereumCustodyResult.Success -> {
                        val reveal = try {
                            engine.revealRecoveryPhrase(result.value)
                        } catch (_: Throwable) {
                            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
                        } finally {
                            result.value.close()
                        }
                        when (reveal) {
                            is NativeWalletResult.Failure -> transition(State.Failed(reveal.reason.name))
                            is NativeWalletResult.Success -> {
                                revealedPhrase?.close()
                                revealedPhrase = reveal.value
                                transition(
                                    State.BackupDisplay(
                                        activeAddress ?: "",
                                        reveal.value.wordCount,
                                        revealOnly = true,
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            if (owns(generation, Purpose.REVEAL_BACKUP)) failCustody(EthereumCustodyFailure.OPERATION_FAILED)
        }
    }

    fun beginTransferReview(candidate: ExactSepoliaTransferReview) {
        val active = state as? State.Active
        if (active == null || closed || !candidate.isStillBound() ||
            !ethereumAddressesEqual(active.address, candidate.sender) ||
            candidate.expiresAtEpochMillis <= clockMillis()
        ) {
            candidate.close()
            return
        }
        review?.close()
        review = candidate
        transition(State.Reviewing(candidate))
    }

    fun beginClearSignedReview(candidate: ExactClearSignedReview) {
        val active = state as? State.Active
        if (active == null || closed || !candidate.isStillBound() ||
            !ethereumAddressesEqual(active.address, candidate.sender) ||
            candidate.expiresAtEpochMillis <= clockMillis()
        ) {
            candidate.close()
            return
        }
        review?.close()
        review = null
        clearSignReview?.close()
        clearSignReview = candidate
        transition(State.ClearSigningReviewing(candidate))
    }

    fun approveClearSignedOperation() {
        val reviewing = state as? State.ClearSigningReviewing ?: return
        val lockedReview = clearSignReview ?: return
        if (reviewing.review !== lockedReview || !lockedReview.isStillBound() ||
            lockedReview.expiresAtEpochMillis <= clockMillis()
        ) {
            cancelToActive()
            return
        }
        val generation = nextOperation()
        transition(State.Authorizing(Purpose.SIGN_CLEAR_SIGNED))
        try {
            custody.authorizeAndLoad(activeAddress ?: "") { result ->
                if (!owns(generation, Purpose.SIGN_CLEAR_SIGNED)) {
                    closeCustodyResult(result)
                    return@authorizeAndLoad
                }
                when (result) {
                    is EthereumCustodyResult.Failure -> failCustody(result.reason)
                    is EthereumCustodyResult.Success -> {
                        if (!lockedReview.isStillBound() ||
                            lockedReview.expiresAtEpochMillis <= clockMillis()
                        ) {
                            result.value.close()
                            cancelToActive()
                            return@authorizeAndLoad
                        }
                        val signed = try {
                            engine.signClearSignedOperation(lockedReview, result.value)
                        } catch (_: Throwable) {
                            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
                        } finally {
                            result.value.close()
                        }
                        when (signed) {
                            is NativeWalletResult.Failure ->
                                transition(State.Failed(signed.reason.name))
                            is NativeWalletResult.Success -> {
                                if (TRANSACTION_HASH.matches(signed.value)) {
                                    transition(State.Signed(signed.value))
                                } else {
                                    transition(State.Failed("INVALID_TRANSACTION_HASH"))
                                }
                            }
                        }
                        lockedReview.close()
                        clearSignReview = null
                    }
                }
            }
        } catch (_: Throwable) {
            if (owns(generation, Purpose.SIGN_CLEAR_SIGNED)) {
                failCustody(EthereumCustodyFailure.OPERATION_FAILED)
            }
        }
    }

    fun approveTransfer() {
        val reviewing = state as? State.Reviewing ?: return
        val lockedReview = review ?: return
        if (reviewing.review !== lockedReview || !lockedReview.isStillBound() ||
            lockedReview.expiresAtEpochMillis <= clockMillis()
        ) {
            cancelToActive()
            return
        }
        val generation = nextOperation()
        transition(State.Authorizing(Purpose.SIGN_TRANSFER))
        try {
            custody.authorizeAndLoad(activeAddress ?: "") { result ->
                if (!owns(generation, Purpose.SIGN_TRANSFER)) {
                    closeCustodyResult(result)
                    return@authorizeAndLoad
                }
                when (result) {
                    is EthereumCustodyResult.Failure -> failCustody(result.reason)
                    is EthereumCustodyResult.Success -> {
                        if (!lockedReview.isStillBound() || lockedReview.expiresAtEpochMillis <= clockMillis()) {
                            result.value.close()
                            cancelToActive()
                            return@authorizeAndLoad
                        }
                        val signed = try {
                            engine.signExactTransfer(lockedReview, result.value)
                        } catch (_: Throwable) {
                            NativeWalletResult.Failure(NativeWalletFailure.OPERATION_FAILED)
                        } finally {
                            result.value.close()
                        }
                        when (signed) {
                            is NativeWalletResult.Failure -> transition(State.Failed(signed.reason.name))
                            is NativeWalletResult.Success -> {
                                if (TRANSACTION_HASH.matches(signed.value)) {
                                    transition(State.Signed(signed.value))
                                } else {
                                    transition(State.Failed("INVALID_TRANSACTION_HASH"))
                                }
                            }
                        }
                        lockedReview.close()
                        review = null
                    }
                }
            }
        } catch (_: Throwable) {
            if (owns(generation, Purpose.SIGN_TRANSFER)) failCustody(EthereumCustodyFailure.OPERATION_FAILED)
        }
    }

    fun cancel() {
        if (closed) return
        nextOperation()
        cancelSensitiveState()
        transitionToRestingState()
    }

    /** Activity backgrounding, rotation, or destruction is a terminal cancellation barrier. */
    override fun close() {
        if (closed) return
        closed = true
        nextOperation()
        cancelSensitiveState()
        custody.close()
        transition(State.Unavailable("Native wallet session closed"))
    }

    private fun failCustody(reason: EthereumCustodyFailure) {
        if (reason == EthereumCustodyFailure.KEY_INVALIDATED_RECOVERY_REQUIRED ||
            reason == EthereumCustodyFailure.INVALID_ENVELOPE
        ) {
            val expected = activeAddress ?: recoveryExpectedAddress
            cancelSensitiveState()
            activeAddress = null
            if (expected == null) {
                transition(State.Failed(reason.name))
            } else {
                recoveryExpectedAddress = expected
                transition(State.RecoveryRequired(expected, reason.name))
            }
        } else {
            cancelSensitiveState()
            if (recoveryExpectedAddress != null) {
                transition(State.RecoveryRequired(recoveryExpectedAddress!!, reason.name))
            } else {
                activeAddress?.let { transition(State.Active(it)) }
                    ?: transition(State.Failed(reason.name))
            }
        }
    }

    private fun cancelToActive() {
        nextOperation()
        review?.close()
        review = null
        clearSignReview?.close()
        clearSignReview = null
        transitionToRestingState()
    }

    private fun cancelSensitiveState() {
        pendingWallet?.let(::discardPendingWallet)
        pendingWallet?.close()
        pendingWallet = null
        revealedPhrase?.close()
        revealedPhrase = null
        review?.close()
        review = null
        clearSignReview?.close()
        clearSignReview = null
    }

    private fun discardPendingWallet(wallet: PendingNativeWallet) {
        try {
            engine.discardPendingWallet(wallet.activationHandle)
        } catch (_: Throwable) {
            // Cleanup remains fail-closed even if the native engine is gone.
        }
    }

    private fun nextOperation(): Long = ++operationGeneration

    private fun transitionToRestingState() {
        val expectedRecovery = recoveryExpectedAddress
        when {
            expectedRecovery != null ->
                transition(State.RecoveryRequired(expectedRecovery, "RECOVERY_REQUIRED"))
            activeAddress != null -> transition(State.Active(activeAddress!!))
            else -> transition(State.Ready)
        }
    }

    private fun owns(generation: Long, purpose: Purpose): Boolean =
        !closed && generation == operationGeneration && (state as? State.Authorizing)?.purpose == purpose

    private fun transition(next: State) {
        state = next
        observer(next)
    }

    private fun closeCustodyResult(result: EthereumCustodyResult<*>) {
        (result as? EthereumCustodyResult.Success<*>)?.value.let { value ->
            if (value is AutoCloseable) value.close()
        }
    }

    private fun challengeIndexes(wordCount: Int): List<Int> = listOf(1, (wordCount + 1) / 2, wordCount).distinct()

    companion object {
        private val ADDRESS = Regex("^0x[0-9a-fA-F]{40}$")
        private val TRANSACTION_HASH = Regex("^0x[0-9a-fA-F]{64}$")
    }
}
