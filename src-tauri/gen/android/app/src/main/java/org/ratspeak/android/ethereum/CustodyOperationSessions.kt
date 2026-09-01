package org.ratspeak.android.ethereum

/**
 * Exact operation ownership for asynchronous biometric callbacks.
 *
 * A token can be claimed for terminal work once. New operations remain blocked
 * until the claimed terminal path finishes, and close prevents all later result
 * delivery. Cleanup callbacks run outside the lock.
 */
internal class CustodyOperationSessions {
    data class Token internal constructor(val value: Long)

    private enum class Phase { ACTIVE, CLAIMED }

    private data class Session(
        val token: Token,
        var phase: Phase,
        var cancel: (() -> Unit)?,
        var abandon: (() -> Unit)?,
    )

    private val lock = Any()
    private var nextToken = 1L
    private var session: Session? = null
    private var closed = false

    fun begin(abandon: () -> Unit): Token? = synchronized(lock) {
        if (closed || session != null) return@synchronized null
        val token = Token(nextToken++)
        session = Session(token, Phase.ACTIVE, null, abandon)
        token
    }

    fun attachCancellation(token: Token, cancel: () -> Unit): Boolean {
        val attached = synchronized(lock) {
            val current = session
            if (!closed && current?.token == token && current.phase == Phase.ACTIVE) {
                current.cancel = cancel
                true
            } else {
                false
            }
        }
        if (!attached) runSafely(cancel)
        return attached
    }

    /** Claims this exact token before any terminal crypto or result creation. */
    fun claim(token: Token): Boolean = synchronized(lock) {
        val current = session
        if (closed || current?.token != token || current.phase != Phase.ACTIVE) {
            false
        } else {
            current.phase = Phase.CLAIMED
            current.cancel = null
            true
        }
    }

    fun abandonClaimed(token: Token) {
        val abandon = synchronized(lock) {
            val current = session
            if (current?.token != token || current.phase != Phase.CLAIMED) return@synchronized null
            current.abandon.also { current.abandon = null }
        }
        abandon?.let(::runSafely)
    }

    /**
     * Completes the claimed token and delivers at most once. If close won the
     * race or the callback throws, `discard` owns cleanup of the result.
     */
    fun <T> finishAndDeliver(
        token: Token,
        value: T,
        discard: (T) -> Unit,
        deliver: (T) -> Unit,
    ) {
        val mayDeliver = synchronized(lock) {
            val current = session
            if (current?.token != token || current.phase != Phase.CLAIMED) {
                false
            } else {
                session = null
                !closed
            }
        }
        if (!mayDeliver) {
            runSafely { discard(value) }
            return
        }
        try {
            deliver(value)
        } catch (_: Throwable) {
            runSafely { discard(value) }
        }
    }

    /** Close is a delivery barrier and cancels/clears an unclaimed operation. */
    fun close() {
        val cleanup = synchronized(lock) {
            if (closed) return
            closed = true
            val current = session ?: return@synchronized emptyList()
            val actions = if (current.phase == Phase.ACTIVE) {
                session = null
                listOfNotNull(current.cancel, current.abandon)
            } else {
                // The terminal owner has already claimed cleanup. It will see
                // the closed barrier in finishAndDeliver and discard its result.
                emptyList()
            }
            actions
        }
        cleanup.forEach(::runSafely)
    }

    private fun runSafely(action: () -> Unit) {
        try {
            action()
        } catch (_: Throwable) {
            // Cleanup is best effort and never changes operation ownership.
        }
    }
}
