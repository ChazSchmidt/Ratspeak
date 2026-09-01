package org.ratspeak.android.ethereum

import android.content.ContentResolver
import android.net.Uri
import java.io.InputStream
import java.util.concurrent.Future
import java.util.concurrent.FutureTask
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One process-wide reservation shared by checkpoint and gateway pickers. */
internal object EthereumDocumentReadCoordinator {
    internal enum class Kind { CHECKPOINT, GATEWAY }

    private data class Reservation(val kind: Kind, val token: String)
    private var active: Reservation? = null

    @Synchronized
    internal fun reserve(kind: Kind, token: String): Boolean {
        if (active != null || EthereumDocumentReadExecutor.isBusy()) return false
        active = Reservation(kind, token)
        return true
    }

    @Synchronized
    internal fun release(kind: Kind, token: String): Boolean {
        if (active != Reservation(kind, token)) return false
        active = null
        return true
    }
}

/**
 * Process-owned bounded reader for Android document-provider streams.
 *
 * A provider is outside the application process and may ignore interruption
 * or block before returning a stream.  There is one slot and no queue, so a
 * timed-out provider cannot make every subsequent picker result allocate a
 * new thread.  Callers retain ownership of the returned bytes and must wipe
 * them after their native handoff.
 */
internal object EthereumDocumentReadExecutor {
    private class Session(val token: String) {
        @Volatile var cancelled = false
        @Volatile var started = false
        var input: InputStream? = null
        var future: Future<*>? = null
    }

    private val executor = ThreadPoolExecutor(
        0,
        1,
        30L,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        { runnable ->
            Thread(runnable, "ratspeak-ethereum-document-reader").apply {
                isDaemon = true
            }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private var active: Session? = null

    @Synchronized
    internal fun isBusy(): Boolean = active != null

    /** Builds an unstarted session for deterministic cancellation tests. */
    internal fun reserveUnstartedForTest(token: String): Boolean = synchronized(this) {
        if (active != null) return@synchronized false
        active = Session(token).also { it.future = FutureTask<Unit> {} }
        true
    }

    @Synchronized
    internal fun submit(
        token: String,
        resolver: ContentResolver,
        uri: Uri,
        readBounded: (InputStream) -> ByteArray?,
        onSuccess: (ByteArray?) -> Unit,
        onFailure: () -> Unit,
    ): Boolean {
        if (active != null) return false
        val session = Session(token)
        active = session
        return try {
            session.future = executor.submit {
                run(session, resolver, uri, readBounded, onSuccess, onFailure)
            }
            true
        } catch (_: Throwable) {
            if (active === session) active = null
            false
        }
    }

    internal fun cancel(token: String): Boolean {
        val (session, future, neverStarted) = synchronized(this) {
            val session = active?.takeIf { it.token == token } ?: return false
            session.cancelled = true
            Triple(session, session.future, !session.started)
        }
        try { session.input?.close() } catch (_: Throwable) { }
        future?.cancel(true)
        if (neverStarted) {
            // A Future cancelled before its callable starts never reaches
            // run/finally. Release only that exact session; a running session
            // keeps the slot until its provider call actually returns.
            synchronized(this) {
                if (active === session && !session.started) active = null
            }
        }
        return true
    }

    private fun run(
        session: Session,
        resolver: ContentResolver,
        uri: Uri,
        readBounded: (InputStream) -> ByteArray?,
        onSuccess: (ByteArray?) -> Unit,
        onFailure: () -> Unit,
    ) {
        var bytes: ByteArray? = null
        try {
            synchronized(this) {
                if (active !== session || session.cancelled) return
                session.started = true
            }
            val input = resolver.openInputStream(uri)
            synchronized(this) {
                if (active !== session || session.cancelled) {
                    try { input?.close() } catch (_: Throwable) { }
                    return
                }
                session.input = input
            }
            bytes = input?.use(readBounded)
            if (session.cancelled) return
            onSuccess(bytes)
            bytes = null
        } catch (_: Throwable) {
            if (!session.cancelled) onFailure()
        } finally {
            bytes?.fill(0)
            synchronized(this) {
                if (active === session) active = null
                session.input = null
            }
        }
    }
}
