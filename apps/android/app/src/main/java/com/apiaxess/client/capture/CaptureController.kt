package com.apiaxess.client.capture

import android.content.Context
import android.os.Build
import com.apiaxess.client.control.ControlEvent
import com.apiaxess.client.control.ControlException
import com.apiaxess.client.control.PairingPoll
import com.apiaxess.client.control.SessionToken
import com.apiaxess.client.control.WorkbenchClient
import com.apiaxess.client.core.ClientDiagnostic
import com.apiaxess.client.core.WorkbenchConfig
import com.apiaxess.client.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicLong

/**
 * Orchestrates one per-app capture session end to end and keeps it alive:
 * root check → resolve UID → exchange pairing token → start relay → install the
 * per-app iptables redirect + QUIC block → hold the token-auth'd control channel
 * open, reconnecting with exponential backoff and re-applying the redirect on
 * network change.
 *
 * The traffic path (relay → tunnelled proxy) is independent of the control
 * channel, so a control blip never drops in-flight capture — over adb it is
 * effectively seamless.
 */
class CaptureController(
    private val context: Context,
    private val scope: CoroutineScope,
) : RelayListener {

    private val _state = MutableStateFlow<CaptureState>(CaptureState.Idle)
    val state: StateFlow<CaptureState> = _state.asStateFlow()

    private val totalConnections = AtomicLong(0)

    private var config: WorkbenchConfig? = null
    private var target: CaptureTarget? = null
    private var sessionToken: SessionToken? = null

    private val redirector = IptablesRedirector()
    private var relay: Relay? = null
    private var workbench: WorkbenchClient? = null
    private var networkMonitor: NetworkMonitor? = null

    private var controlJob: Job? = null
    private var keepAliveJob: Job? = null
    private var running = false

    /** Begins capture for [target] against [config]. Idempotent while running. */
    fun start(config: WorkbenchConfig, target: CaptureTarget) {
        if (running) return
        running = true
        this.config = config
        this.target = target
        scope.launch { bringUp() }
    }

    private suspend fun bringUp() {
        emit(CaptureState.Preparing("Checking root"))
        if (!withContext(Dispatchers.IO) { RootShell.isRootAvailable() }) {
            return fail(ClientDiagnostic.rootUnavailable("`su` did not return uid=0"))
        }
        val target = this.target ?: return
        val config = this.config ?: return

        val client = WorkbenchClient(config).also { workbench = it }

        // Pin the workbench: verify the served CA matches the QR's fingerprint
        // before presenting the token (a manual-entry config skips this).
        emit(CaptureState.Preparing("Verifying the workbench"))
        withContext(Dispatchers.IO) { client.verifyCaFingerprint() }.getOrElse { error ->
            return fail((error as? ControlException)?.diagnostic
                ?: ClientDiagnostic.fingerprintMismatch(error.message ?: "verification failed"))
        }

        // Present the pairing token and wait for the operator's accept/decline.
        emit(CaptureState.Preparing("Requesting to connect"))
        val requestId = withContext(Dispatchers.IO) {
            client.requestPairing(deviceName())
        }.getOrElse { error ->
            return fail((error as? ControlException)?.diagnostic
                ?: ClientDiagnostic.workbenchUnreachable(error.message ?: "pairing request failed"))
        }
        val token = awaitOperatorDecision(client, requestId) ?: return
        sessionToken = token

        emit(CaptureState.Preparing("Starting the capture relay"))
        val relay = Relay(config, this).also { this.relay = it }
        try {
            withContext(Dispatchers.IO) { relay.start() }
        } catch (error: Exception) {
            return fail(ClientDiagnostic.relayFailed(error.message ?: "relay bind failed"))
        }

        emit(CaptureState.Preparing("Installing the per-app redirect"))
        val redirectError = withContext(Dispatchers.IO) { redirector.apply(target.uid) }
        if (redirectError != null) return fail(redirectError)

        // Re-establish the redirect on network change (best-effort, blip-free).
        networkMonitor = NetworkMonitor(context) {
            scope.launch(Dispatchers.IO) { if (running) redirector.apply(target.uid) }
        }.also { it.start() }

        emit(capturing())
        connectControlWithBackoff(token)
    }

    /**
     * Polls the C5 accept/decline gate until the operator decides. Returns the
     * issued session token on accept, or `null` after calling [fail] on decline,
     * expiry, or transport failure.
     */
    private suspend fun awaitOperatorDecision(
        client: WorkbenchClient,
        requestId: String,
    ): SessionToken? {
        emit(CaptureState.Preparing("Waiting for the operator to accept"))
        val deadline = System.currentTimeMillis() + ACCEPT_TIMEOUT_MS
        while (running && System.currentTimeMillis() < deadline) {
            when (val poll = withContext(Dispatchers.IO) { client.pollPairing(requestId) }) {
                is PairingPoll.Accepted -> return poll.token
                is PairingPoll.Declined -> {
                    fail(poll.diagnostic)
                    return null
                }
                is PairingPoll.Failed -> {
                    fail(poll.diagnostic)
                    return null
                }
                PairingPoll.Pending -> delay(POLL_INTERVAL_MS)
            }
        }
        fail(ClientDiagnostic.pairingExpired())
        return null
    }

    private fun deviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    private fun connectControlWithBackoff(initialToken: SessionToken) {
        controlJob?.cancel()
        controlJob = scope.launch {
            var attempt = 0
            val token = initialToken
            while (isActive && running) {
                val outcome = openControlOnce(token)
                if (outcome.reachedReady) {
                    // A live session dropped; reconnect promptly (blip-free over adb)
                    // with just a brief guard against hot-looping.
                    attempt = 0
                    delay(1_000)
                    if (running) emit(capturing())
                    continue
                }
                // Never reached ready. If the workbench actively declined the session
                // token (rejected or expired), stop rather than loop forever — the
                // one-time pairing token is already consumed, so recovery means the
                // operator re-pairing (the connection-declined diagnostic says so).
                // Otherwise the reverse tunnel is transiently down; back off and retry
                // with the same session token.
                attempt += 1
                if (outcome.diagnostic?.id == "client.connection-declined") {
                    return@launch fail(outcome.diagnostic)
                }
                val backoffMs = backoffMillis(attempt)
                if (running) emit(CaptureState.Reconnecting(attempt, "retrying in ${backoffMs / 1000}s"))
                delay(backoffMs)
                if (running) emit(capturing())
            }
        }
    }

    private data class ControlOutcome(val reachedReady: Boolean, val diagnostic: ClientDiagnostic?)

    /**
     * Opens the control channel once and suspends until it becomes ready then
     * drops, or fails to become ready. Reports whether ready was reached and the
     * close diagnostic.
     */
    private suspend fun openControlOnce(token: SessionToken): ControlOutcome {
        val client = workbench ?: return ControlOutcome(false, null)
        val closed = kotlinx.coroutines.CompletableDeferred<ClientDiagnostic?>()
        var reachedReady = false
        client.openControlChannel(token) { event ->
            when (event) {
                is ControlEvent.Ready -> {
                    if (!reachedReady) {
                        reachedReady = true
                        startKeepAlive()
                        if (running) emit(capturing())
                    }
                }
                is ControlEvent.Closed -> {
                    stopKeepAlive()
                    if (!closed.isCompleted) closed.complete(event.diagnostic)
                }
            }
        }
        val diagnostic = closed.await()
        return ControlOutcome(reachedReady, diagnostic)
    }

    private fun startKeepAlive() {
        keepAliveJob?.cancel()
        keepAliveJob = scope.launch {
            while (isActive) {
                delay(20_000)
                workbench?.keepAlive()
            }
        }
    }

    private fun stopKeepAlive() {
        keepAliveJob?.cancel()
        keepAliveJob = null
    }

    private fun capturing(): CaptureState.Capturing {
        val target = this.target!!
        val active = relay?.activeConnections?.get() ?: 0
        return CaptureState.Capturing(target, active, totalConnections.get())
    }

    /** Tears everything down and returns to a clean device state. */
    fun stop() {
        if (!running) return
        running = false
        controlJob?.cancel()
        stopKeepAlive()
        networkMonitor?.stop()
        workbench?.close()
        relay?.stop()
        target?.let { scope.launch(Dispatchers.IO) { redirector.clear(it.uid) } }
        emit(CaptureState.Stopped)
    }

    private fun fail(diagnostic: ClientDiagnostic) {
        running = false
        stopKeepAlive()
        controlJob?.cancel()
        networkMonitor?.stop()
        workbench?.close()
        relay?.stop()
        target?.let { scope.launch(Dispatchers.IO) { redirector.clear(it.uid) } }
        emit(CaptureState.Failed(diagnostic))
    }

    private fun emit(state: CaptureState) {
        _state.value = state
    }

    // RelayListener --------------------------------------------------------
    override fun onConnectionOpened(target: String) {
        totalConnections.incrementAndGet()
        if (running && _state.value is CaptureState.Capturing) emit(capturing())
    }

    override fun onConnectionError(detail: String) {
        // Per-connection errors are non-fatal (one flow failing is not a session
        // failure); they are surfaced only if the whole session is not capturing.
    }

    private companion object {
        fun backoffMillis(attempt: Int): Long {
            val capped = attempt.coerceIn(1, 6)
            return (1_000L shl (capped - 1)).coerceAtMost(30_000L)
        }

        /** How long the device waits at the accept/decline gate before giving up. */
        const val ACCEPT_TIMEOUT_MS = 3 * 60 * 1000L

        /** Poll cadence while waiting for the operator decision. */
        const val POLL_INTERVAL_MS = 1_500L
    }
}
