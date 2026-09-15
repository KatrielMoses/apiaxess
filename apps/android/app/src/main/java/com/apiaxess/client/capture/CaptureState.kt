package com.apiaxess.client.capture

import com.apiaxess.client.core.ClientDiagnostic

/** The app chosen for per-app capture. */
data class CaptureTarget(
    val packageName: String,
    val label: String,
    val uid: Int,
)

/** Observable capture state for the UI and the foreground notification. */
sealed interface CaptureState {
    data object Idle : CaptureState

    data class Preparing(val step: String) : CaptureState

    data class Capturing(
        val target: CaptureTarget,
        val activeConnections: Long,
        val totalConnections: Long,
    ) : CaptureState

    data class Reconnecting(val attempt: Int, val detail: String) : CaptureState

    data class Failed(val diagnostic: ClientDiagnostic) : CaptureState

    data object Stopped : CaptureState
}
