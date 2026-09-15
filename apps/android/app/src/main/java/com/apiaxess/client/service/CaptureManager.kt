package com.apiaxess.client.service

import android.content.Context
import com.apiaxess.client.capture.CaptureController
import com.apiaxess.client.capture.CaptureState
import com.apiaxess.client.capture.CaptureTarget
import com.apiaxess.client.core.WorkbenchConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.StateFlow

/**
 * Process-wide owner of the single capture session, so the UI and the foreground
 * service observe one source of truth. The [CaptureService] drives start/stop
 * (to guarantee a foreground context + wakelock); the UI only reads [state].
 */
object CaptureManager {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var controller: CaptureController? = null

    val state: StateFlow<CaptureState>
        get() = requireNotNull(controller) { "CaptureManager not initialised" }.state

    fun ensureInitialised(context: Context) {
        if (controller == null) {
            controller = CaptureController(context.applicationContext, scope)
        }
    }

    fun start(context: Context, config: WorkbenchConfig, target: CaptureTarget) {
        ensureInitialised(context)
        controller?.start(config, target)
    }

    fun stop() {
        controller?.stop()
    }

    fun isInitialised(): Boolean = controller != null
}
