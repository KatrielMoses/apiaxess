package com.apiaxess.client.ui

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import com.apiaxess.client.capture.CaptureState
import com.apiaxess.client.capture.CaptureTarget
import com.apiaxess.client.core.WorkbenchConfig
import com.apiaxess.client.service.CaptureManager
import com.apiaxess.client.service.CaptureService
import com.apiaxess.client.ui.theme.Ink

private enum class Screen { Connect, Pick, Status }

@Composable
fun ClientApp() {
    val context = LocalContext.current
    remember { CaptureManager.ensureInitialised(context) }
    val captureState by CaptureManager.state.collectAsState()

    var screen by remember { mutableStateOf(Screen.Connect) }
    val connectState = remember { ConnectState() }
    var pendingConfig by remember { mutableStateOf<WorkbenchConfig?>(null) }

    // Post-notifications is required for the foreground capture notification.
    val notifications = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        // Resume into the status view if a session is already live.
        if (captureState !is CaptureState.Idle && captureState !is CaptureState.Stopped) {
            screen = Screen.Status
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Ink) {
        when (screen) {
            Screen.Connect -> ConnectScreen(connectState) { config ->
                pendingConfig = config
                screen = Screen.Pick
            }

            Screen.Pick -> AppPickerScreen { app ->
                val config = pendingConfig ?: return@AppPickerScreen
                val target = CaptureTarget(app.packageName, app.label, app.uid)
                ContextCompat.startForegroundService(
                    context,
                    CaptureService.startIntent(context, config, target),
                )
                screen = Screen.Status
            }

            Screen.Status -> StatusScreen(
                state = captureState,
                onStop = {
                    context.startService(CaptureService.stopIntent(context))
                    screen = Screen.Connect
                },
                onRetry = {
                    context.startService(CaptureService.stopIntent(context))
                    screen = Screen.Connect
                },
            )
        }
    }
}
