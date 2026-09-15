package com.apiaxess.client.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.apiaxess.client.capture.CaptureState
import com.apiaxess.client.core.ClientDiagnostic
import com.apiaxess.client.ui.theme.AccentGreen
import com.apiaxess.client.ui.theme.ErrorRed
import com.apiaxess.client.ui.theme.Muted
import com.apiaxess.client.ui.theme.OnSurface
import com.apiaxess.client.ui.theme.SurfaceElevated

@Composable
fun StatusScreen(
    state: CaptureState,
    onStop: () -> Unit,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        BrandLockup()

        when (state) {
            is CaptureState.Capturing -> CapturingBody(state)
            is CaptureState.Preparing -> Pending("Connecting", state.step)
            is CaptureState.Reconnecting ->
                Pending("Reconnecting", "Attempt ${state.attempt} · ${state.detail}")
            is CaptureState.Failed -> DiagnosticBody(state.diagnostic)
            is CaptureState.Stopped -> Pending("Stopped", "Capture ended and this device's redirect was removed.")
            is CaptureState.Idle -> Pending("Idle", "Not capturing yet.")
        }

        Spacer(Modifier.weight(1f))

        // Active states can be stopped; terminal/idle states offer a restart.
        val isActive = state is CaptureState.Capturing ||
            state is CaptureState.Preparing ||
            state is CaptureState.Reconnecting
        if (isActive) {
            OutlinedButton(
                onClick = onStop,
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Stop capture") }
        } else {
            Button(
                onClick = onRetry,
                colors = ButtonDefaults.buttonColors(containerColor = InteractiveAccent),
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Start over") }
        }
    }
}

@Composable
private fun CapturingBody(state: CaptureState.Capturing) {
    StatusPill("Capturing", AccentGreen)
    Card {
        DetailRow("App", state.target.label)
        DetailRow("Package", state.target.packageName)
        DetailRow("UID", state.target.uid.toString())
        DetailRow("Active flows", state.activeConnections.toString())
        DetailRow("Total flows", state.totalConnections.toString())
    }
    Text(
        "Only ${state.target.label}'s traffic is redirected — nothing else on the device. " +
            "Its HTTPS is decrypted at the workbench and appears there.",
        color = Muted,
    )
    SectionLabel("Good to know")
    Text(
        "QUIC / HTTP-3 is blocked so apps fall back to interceptable HTTPS. " +
            "Certificate-pinned apps only decrypt when the workbench's pinning bypass " +
            "succeeds. Some apps may still resist capture: Flutter or other natively-pinned " +
            "apps, WebView / Chromium-based apps (their in-app browser doesn't trust the " +
            "workbench certificate the way normal apps do), and apps with anti-tampering checks.",
        color = Muted,
    )
}

@Composable
private fun Pending(title: String, detail: String) {
    StatusPill(title, InteractiveAccent)
    Text(detail, color = OnSurface)
}

@Composable
private fun DiagnosticBody(diagnostic: ClientDiagnostic) {
    // A declined/expired pairing is a normal outcome the user can retry (neutral
    // accent); a fingerprint mismatch is a security stop and everything else is a
    // genuine failure (both red).
    val (label, color) = when (diagnostic.id) {
        "client.operator-declined" -> "Declined" to InteractiveAccent
        "client.pairing-expired" -> "Pairing expired" to InteractiveAccent
        "client.fingerprint-mismatch" -> "Security warning" to ErrorRed
        else -> "Can't capture" to ErrorRed
    }
    StatusPill(label, color)
    Card {
        Text(diagnostic.what, color = OnSurface)
        Spacer(Modifier.height(12.dp))
        SectionLabel("Why")
        Text(diagnostic.why, color = Muted)
        Spacer(Modifier.height(10.dp))
        SectionLabel("Fix")
        Text(diagnostic.fix, color = OnSurface)
    }
}

@Composable
private fun Card(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(SurfaceElevated)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
        content = { content() },
    )
}
