package com.apiaxess.client.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.apiaxess.client.core.PairingQr
import com.apiaxess.client.core.WorkbenchConfig
import com.apiaxess.client.ui.theme.ErrorRed
import com.apiaxess.client.ui.theme.Muted
import com.apiaxess.client.ui.theme.OnSurface
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/** Hoisted form state so entries survive stepping to the app picker and back. */
class ConnectState {
    var autoDetect by mutableStateOf(true)
    var host by mutableStateOf(WorkbenchConfig.DEFAULT_HOST)
    var controlPort by mutableStateOf(WorkbenchConfig.DEFAULT_CONTROL_PORT.toString())
    var proxyPort by mutableStateOf(WorkbenchConfig.DEFAULT_PROXY_PORT.toString())
    var pairingToken by mutableStateOf("")

    fun toConfig(): WorkbenchConfig {
        val effectiveHost = if (autoDetect) WorkbenchConfig.DEFAULT_HOST else host.trim()
        return WorkbenchConfig(
            controlHost = effectiveHost,
            controlPort = controlPort.toIntOrNull() ?: WorkbenchConfig.DEFAULT_CONTROL_PORT,
            proxyHost = effectiveHost,
            proxyPort = proxyPort.toIntOrNull() ?: WorkbenchConfig.DEFAULT_PROXY_PORT,
            pairingToken = pairingToken.trim(),
        )
    }
}

@Composable
fun ConnectScreen(
    state: ConnectState,
    onContinue: (WorkbenchConfig) -> Unit,
) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(scroll)
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        BrandLockup()
        Text(
            "Per-app HTTPS capture, straight to your workbench.",
            color = Muted,
        )

        // QR is the primary "connect without typing" path; manual is the fallback.
        var qrError by remember { mutableStateOf<String?>(null) }
        val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
            val contents = result.contents
            when {
                contents == null -> Unit // scan cancelled
                else -> {
                    val config = PairingQr.parse(contents)
                    if (config != null) {
                        qrError = null
                        onContinue(config)
                    } else {
                        qrError = "That QR is not an APIaxess pairing code. Scan the one on the workbench's Pair a device screen."
                    }
                }
            }
        }
        SectionLabel("Pair by QR (recommended)")
        Button(
            onClick = {
                scanLauncher.launch(
                    ScanOptions()
                        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        .setOrientationLocked(false)
                        .setBeepEnabled(false)
                        .setPrompt("Scan the workbench pairing QR"),
                )
            },
            colors = ButtonDefaults.buttonColors(containerColor = InteractiveAccent),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text("Scan pairing QR")
        }
        Text(
            "One scan configures the connection, carries a one-time token, and pins " +
                "the workbench CA. Or enter the details manually below.",
            color = Muted,
        )
        qrError?.let { Text(it, color = ErrorRed) }

        SectionLabel("Rooted device required")
        Text(
            "This app needs root: it installs a per-app traffic redirect and reads the " +
                "redirected connections. When you pair, the workbench installs its " +
                "certificate on this device so HTTPS can be decrypted.",
            color = OnSurface,
        )

        SectionLabel("Workbench connection")
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text("Auto-detect (adb / USB)", color = OnSurface)
                Text(
                    "Use the adb-reverse tunnel on 127.0.0.1",
                    color = Muted,
                )
            }
            Switch(checked = state.autoDetect, onCheckedChange = { state.autoDetect = it })
        }

        if (!state.autoDetect) {
            OutlinedTextField(
                value = state.host,
                onValueChange = { state.host = it },
                label = { Text("Workbench host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value = state.controlPort,
                onValueChange = { state.controlPort = it.filter(Char::isDigit) },
                label = { Text("Control port") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
            OutlinedTextField(
                value = state.proxyPort,
                onValueChange = { state.proxyPort = it.filter(Char::isDigit) },
                label = { Text("Proxy port") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
        }

        SectionLabel("Pairing token")
        OutlinedTextField(
            value = state.pairingToken,
            onValueChange = { state.pairingToken = it },
            label = { Text("One-time pairing token from the workbench") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "Only needed for manual pairing — generate it on the workbench and paste it " +
                "here. Scanning the QR above fills this in for you.",
            color = Muted,
        )

        Spacer(Modifier.height(4.dp))
        Button(
            onClick = { onContinue(state.toConfig()) },
            enabled = state.toConfig().isUsable(),
            colors = ButtonDefaults.buttonColors(containerColor = InteractiveAccent),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text("Choose an app")
        }
    }
}
