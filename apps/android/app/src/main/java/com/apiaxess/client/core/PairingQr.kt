package com.apiaxess.client.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The payload the workbench QR encodes (Phase C5): where to connect, the one-time
 * pairing token, and the CA SHA-256 fingerprint to pin. One scan fully configures
 * the client.
 */
@Serializable
private data class PairingQrPayload(
    val host: String = WorkbenchConfig.DEFAULT_HOST,
    val controlPort: Int = WorkbenchConfig.DEFAULT_CONTROL_PORT,
    val proxyPort: Int = WorkbenchConfig.DEFAULT_PROXY_PORT,
    val pairingToken: String = "",
    val caFingerprintSha256: String = "",
    val expiresAtMs: Long = 0,
)

object PairingQr {
    private val json = Json { ignoreUnknownKeys = true }

    /** Parses a scanned QR string into a [WorkbenchConfig], or null if invalid. */
    fun parse(raw: String): WorkbenchConfig? {
        val payload = try {
            json.decodeFromString(PairingQrPayload.serializer(), raw)
        } catch (error: Exception) {
            return null
        }
        if (payload.pairingToken.isBlank() || payload.caFingerprintSha256.isBlank()) {
            return null
        }
        return WorkbenchConfig(
            controlHost = payload.host,
            controlPort = payload.controlPort,
            proxyHost = payload.host,
            proxyPort = payload.proxyPort,
            pairingToken = payload.pairingToken,
            caFingerprint = payload.caFingerprintSha256,
        )
    }
}
