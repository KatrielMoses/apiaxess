package com.apiaxess.client.core

/**
 * Where the workbench is reachable from the device and how this client relays to
 * it. Over an adb-reverse tunnel (Phase C2) the device's own loopback ports map
 * onto the workbench's loopback, so the defaults below are the workbench defaults
 * seen through that tunnel:
 *
 *  - control/API + device control WebSocket: `127.0.0.1:7777` (local-api)
 *  - MITM proxy the relay issues `CONNECT` to:  `127.0.0.1:8080` (workbench proxy)
 *
 * `auto-detect` in the UI simply keeps these adb-tunnel defaults; QR/LAN discovery
 * is Phase C5.
 */
data class WorkbenchConfig(
    val controlHost: String = DEFAULT_HOST,
    val controlPort: Int = DEFAULT_CONTROL_PORT,
    val proxyHost: String = DEFAULT_HOST,
    val proxyPort: Int = DEFAULT_PROXY_PORT,
    /**
     * The one-time pairing token minted by the workbench (Phase C1). C3 accepts it
     * by manual entry; C5 delivers the same value via QR. Exchanged once for a
     * per-session bearer token.
     */
    val pairingToken: String = "",
    /**
     * The workbench CA's SHA-256 fingerprint carried by the QR (Phase C5). When
     * present the client pins it before pairing; manual entry leaves it null.
     */
    val caFingerprint: String? = null,
) {
    val controlBaseUrl: String get() = "http://$controlHost:$controlPort"
    val deviceControlWsUrl: String
        get() = "ws://$controlHost:$controlPort/api/v1/workbench/ws/device/control"
    val pairingExchangeUrl: String
        get() = "$controlBaseUrl/api/v1/pairing/exchange"
    val pairingCaUrl: String
        get() = "$controlBaseUrl/api/v1/pairing/ca"

    fun pairingPollUrl(requestId: String): String = "$pairingExchangeUrl/$requestId"

    fun isUsable(): Boolean =
        controlHost.isNotBlank() &&
            controlPort in 1..65535 &&
            proxyPort in 1..65535 &&
            pairingToken.isNotBlank()

    companion object {
        const val DEFAULT_HOST = "127.0.0.1"
        const val DEFAULT_CONTROL_PORT = 7777
        const val DEFAULT_PROXY_PORT = 8080

        /** Loopback port the on-device relay listens on for redirected traffic. */
        const val RELAY_PORT = 28080
    }
}
