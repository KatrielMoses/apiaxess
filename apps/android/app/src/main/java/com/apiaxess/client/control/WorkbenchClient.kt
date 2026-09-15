package com.apiaxess.client.control

import com.apiaxess.client.core.ClientDiagnostic
import com.apiaxess.client.core.WorkbenchConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit

@Serializable
private data class ExchangeRequest(val pairingToken: String, val deviceName: String? = null)

@Serializable
private data class ExchangeAck(val requestId: String, val status: String = "pending")

@Serializable
private data class PollResponse(
    val status: String,
    val sessionToken: String? = null,
    val expiresAtMs: Long = 0,
)

/** A per-session bearer token issued by the workbench pairing exchange (C1). */
data class SessionToken(val value: String, val expiresAtMs: Long)

/** Lifecycle of the device control channel. */
sealed interface ControlEvent {
    data object Ready : ControlEvent
    data class Closed(val diagnostic: ClientDiagnostic) : ControlEvent
}

/** One poll of the C5 accept/decline gate. */
sealed interface PairingPoll {
    data object Pending : PairingPoll
    data class Accepted(val token: SessionToken) : PairingPoll
    data class Declined(val diagnostic: ClientDiagnostic) : PairingPoll
    data class Failed(val diagnostic: ClientDiagnostic) : PairingPoll
}

/**
 * Speaks the device pairing contract (C1 + the C5 accept/decline gate):
 *
 *  1. [verifyCaFingerprint] pins the workbench — it fetches the live session CA and
 *     checks its SHA-256 against the fingerprint the QR carried, so a rogue server
 *     cannot MITM the pairing.
 *  2. [requestPairing] presents the one-time pairing token and enters the gate.
 *  3. [pollPairing] waits for the operator's accept/decline.
 *  4. [openControlChannel] holds the token-authenticated device control WebSocket
 *     open (with keepalive) as the device's authenticated presence.
 */
class WorkbenchClient(private val config: WorkbenchConfig) {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .pingInterval(20, TimeUnit.SECONDS)
        .build()

    private var socket: WebSocket? = null

    /**
     * Pins the workbench: fetches `GET /pairing/ca` and verifies the served CA's
     * SHA-256 matches the fingerprint the QR carried. A mismatch means the endpoint
     * the device reached is not the workbench that showed the QR (pairing MITM).
     * Manual entry has no out-of-band fingerprint, so it is skipped (fallback).
     */
    fun verifyCaFingerprint(): Result<Unit> {
        val expected = config.caFingerprint?.lowercase()?.replace(":", "")
        if (expected.isNullOrBlank()) return Result.success(Unit) // manual entry: nothing to pin
        val request = Request.Builder().url(config.pairingCaUrl).get().build()
        return try {
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return Result.failure(ControlException(ClientDiagnostic.workbenchUnreachable("CA fetch HTTP ${response.code}")))
                }
                val pem = response.body?.string().orEmpty()
                val actual = sha256HexOfPem(pem)
                    ?: return Result.failure(ControlException(ClientDiagnostic.fingerprintMismatch("the served CA could not be parsed")))
                if (actual == expected) {
                    Result.success(Unit)
                } else {
                    Result.failure(ControlException(ClientDiagnostic.fingerprintMismatch("expected $expected, served $actual")))
                }
            }
        } catch (error: Exception) {
            Result.failure(ControlException(ClientDiagnostic.workbenchUnreachable(error.message ?: "CA fetch failed")))
        }
    }

    /** Presents the pairing token and enters the accept/decline gate; returns the
     *  request id the device polls. */
    fun requestPairing(deviceName: String): Result<String> {
        val body = json
            .encodeToString(
                ExchangeRequest.serializer(),
                ExchangeRequest(config.pairingToken, deviceName),
            )
            .toRequestBody(JSON_MEDIA)
        val request = Request.Builder().url(config.pairingExchangeUrl).post(body).build()
        return try {
            http.newCall(request).execute().use { response ->
                when {
                    response.isSuccessful -> {
                        val ack = json.decodeFromString(ExchangeAck.serializer(), response.body?.string().orEmpty())
                        Result.success(ack.requestId)
                    }
                    response.code == 401 || response.code == 403 ->
                        Result.failure(ControlException(ClientDiagnostic.pairingRejected("HTTP ${response.code}")))
                    else ->
                        Result.failure(ControlException(ClientDiagnostic.workbenchUnreachable("HTTP ${response.code}")))
                }
            }
        } catch (error: Exception) {
            Result.failure(ControlException(ClientDiagnostic.workbenchUnreachable(error.message ?: "pairing request failed")))
        }
    }

    /** Polls the operator's decision on a pending pairing request. */
    fun pollPairing(requestId: String): PairingPoll {
        val request = Request.Builder().url(config.pairingPollUrl(requestId)).get().build()
        return try {
            http.newCall(request).execute().use { response ->
                when (response.code) {
                    200 -> {
                        val poll = json.decodeFromString(PollResponse.serializer(), response.body?.string().orEmpty())
                        if (poll.status == "accepted" && poll.sessionToken != null) {
                            PairingPoll.Accepted(SessionToken(poll.sessionToken, poll.expiresAtMs))
                        } else {
                            PairingPoll.Pending
                        }
                    }
                    403 -> PairingPoll.Declined(ClientDiagnostic.operatorDeclined())
                    410, 404 -> PairingPoll.Failed(ClientDiagnostic.pairingExpired())
                    else -> PairingPoll.Failed(ClientDiagnostic.workbenchUnreachable("poll HTTP ${response.code}"))
                }
            }
        } catch (error: Exception) {
            PairingPoll.Failed(ClientDiagnostic.workbenchUnreachable(error.message ?: "poll failed"))
        }
    }

    /**
     * Opens the token-authenticated device control channel (the device's
     * authenticated presence + an application-level keepalive).
     */
    fun openControlChannel(token: SessionToken, onEvent: (ControlEvent) -> Unit) {
        val url = "${config.deviceControlWsUrl}?token=${token.value}"
        val request = Request.Builder().url(url).build()
        socket = http.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (text.contains("\"ready\"") || text.contains("\"pong\"")) {
                    onEvent(ControlEvent.Ready)
                }
            }

            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send(PING_MESSAGE)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val diagnostic = when (response?.code) {
                    401, 403 -> ClientDiagnostic.pairingRejected(t.message ?: "session token rejected")
                    else -> ClientDiagnostic.workbenchUnreachable(t.message ?: "control channel failed")
                }
                onEvent(ControlEvent.Closed(diagnostic))
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                onEvent(ControlEvent.Closed(ClientDiagnostic.tunnelDown("control channel closed ($code)")))
            }
        })
    }

    fun keepAlive() {
        socket?.send(PING_MESSAGE)
    }

    fun close() {
        socket?.close(1000, "client stopping")
        socket = null
    }

    /** SHA-256 (lowercase hex) of the DER inside a PEM certificate, or null. */
    private fun sha256HexOfPem(pem: String): String? {
        val base64 = pem
            .substringAfter("-----BEGIN CERTIFICATE-----", "")
            .substringBefore("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
        if (base64.isBlank()) return null
        return try {
            val der = Base64.getDecoder().decode(base64)
            MessageDigest.getInstance("SHA-256")
                .digest(der)
                .joinToString("") { "%02x".format(it) }
        } catch (error: Exception) {
            null
        }
    }

    private companion object {
        val JSON_MEDIA = "application/json".toMediaType()
        const val PING_MESSAGE = "{\"type\":\"ping\"}"
    }
}

/** Wraps a legible diagnostic as a throwable for `Result` propagation. */
class ControlException(val diagnostic: ClientDiagnostic) : Exception(diagnostic.what)
