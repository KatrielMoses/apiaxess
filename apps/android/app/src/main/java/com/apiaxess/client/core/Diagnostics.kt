package com.apiaxess.client.core

/**
 * A legible failure, mirroring the workbench's structured `what / why / fix`
 * diagnostics. The whole value proposition is "zero troubleshoot" — so when the
 * client cannot proceed, it says exactly what happened, why, and how to fix it,
 * rather than a bare stack trace.
 */
data class ClientDiagnostic(
    val id: String,
    val what: String,
    val why: String,
    val fix: String,
) {
    companion object {
        fun rootUnavailable(detail: String) = ClientDiagnostic(
            id = "client.root-unavailable",
            what = "This device is not rooted, or root was denied.",
            why = "Per-app capture installs an iptables rule and reads redirected sockets, which both require root. $detail",
            fix = "Use a rooted device/emulator and grant this app superuser access, then retry.",
        )

        fun iptablesFailed(detail: String) = ClientDiagnostic(
            id = "client.iptables-failed",
            what = "The per-app capture redirect could not be installed.",
            why = "The iptables OUTPUT NAT rule (or the QUIC block) was rejected by the kernel: $detail",
            fix = "Use a rooted device whose kernel supports iptables owner-match + NAT (most stock kernels do), then retry.",
        )

        fun relayFailed(detail: String) = ClientDiagnostic(
            id = "client.relay-failed",
            what = "The local capture relay could not start.",
            why = "The relay could not bind its loopback port or accept redirected connections: $detail",
            fix = "Stop any other capture session, then retry; if the port is in use, reconnect to rebind it.",
        )

        fun tunnelDown(detail: String) = ClientDiagnostic(
            id = "client.tunnel-down",
            what = "The workbench is no longer reachable over USB.",
            why = "The connection to the workbench dropped — the device was unplugged, or the adb link was reset: $detail",
            fix = "Reconnect the USB cable and pair the device again from the workbench to re-establish the connection.",
        )

        fun workbenchUnreachable(detail: String) = ClientDiagnostic(
            id = "client.workbench-unreachable",
            what = "The workbench did not respond.",
            why = "The pairing or control request to the workbench over USB failed: $detail",
            fix = "Confirm the workbench app is running and that you paired this device from it, then retry.",
        )

        fun operatorDeclined() = ClientDiagnostic(
            id = "client.operator-declined",
            what = "The workbench operator declined this device.",
            why = "Someone at the workbench chose Decline on the Accept / Decline prompt, so no session was granted.",
            fix = "Ask the operator to accept the connection, then scan a fresh pairing QR — each pairing token is single-use.",
        )

        fun pairingRejected(detail: String) = ClientDiagnostic(
            id = "client.pairing-rejected",
            what = "The workbench rejected the pairing token.",
            why = "The one-time pairing token was invalid, already used, or expired: $detail",
            fix = "Show a fresh pairing QR on the workbench and scan it again — pairing tokens are single-use and short-lived.",
        )

        fun fingerprintMismatch(detail: String) = ClientDiagnostic(
            id = "client.fingerprint-mismatch",
            what = "This is not the workbench that showed the QR.",
            why = "The CA served at the scanned address does not match the fingerprint the QR pinned, which means a different (possibly rogue) server answered: $detail",
            fix = "Do not proceed. Re-scan the QR directly from the intended workbench, and check nothing is intercepting the connection.",
        )

        fun pairingExpired() = ClientDiagnostic(
            id = "client.pairing-expired",
            what = "The pairing request expired before it was accepted.",
            why = "The operator did not accept or decline in time, or the workbench restarted, so the pending request is gone.",
            fix = "Scan a fresh pairing QR (or re-enter the token) to start a new request.",
        )
    }
}
