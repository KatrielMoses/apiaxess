package com.apiaxess.client.capture

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VpnService fallback (Phase C3, requirement 2) for devices where the iptables
 * owner-match redirect is constrained (locked-down kernels, no NAT/owner module).
 *
 * It establishes a **per-app** tunnel — `addAllowedApplication(targetPackage)` —
 * so only the chosen app is routed, matching the iptables path's per-app scoping,
 * and blocks QUIC by NOT routing UDP/443 through an interceptable path (the app
 * sees the tunnel drop it, forcing TCP fallback). The primary, proven path is
 * iptables; this fallback shares the same relay → tunnelled-MITM destination.
 *
 * NOTE (honest residual): turning tun packets back into per-flow `CONNECT`s to the
 * relay requires a userspace TCP/IP reassembly engine (a tun2socks-style stack).
 * The service below owns the full VpnService lifecycle, per-app allow-listing, and
 * socket protection; the packet engine that drives [forwardTunnel] is the one
 * remaining piece and is intentionally isolated here. The iptables primary path
 * needs none of it.
 */
class ApiaxessVpnService : VpnService() {

    private val running = AtomicBoolean(false)
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val targetPackage = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)
        if (targetPackage == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.compareAndSet(false, true)) {
            establish(targetPackage)
        }
        return START_STICKY
    }

    private fun establish(targetPackage: String) {
        val builder = Builder()
            .setSession("APIaxess capture")
            .setMtu(MTU)
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)

        // Per-app: route ONLY the chosen app through the tunnel.
        runCatching { builder.addAllowedApplication(targetPackage) }
        // Never route ourselves through the tunnel (avoids a relay loop).
        runCatching { builder.addDisallowedApplication(packageName) }

        val descriptor = builder.establish() ?: run {
            running.set(false)
            stopSelf()
            return
        }
        tunnel = descriptor
        worker = Thread({ forwardTunnel(descriptor) }, "apiaxess-vpn-forward").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Reads packets from the tun. A full implementation reassembles TCP flows and,
     * for each, opens a [protect]ed socket to the relay/tunnelled proxy and issues
     * `CONNECT <dst>` — reusing the exact relay path as the iptables lane. UDP/443
     * is intentionally not forwarded, so QUIC is dropped and apps fall back to TCP.
     */
    private fun forwardTunnel(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val packet = ByteArray(MTU)
        while (running.get()) {
            val read = try {
                input.read(packet)
            } catch (error: Exception) {
                break
            }
            if (read <= 0) continue
            // Residual seam: hand `packet[0 until read]` to the tun2socks engine,
            // which learns the destination from the IP header and relays TCP flows
            // to the relay's loopback port via CONNECT, dropping UDP/443. Sockets it
            // opens must be wrapped in `protect(fd)` so they egress the real network
            // rather than re-entering the tunnel.
        }
    }

    /** Wraps an outbound socket fd so it bypasses this VPN (used by the engine). */
    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onDestroy() {
        running.set(false)
        worker?.interrupt()
        runCatching { tunnel?.close() }
        tunnel = null
        super.onDestroy()
    }

    companion object {
        const val EXTRA_TARGET_PACKAGE = "target_package"
        private const val MTU = 1500
        private const val TUN_ADDRESS = "10.111.0.2"
        private const val TUN_PREFIX = 32
    }
}
