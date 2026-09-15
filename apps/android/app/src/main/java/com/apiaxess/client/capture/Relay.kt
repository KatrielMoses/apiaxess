package com.apiaxess.client.capture

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.apiaxess.client.core.WorkbenchConfig
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Observes relay lifecycle for the status UI. */
interface RelayListener {
    fun onConnectionOpened(target: String)
    fun onConnectionError(detail: String)
}

/**
 * The on-device transparent-to-explicit shim (Phase C3, requirement 3).
 *
 * iptables REDIRECTs the chosen app's TCP to this relay's loopback port. For each
 * accepted connection the relay reads the original destination via
 * `SO_ORIGINAL_DST`, opens the workbench MITM over the adb-reverse tunnel
 * (`127.0.0.1:<proxyPort>`), issues an explicit `CONNECT host:port`, and — once
 * the proxy answers `200` — pipes the bytes both ways. This reuses the
 * workbench's proven explicit-CONNECT MITM path unchanged.
 */
class Relay(
    private val config: WorkbenchConfig,
    private val listener: RelayListener,
) {
    private val running = AtomicBoolean(false)
    private val pumps = Executors.newCachedThreadPool()
    private val acceptors = mutableListOf<Thread>()
    private val serverFds = mutableListOf<FileDescriptor>()
    val activeConnections = AtomicLong(0)

    /**
     * Binds the relay on loopback for IPv4 and IPv6 and starts accepting.
     *
     * @throws ErrnoException if a listener socket cannot be created or bound.
     */
    fun start() {
        if (!running.compareAndSet(false, true)) return
        listen(OsConstants.AF_INET, InetAddress.getByName("127.0.0.1"))
        // IPv6 is best-effort: some devices/emulators have it disabled.
        runCatching { listen(OsConstants.AF_INET6, InetAddress.getByName("::1")) }
    }

    private fun listen(family: Int, address: InetAddress) {
        val serverFd = Os.socket(family, OsConstants.SOCK_STREAM, 0)
        Os.setsockoptInt(serverFd, OsConstants.SOL_SOCKET, OsConstants.SO_REUSEADDR, 1)
        Os.bind(serverFd, address, WorkbenchConfig.RELAY_PORT)
        Os.listen(serverFd, BACKLOG)
        serverFds += serverFd
        val acceptor = Thread({ acceptLoop(serverFd) }, "apiaxess-relay-accept")
        acceptor.isDaemon = true
        acceptors += acceptor
        acceptor.start()
    }

    private fun acceptLoop(serverFd: FileDescriptor) {
        while (running.get()) {
            val clientFd = try {
                Os.accept(serverFd, null)
            } catch (error: ErrnoException) {
                if (running.get()) listener.onConnectionError("accept: ${error.message}")
                break
            }
            pumps.execute { handle(clientFd) }
        }
    }

    private fun handle(clientFd: FileDescriptor) {
        val target = OriginalDst.of(clientFd)
        if (target == null) {
            safeClose(clientFd)
            listener.onConnectionError("original destination unavailable (connection not redirected)")
            return
        }
        var upstream: Socket? = null
        try {
            upstream = Socket()
            upstream.tcpNoDelay = true
            upstream.connect(
                InetSocketAddress(config.proxyHost, config.proxyPort),
                CONNECT_TIMEOUT_MS,
            )
            val upIn = upstream.getInputStream()
            val upOut = upstream.getOutputStream()
            if (!openConnectTunnel(upIn, upOut, target)) {
                listener.onConnectionError("workbench proxy refused CONNECT $target")
                safeClose(clientFd)
                upstream.close()
                return
            }
            listener.onConnectionOpened(target)
            activeConnections.incrementAndGet()

            // Own the accepted fd through streams from here on: closing a stream
            // invalidates the shared FileDescriptor (to -1), which both prevents an
            // fd-reuse double-close and unblocks the peer pump's read.
            val clientIn = FileInputStream(clientFd)
            val clientOut = FileOutputStream(clientFd)
            val finalUpstream = upstream
            val closed = java.util.concurrent.atomic.AtomicBoolean(false)
            val teardown = {
                if (closed.compareAndSet(false, true)) {
                    runCatching { clientIn.close() }
                    runCatching { clientOut.close() }
                    runCatching { finalUpstream.close() }
                    activeConnections.updateAndGet { if (it > 0) it - 1 else 0 }
                }
            }
            // client -> proxy
            pumps.execute {
                copy(clientIn, upOut)
                teardown()
            }
            // proxy -> client
            copy(upIn, clientOut)
            teardown()
        } catch (error: Exception) {
            listener.onConnectionError("relay $target: ${error.message}")
            safeClose(clientFd)
            upstream?.let { runCatching { it.close() } }
        }
    }

    /** Sends `CONNECT host:port` and returns true iff the proxy answers 2xx. */
    private fun openConnectTunnel(input: InputStream, output: OutputStream, target: String): Boolean {
        val request = "CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n"
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()
        val statusLine = readHttpStatusLine(input) ?: return false
        // Expect e.g. "HTTP/1.1 200 Connection Established".
        val parts = statusLine.split(' ')
        val code = parts.getOrNull(1)?.toIntOrNull() ?: return false
        return code in 200..299
    }

    /**
     * Reads response bytes up to the end of the header block (CRLF CRLF) and
     * returns the first (status) line, e.g. "HTTP/1.1 200 Connection Established".
     * Reads a byte at a time deliberately: after the blank line the very next
     * bytes are the tunnelled payload, which must be left in the stream.
     */
    private fun readHttpStatusLine(input: InputStream): String? {
        val header = ByteArray(MAX_HEADER_BYTES)
        var length = 0
        while (length < MAX_HEADER_BYTES) {
            val byte = input.read()
            if (byte == -1) return null
            header[length++] = byte.toByte()
            if (length >= 4 &&
                header[length - 4] == '\r'.code.toByte() &&
                header[length - 3] == '\n'.code.toByte() &&
                header[length - 2] == '\r'.code.toByte() &&
                header[length - 1] == '\n'.code.toByte()
            ) {
                val text = String(header, 0, length, Charsets.US_ASCII)
                return text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()
            }
        }
        return null
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_BYTES)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (_: Exception) {
            // Peer closed or the fd was torn down; the finally in handle() cleans up.
        }
    }

    private fun safeClose(fd: FileDescriptor) {
        runCatching { Os.close(fd) }
    }

    /** Stops accepting and closes the listener sockets. */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        serverFds.forEach { safeClose(it) }
        serverFds.clear()
        acceptors.clear()
        pumps.shutdownNow()
    }

    private companion object {
        const val BACKLOG = 128
        const val BUFFER_BYTES = 32 * 1024
        const val CONNECT_TIMEOUT_MS = 10_000
        const val MAX_HEADER_BYTES = 8 * 1024
    }
}
