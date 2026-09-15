package com.apiaxess.client.capture

import android.os.ParcelFileDescriptor
import java.io.FileDescriptor

/**
 * Reads the original destination of an iptables-REDIRECTed connection.
 *
 * The accepted socket is presented as a [FileDescriptor] (from `Os.accept`). To
 * hand a plain int fd to the native `getsockopt(SO_ORIGINAL_DST)` shim without
 * touching hidden reflection APIs, we `ParcelFileDescriptor.dup` it (public API):
 * the dup shares the same underlying socket, so the socket option reads back
 * identically, and we close the dup immediately after.
 */
object OriginalDst {
    init {
        System.loadLibrary("apiaxessclient")
    }

    /** Returns "host:port" ("[v6]:port" for IPv6), or null if not redirected. */
    fun of(fileDescriptor: FileDescriptor): String? {
        val dup = try {
            ParcelFileDescriptor.dup(fileDescriptor)
        } catch (error: Exception) {
            return null
        }
        return dup.use { nativeOriginalDst(it.fd) }
    }

    @JvmStatic
    private external fun nativeOriginalDst(fd: Int): String?
}
