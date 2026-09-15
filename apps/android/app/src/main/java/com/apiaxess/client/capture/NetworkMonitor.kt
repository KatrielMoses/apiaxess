package com.apiaxess.client.capture

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest

/**
 * Notifies when the default network changes so the capture redirect can be
 * re-established (a connectivity change can flush NAT state). Over adb/USB this
 * keeps capture effectively blip-free.
 */
class NetworkMonitor(context: Context, private val onChanged: () -> Unit) {

    private val connectivity =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = onChanged()
        override fun onLost(network: Network) = onChanged()
    }

    fun start() {
        val request = NetworkRequest.Builder().build()
        runCatching { connectivity.registerNetworkCallback(request, callback) }
    }

    fun stop() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }
}
