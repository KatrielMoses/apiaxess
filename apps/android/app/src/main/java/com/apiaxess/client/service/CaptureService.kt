package com.apiaxess.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.apiaxess.client.MainActivity
import com.apiaxess.client.R
import com.apiaxess.client.capture.CaptureState
import com.apiaxess.client.capture.CaptureTarget
import com.apiaxess.client.core.WorkbenchConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import android.app.PendingIntent

/**
 * Foreground service that makes capture survive the app leaving the foreground
 * and the device sleeping: it holds a partial wakelock and a persistent
 * notification, and mirrors [CaptureManager]'s state into that notification. All
 * capture logic lives in [CaptureManager]/CaptureController; this is the OS-facing
 * lifecycle shell.
 */
class CaptureService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var wakeLock: PowerManager.WakeLock? = null
    private var observer: Job? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                CaptureManager.stop()
                shutdown()
                return START_NOT_STICKY
            }
            else -> start(intent)
        }
        return START_STICKY
    }

    private fun start(intent: Intent?) {
        enterForeground("Starting capture…")
        acquireWakeLock()
        observeState()

        val config = intent?.toConfig()
        val target = intent?.toTarget()
        if (config != null && target != null) {
            CaptureManager.start(this, config, target)
        }
    }

    private fun observeState() {
        if (observer != null) return
        CaptureManager.ensureInitialised(this)
        observer = CaptureManager.state
            .onEach { state ->
                notify(notificationText(state))
                if (state is CaptureState.Failed || state is CaptureState.Stopped) {
                    // Keep the service alive on Failed so the UI can read the
                    // diagnostic; drop the wakelock since nothing is capturing.
                    releaseWakeLock()
                }
            }
            .launchIn(scope)
    }

    private fun notificationText(state: CaptureState): String = when (state) {
        is CaptureState.Idle -> "Idle"
        is CaptureState.Preparing -> state.step
        is CaptureState.Capturing ->
            "Capturing ${state.target.label} · ${state.totalConnections} flows"
        is CaptureState.Reconnecting -> "Reconnecting (attempt ${state.attempt})"
        is CaptureState.Failed -> state.diagnostic.what
        is CaptureState.Stopped -> "Stopped"
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG).apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) wakeLock?.release()
    }

    private fun shutdown() {
        releaseWakeLock()
        observer?.cancel()
        observer = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        releaseWakeLock()
        observer?.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Capture",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "APIaxess per-app capture status" }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APIaxess capture")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setContentIntent(open)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun notify(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    /** Enters the foreground with the correct FGS type, updating the notification. */
    private fun enterForeground(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun Intent.toConfig(): WorkbenchConfig? {
        val host = getStringExtra(EXTRA_CONTROL_HOST) ?: return null
        return WorkbenchConfig(
            controlHost = host,
            controlPort = getIntExtra(EXTRA_CONTROL_PORT, WorkbenchConfig.DEFAULT_CONTROL_PORT),
            proxyHost = getStringExtra(EXTRA_PROXY_HOST) ?: host,
            proxyPort = getIntExtra(EXTRA_PROXY_PORT, WorkbenchConfig.DEFAULT_PROXY_PORT),
            pairingToken = getStringExtra(EXTRA_PAIRING_TOKEN).orEmpty(),
            // Carry the QR's pinned CA fingerprint through the service boundary so
            // verifyCaFingerprint actually pins it (the rogue-server defense). A
            // manual-entry config has none, leaving this null (pinning skipped).
            caFingerprint = getStringExtra(EXTRA_CA_FINGERPRINT),
        )
    }

    private fun Intent.toTarget(): CaptureTarget? {
        val pkg = getStringExtra(EXTRA_TARGET_PACKAGE) ?: return null
        val uid = getIntExtra(EXTRA_TARGET_UID, -1)
        if (uid < 0) return null
        return CaptureTarget(pkg, getStringExtra(EXTRA_TARGET_LABEL) ?: pkg, uid)
    }

    companion object {
        private const val CHANNEL_ID = "apiaxess-capture"
        private const val NOTIFICATION_ID = 1
        private const val WAKELOCK_TAG = "apiaxess:capture"

        const val ACTION_START = "com.apiaxess.client.action.START"
        const val ACTION_STOP = "com.apiaxess.client.action.STOP"

        const val EXTRA_CONTROL_HOST = "control_host"
        const val EXTRA_CONTROL_PORT = "control_port"
        const val EXTRA_PROXY_HOST = "proxy_host"
        const val EXTRA_PROXY_PORT = "proxy_port"
        const val EXTRA_PAIRING_TOKEN = "pairing_token"
        const val EXTRA_CA_FINGERPRINT = "ca_fingerprint"
        const val EXTRA_TARGET_PACKAGE = "target_package"
        const val EXTRA_TARGET_LABEL = "target_label"
        const val EXTRA_TARGET_UID = "target_uid"

        fun startIntent(
            context: Context,
            config: WorkbenchConfig,
            target: CaptureTarget,
        ): Intent = Intent(context, CaptureService::class.java).apply {
            action = ACTION_START
            putExtra(EXTRA_CONTROL_HOST, config.controlHost)
            putExtra(EXTRA_CONTROL_PORT, config.controlPort)
            putExtra(EXTRA_PROXY_HOST, config.proxyHost)
            putExtra(EXTRA_PROXY_PORT, config.proxyPort)
            putExtra(EXTRA_PAIRING_TOKEN, config.pairingToken)
            putExtra(EXTRA_CA_FINGERPRINT, config.caFingerprint)
            putExtra(EXTRA_TARGET_PACKAGE, target.packageName)
            putExtra(EXTRA_TARGET_LABEL, target.label)
            putExtra(EXTRA_TARGET_UID, target.uid)
        }

        fun stopIntent(context: Context): Intent =
            Intent(context, CaptureService::class.java).apply { action = ACTION_STOP }
    }
}
