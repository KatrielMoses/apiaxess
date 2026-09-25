package pro.mailaccess.reference

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import pro.mailaccess.reference.net.ApiConfig
import pro.mailaccess.reference.net.LegacyHttpClient
import pro.mailaccess.reference.net.Network
import pro.mailaccess.reference.net.RawApiClient

/** Second screen: only reachable by tapping "Open settings" on the home screen. */
class SettingsActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val raw = RawApiClient()
    private val legacy = LegacyHttpClient()
    private lateinit var log: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        log = findViewById(R.id.log)

        call("E08") {
            Network.mailAccess.listMessages(
                mailboxId = "inbox",
                limit = 20,
                before = "2026-09-25T00:00:00Z",
                clientVersion = ApiConfig.CLIENT_VERSION,
            ).code()
        }

        findViewById<Button>(R.id.btn_save_settings).setOnClickListener {
            call("E16") { legacy.saveNotificationSettings(email = true, push = false) }
        }
        findViewById<Button>(R.id.btn_clear_session).setOnClickListener {
            call("E13") { raw.endSession("sess_7d1e") }
        }
    }

    private fun call(label: String, block: suspend () -> Int) {
        scope.launch {
            val outcome = try {
                withContext(Dispatchers.IO) { block() }.toString()
            } catch (e: Exception) {
                "error: ${e.javaClass.simpleName}"
            }
            Log.i(MainActivity.TAG, "$label -> $outcome")
            log.append("$label -> $outcome\n")
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
