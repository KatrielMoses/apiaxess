package pro.mailaccess.reference

import android.app.Activity
import android.content.Intent
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
import pro.mailaccess.reference.net.LegacyHttpClient
import pro.mailaccess.reference.net.Network
import pro.mailaccess.reference.net.RawApiClient
import pro.mailaccess.reference.net.UserPayload

class MainActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val api = Network.mailAccess
    private val raw = RawApiClient()
    private val legacy = LegacyHttpClient()
    private lateinit var log: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        log = findViewById(R.id.log)

        loadHome()

        bind(R.id.btn_create_user) {
            call("E04") { api.createUser(UserPayload("Ada Lovelace", "ada@example.com")).code() }
        }
        bind(R.id.btn_update_user) {
            call("E05") { api.updateUser(CURRENT_USER_ID, UserPayload("Ada King", "ada@example.com")).code() }
        }
        bind(R.id.btn_delete_user) {
            call("E06") { api.deleteUser(CURRENT_USER_ID).code() }
        }
        bind(R.id.btn_search) {
            call("E07") { api.search("invoice").code() }
        }
        bind(R.id.btn_load_order) {
            call("E11") { raw.loadOrderItems("ord_9f2c") }
        }
        bind(R.id.btn_reports) {
            call("E12") { raw.loadReports("2026-09-01", "2026-09-30") }
        }
        bind(R.id.btn_load_profile) {
            call("E14") { raw.loadProfile(CURRENT_USER_ID) }
        }
        bind(R.id.btn_open_settings) {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    /** Everything the home screen fetches as soon as it opens. */
    private fun loadHome() {
        call("E01") { api.status().code() }
        call("E02") { api.getUser(CURRENT_USER_ID).code() }
        call("E03") { api.listUsers(page = 1, sort = "name").code() }
        call("E09") { raw.fetchConfig() }
        call("E10") { raw.trackEvent("app_open", "home") }
        call("E15") { legacy.healthCheck() }
        call("E17") { Network.todos.getTodo(1).execute().code() }
    }

    private fun bind(id: Int, action: () -> Unit) {
        findViewById<Button>(id).setOnClickListener { action() }
    }

    private fun call(label: String, block: suspend () -> Int) {
        scope.launch {
            val outcome = try {
                withContext(Dispatchers.IO) { block() }.toString()
            } catch (e: Exception) {
                "error: ${e.javaClass.simpleName}"
            }
            Log.i(TAG, "$label -> $outcome")
            log.append("$label -> $outcome\n")
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val TAG = "MailAccessRef"
        const val CURRENT_USER_ID = 42L
    }
}
