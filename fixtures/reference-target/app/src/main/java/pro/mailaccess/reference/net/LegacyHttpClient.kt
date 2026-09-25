package pro.mailaccess.reference.net

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Platform HttpURLConnection calls, as found in legacy modules and SDKs. */
class LegacyHttpClient {

    fun healthCheck(): Int {
        val connection = URL("https://mailaccess.pro/api/v1/health").openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.responseCode
        } finally {
            connection.disconnect()
        }
    }

    fun saveNotificationSettings(email: Boolean, push: Boolean): Int {
        val url = URL(ApiConfig.BASE_URL + "/api/v1/settings/notifications")
        val connection = url.openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "PUT"
            connection.doOutput = true
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("X-App-Platform", ApiConfig.PLATFORM)
            val body = JSONObject().put("email", email).put("push", push).toString()
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            connection.responseCode
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val TIMEOUT_MS = 15_000
    }
}
