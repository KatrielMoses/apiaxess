package pro.mailaccess.reference.net

import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.UUID

/**
 * Hand-written OkHttp calls. URLs are assembled at runtime from the base URL
 * constant — concatenation, string templates and HttpUrl.Builder — the way
 * older or performance-sensitive parts of real apps do it.
 */
class RawApiClient {

    private val client = Network.okHttp
    private val json = "application/json; charset=utf-8".toMediaType()

    fun fetchConfig(): Int {
        val request = Request.Builder()
            .url(ApiConfig.BASE_URL + ApiConfig.CONFIG_PATH)
            .get()
            .build()
        return execute(request)
    }

    fun trackEvent(event: String, screen: String): Int {
        val body = JSONObject()
            .put("event", event)
            .put("screen", screen)
            .put("ts", System.currentTimeMillis())
            .toString()
        val request = Request.Builder()
            .url(ApiConfig.BASE_URL + "/api/v1/events")
            .header("X-Request-Id", UUID.randomUUID().toString())
            .post(body.toRequestBody(json))
            .build()
        return execute(request)
    }

    fun loadOrderItems(orderId: String): Int {
        val request = Request.Builder()
            .url("${ApiConfig.BASE_URL}/api/v1/orders/$orderId/items")
            .build()
        return execute(request)
    }

    fun loadReports(from: String, to: String): Int {
        val url = HttpUrl.Builder()
            .scheme("https")
            .host("mailaccess.pro")
            .addPathSegments("api/v2/reports")
            .addQueryParameter("from", from)
            .addQueryParameter("to", to)
            .build()
        return execute(Request.Builder().url(url).build())
    }

    fun endSession(sessionId: String): Int {
        val request = Request.Builder()
            .url(ApiConfig.BASE_URL + "/api/v1/sessions/" + sessionId)
            .delete()
            .build()
        return execute(request)
    }

    /** GraphQL over plain OkHttp: a single POST endpoint, operation in the body. */
    fun loadProfile(userId: Long): Int {
        val body = JSONObject()
            .put("operationName", "GetProfile")
            .put("query", PROFILE_QUERY)
            .put("variables", JSONObject().put("id", userId))
            .toString()
        val request = Request.Builder()
            .url(ApiConfig.BASE_URL + "/graphql")
            .post(body.toRequestBody(json))
            .build()
        return execute(request)
    }

    private fun execute(request: Request): Int =
        client.newCall(request).execute().use { it.code }

    private companion object {
        const val PROFILE_QUERY =
            "query GetProfile(\$id: ID!) { profile(id: \$id) { id displayName email plan } }"
    }
}
