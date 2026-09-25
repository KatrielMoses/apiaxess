package pro.mailaccess.reference.net

/** Backend locations and client identity shared by every networking layer. */
object ApiConfig {
    /** First-party backend. Raw OkHttp and HttpURLConnection build URLs from this. */
    const val BASE_URL = "https://mailaccess.pro"

    /** Retrofit requires a trailing slash on its base URL. */
    const val RETROFIT_BASE_URL = "$BASE_URL/"

    /** Third-party placeholder API used for the "tip of the day" card. */
    const val TODO_BASE_URL = "https://jsonplaceholder.typicode.com/"

    const val CONFIG_PATH = "/api/v1/config"

    const val CLIENT_VERSION = "1.0.0"
    const val PLATFORM = "android"
}
