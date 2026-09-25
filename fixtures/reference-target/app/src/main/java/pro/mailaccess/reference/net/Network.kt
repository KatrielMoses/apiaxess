package pro.mailaccess.reference.net

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/** Process-wide HTTP stack: one OkHttp client shared by Retrofit and raw calls. */
object Network {

    /** Tags every first-party request with the client platform. */
    private val platformHeader = Interceptor { chain ->
        val request = chain.request()
        if (request.url.host == "mailaccess.pro") {
            chain.proceed(
                request.newBuilder()
                    .header("X-App-Platform", ApiConfig.PLATFORM)
                    .build(),
            )
        } else {
            chain.proceed(request)
        }
    }

    val okHttp: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .addInterceptor(platformHeader)
        .build()

    val mailAccess: MailAccessApi = Retrofit.Builder()
        .baseUrl(ApiConfig.RETROFIT_BASE_URL)
        .client(okHttp)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(MailAccessApi::class.java)

    val todos: TodoApi = Retrofit.Builder()
        .baseUrl(ApiConfig.TODO_BASE_URL)
        .client(okHttp)
        .build()
        .create(TodoApi::class.java)
}
