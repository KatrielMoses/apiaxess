package pro.mailaccess.reference.net

import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/** First-party REST API, declared the annotation-driven Retrofit way. */
interface MailAccessApi {

    @GET("api/v1/status")
    suspend fun status(): Response<ResponseBody>

    @GET("api/v1/users/{id}")
    suspend fun getUser(@Path("id") id: Long): Response<ResponseBody>

    @GET("api/v1/users")
    suspend fun listUsers(
        @Query("page") page: Int,
        @Query("sort") sort: String,
    ): Response<ResponseBody>

    @POST("api/v1/users")
    suspend fun createUser(@Body user: UserPayload): Response<ResponseBody>

    @PUT("api/v1/users/{id}")
    suspend fun updateUser(
        @Path("id") id: Long,
        @Body user: UserPayload,
    ): Response<ResponseBody>

    @DELETE("api/v1/users/{id}")
    suspend fun deleteUser(@Path("id") id: Long): Response<ResponseBody>

    @GET("api/v1/search")
    suspend fun search(@Query("q") query: String): Response<ResponseBody>

    @GET("api/v1/mailboxes/{mailboxId}/messages")
    suspend fun listMessages(
        @Path("mailboxId") mailboxId: String,
        @Query("limit") limit: Int,
        @Query("before") before: String,
        @Header("X-Client-Version") clientVersion: String,
    ): Response<ResponseBody>
}
