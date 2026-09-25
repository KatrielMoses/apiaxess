package pro.mailaccess.reference.net

import okhttp3.ResponseBody
import retrofit2.Call
import retrofit2.http.GET
import retrofit2.http.Path

/** Third-party API, declared with the older blocking Call<T> Retrofit style. */
interface TodoApi {

    @GET("todos/{id}")
    fun getTodo(@Path("id") id: Int): Call<ResponseBody>
}
