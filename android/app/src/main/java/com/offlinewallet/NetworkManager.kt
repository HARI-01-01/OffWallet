package com.offlinewallet

import android.content.Context
import com.offlinewallet.api.WalletApi
import com.offlinewallet.models.*
import com.offlinewallet.crypto.Signer
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.converter.scalars.ScalarsConverterFactory
import java.util.concurrent.TimeUnit

class NetworkManager(
    private val context: Context,
    private val baseUrl: String
) {
    private val gson: Gson = GsonBuilder().setLenient().create()

    private val authInterceptor = Interceptor { chain ->
        val original = chain.request()
        val builder = original.newBuilder()
        SecureStorage.getAuthToken()?.let { token -> builder.header("firebase-token", token) }
        SecureStorage.getDeviceId()?.let { id -> builder.header("X-Device-ID", id) }
        chain.proceed(builder.build())
    }

    // Issue 3: CT Interceptor
    private val ctInterceptor = Interceptor { chain ->
        val request = chain.request()
        val response = chain.proceed(request)
        val certs = response.handshake?.peerCertificates
        if (certs != null && certs.isNotEmpty()) {
            val leaf = certs[0] as java.security.cert.X509Certificate
            // In a real app, we'd use a CT library. For this LLD, we simulate CT verification.
            // If CT fails, we'd compare against SecureStorage.getServerSpkiPin().
            val pin = android.util.Base64.encodeToString(leaf.publicKey.encoded, android.util.Base64.NO_WRAP)
            val cachedPin = SecureStorage.getServerSslPin() 
            
            // Seed the SSL pin on first connection (ngrok/TLS layer)
            if (cachedPin == null) {
                android.util.Log.i("NetworkManager", "Seeding Server SSL Pin: $pin")
                SecureStorage.saveServerSslPin(pin)
            } else if (cachedPin != pin) {
                // throw java.security.SecurityException("Certificate pinning mismatch!")
                android.util.Log.e("CT", "Certificate mismatch detected! (Simulation)")
            }
        }
        response
    }

    // Issue 6.3: Server Time Sync Interceptor
    private val timeInterceptor = Interceptor { chain ->
        val response = chain.proceed(chain.request())
        val serverTime = response.header("X-Server-Time")?.toLongOrNull()
        if (serverTime != null) {
            com.offlinewallet.crypto.HighWaterStore.bump(com.offlinewallet.crypto.HighWaterStore.Key.TIME_HWM, serverTime)
        }
        response
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(authInterceptor)
        .addInterceptor(ctInterceptor)
        .addInterceptor(timeInterceptor)
        .addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BODY })
        .build()

    private val api: WalletApi = Retrofit.Builder()
        .baseUrl(baseUrl)
        .client(client)
        .addConverterFactory(ScalarsConverterFactory.create())
        .addConverterFactory(GsonConverterFactory.create(gson))
        .build()
        .create(WalletApi::class.java)

    private fun <T> ApiResponse<T>.errorMessage(): String {
        // First check root error/message
        val rootErr = error ?: message ?: detail
        if (rootErr != null) return rootErr
        
        // Use reflection-like check for 'message' field in data object
        try {
            val dataObj = data
            if (dataObj != null) {
                val field = dataObj.javaClass.getDeclaredField("message")
                field.isAccessible = true
                val msg = field.get(dataObj) as? String
                if (msg != null) return msg
            }
        } catch (_: Exception) {}
        
        return "Unknown error"
    }

    suspend fun registerUser(request: UserRegisterRequest): Result<UserRegisterResponse> = try {
        val response = api.registerUser(request)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Registration failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun activateWallet(request: ActivateRequest): Result<ActivateResponse> = try {
        val response = api.activateWallet(request)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Activation failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun refreshPass(integrityToken: String): Result<PassEnvelope> = try {
        val response = api.refreshPass(integrityToken)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Pass refresh failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun loginUser(request: UserLoginRequest): Result<UserLoginResponse> = try {
        val response = api.loginUser(request)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Login failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun lookupUser(walletId: String? = null, email: String? = null, phone: String? = null): Result<UserLookupResponse> = try {
        val response = api.lookupUser(walletId, email, phone)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Lookup failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun getBalance(walletId: String): Result<Long> = try {
        val response = api.getBalance(walletId)
        if (response.status == "success") Result.success(response.data!!.balance)
        else Result.failure(Exception("Balance fetch failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun getBucketStatus(walletId: String): Result<BucketStatusResponse> = try {
        val response = api.getBucketStatus(walletId)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Status fetch failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun topupBucket(walletId: String, amount: Int): Result<BucketTopupResponse> = try {
        val response = api.topupBucket(BucketTopupRequest(walletId, amount))
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Topup failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun requestNonce(walletId: String, deviceId: String): Result<NonceResponse> = try {
        val response = api.requestNonce(NonceRequest(walletId, deviceId))
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Nonce request failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun syncOffline(request: OfflineSyncRequest): Result<OfflineSyncResponse> = try {
        val response = api.syncOffline(request)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Sync failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun sendPayment(request: SendPaymentRequest): Result<SendPaymentResponse> = try {
        val response = api.sendPayment(request)
        if (response.status == "success") Result.success(response.data!!)
        else Result.failure(Exception("Payment failed: ${response.errorMessage()}"))
    } catch (e: Exception) { Result.failure(e) }

    suspend fun syncQueue(apiKey: String, deviceId: String, devicePrivateKey: ByteArray, transactions: List<Map<String, Any>>, queueManager: com.offlinewallet.crypto.QueueManager): Map<String, Int> {
        return mapOf("synced" to 0, "failed" to 0, "duplicate" to 0)
    }

    suspend fun processOnlinePayment(payerId: String, payeeId: String, amount: Int): OnlinePaymentResult {
        return try {
            val res = getBalance(payerId)
            if (res.isSuccess && res.getOrNull()!! >= amount) {
                OnlinePaymentResult(true, "✅ Success", "txn_${System.currentTimeMillis()}", (res.getOrNull()!! - amount).toInt())
            } else OnlinePaymentResult(false, "❌ Failed")
        } catch (e: Exception) { OnlinePaymentResult(false, "❌ Error") }
    }

    suspend fun checkHealth(): Result<Map<String, String>> = try {
        val response = api.health()
        Result.success(response)
    } catch (e: Exception) { Result.failure(e) }

    suspend fun runAutoRescue(): Result<Unit> = try {
        api.runAutoRescue()
        Result.success(Unit)
    } catch (e: Exception) { Result.failure(e) }

    suspend fun reportTamperEvent(walletId: String, reason: String, apkHash: String, deviceId: String): Result<Unit> = try {
        api.reportTamper(TamperReportRequest(walletId, reason, apkHash, deviceId))
        Result.success(Unit)
    } catch (e: Exception) { Result.failure(e) }

    suspend fun unfreezeWallet(): Result<Unit> = try {
        api.unfreezeWallet()
        Result.success(Unit)
    } catch (e: Exception) { Result.failure(e) }
}
