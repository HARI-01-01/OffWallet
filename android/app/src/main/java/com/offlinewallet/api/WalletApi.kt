package com.offlinewallet.api

import com.offlinewallet.models.*
import retrofit2.Call
import retrofit2.http.*

interface WalletApi {
    @GET("/health")
    suspend fun health(): Map<String, String>

    @POST("api/v1/auth/register")
    suspend fun registerUser(@Body request: UserRegisterRequest): ApiResponse<UserRegisterResponse>

    @POST("api/v1/wallet/activate")
    suspend fun activateWallet(@Body request: ActivateRequest): ApiResponse<ActivateResponse>

    @GET("api/v1/pass/refresh")
    suspend fun refreshPass(@Header("integrity-token") integrityToken: String): ApiResponse<PassEnvelope>

    @POST("api/v1/auth/login")
    suspend fun loginUser(@Body request: UserLoginRequest): ApiResponse<UserLoginResponse>

    @GET("api/v1/user/profile")
    suspend fun getUserProfile(): ApiResponse<UserLoginResponse>

    @GET("api/v1/user/lookup")
    suspend fun lookupUser(@Query("wallet_id") walletId: String? = null, @Query("email") email: String? = null, @Query("phone") phone: String? = null): ApiResponse<UserLookupResponse>

    @GET("api/v1/user/qr-code")
    suspend fun getQRCode(): ApiResponse<QRCodeResponse>

    @POST("api/v1/auth/verify-token")
    suspend fun verifyToken(@Body request: VerifyTokenRequest): ApiResponse<VerifyTokenResponse>

    @GET("api/v1/user/{walletId}/status")
    suspend fun getBucketStatus(@Path("walletId") walletId: String): ApiResponse<BucketStatusResponse>

    @POST("api/v1/bucket/topup")
    suspend fun topupBucket(@Body request: BucketTopupRequest): ApiResponse<BucketTopupResponse>

    @POST("api/v1/offline/reconcile")
    suspend fun uploadTransaction(@Header("X-Timestamp") timestamp: String, @Header("X-Signature") signature: String, @Body request: UploadTransactionRequest): ApiResponse<UploadTransactionResponse>

    @GET("api/v1/user/{walletId}/balance")
    suspend fun getBalance(@Path("walletId") walletId: String): ApiResponse<BalanceResponse>

    @GET("api/v1/transactions/{walletId}")
    suspend fun getTransactions(@Path("walletId") walletId: String, @Query("limit") limit: Int = 10): ApiResponse<TransactionHistoryResponse>

    @POST("api/v1/rescue/run")
    suspend fun runAutoRescue(): ApiResponse<Any>

    @POST("api/v1/wallet/send-payment")
    suspend fun sendPayment(@Body request: SendPaymentRequest): ApiResponse<SendPaymentResponse>

    @POST("api/v1/offline/sync")
    suspend fun syncOffline(@Body request: OfflineSyncRequest): ApiResponse<OfflineSyncResponse>

    @POST("api/v1/nonce/request")
    suspend fun requestNonce(@Body request: NonceRequest): ApiResponse<NonceResponse>

    @POST("api/v1/security/tamper-report")
    suspend fun reportTamper(@Body request: TamperReportRequest): ApiResponse<Any>

    @POST("api/v1/security/unfreeze")
    suspend fun unfreezeWallet(): ApiResponse<Any>
}
