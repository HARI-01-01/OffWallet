package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse
import kotlinx.coroutines.tasks.await

/**
 * IntegrityManager - Interface for Google Play Integrity API.
 */
object IntegrityManager {
    private const val TAG = "IntegrityManager"
    private const val CLOUD_PROJECT_NUMBER = 123456789L // Replace with actual project number

    private var lastRequestTime = 0L
    private const val MIN_REQUEST_INTERVAL_MS = 1000L // 1 second throttle to allow sequential steps

    suspend fun fetchIntegrityToken(context: Context, nonce: ByteArray): String? {
        val now = System.currentTimeMillis()
        val timeSinceLastRequest = now - lastRequestTime
        if (timeSinceLastRequest < MIN_REQUEST_INTERVAL_MS) {
            val waitTime = MIN_REQUEST_INTERVAL_MS - timeSinceLastRequest
            Log.i(TAG, "Throttling Integrity request. Waiting ${waitTime}ms...")
            kotlinx.coroutines.delay(waitTime)
        }
        lastRequestTime = System.currentTimeMillis()
        
        return try {
            val integrityManager = IntegrityManagerFactory.create(context)
            
            val request = IntegrityTokenRequest.builder()
                .setCloudProjectNumber(CLOUD_PROJECT_NUMBER)
                .setNonce(HexUtils.encodeHex(nonce))
                .build()

            val response: IntegrityTokenResponse = integrityManager.requestIntegrityToken(request).await()
            response.token()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch Play Integrity token: ${e.message}")
            null // Fail fast in production
        }
    }
}
