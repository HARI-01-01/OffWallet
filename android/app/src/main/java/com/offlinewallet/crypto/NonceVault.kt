package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import com.offlinewallet.SecureStorage

/**
 * NonceVault - Manages session nonces for offline transactions.
 * Nonces are server-issued and bound to app integrity.
 */
object NonceVault {
    private const val TAG = "NonceVault"
    private var currentNonce: String? = null
    private var sequenceNumber: Int = 0

    fun init(context: Context) {
        // Load latest nonce from database
        val db = SimpleDatabase.getInstance(context)
        val cursor = db.readableDatabase.query(
            "nonce_registry", 
            null, 
            "status = ?", 
            arrayOf("ACTIVE"), 
            null, null, 
            "sequence_number DESC", 
            "1"
        )
        
        cursor.use {
            if (it.moveToFirst()) {
                currentNonce = it.getString(it.getColumnIndexOrThrow("nonce_value"))
                sequenceNumber = it.getInt(it.getColumnIndexOrThrow("sequence_number"))
                Log.d(TAG, "Active nonce loaded: $currentNonce, seq: $sequenceNumber")
            }
        }
    }

    /**
     * Get the current active nonce for a transaction.
     * Fails if app integrity is compromised.
     */
    fun getCurrentNonce(): String? {
        if (!IntegrityGuardian.checkIntegrity()) {
            Log.e(TAG, "Security violation: Cannot get nonce")
            return null
        }
        return currentNonce
    }

    /**
     * Update nonce registry with a new server-issued nonce
     */
    fun saveNewNonce(context: Context, nonceId: String, walletId: String, deviceId: String, value: String, seq: Int, sig: ByteArray, expiresAt: Long) {
        val db = SimpleDatabase.getInstance(context)
        
        // Mark all old nonces as USED
        db.writableDatabase.execSQL("UPDATE nonce_registry SET status = 'USED' WHERE wallet_id = ?", arrayOf(walletId))
        
        val values = android.content.ContentValues().apply {
            put("nonce_id", nonceId)
            put("wallet_id", walletId)
            put("device_id", deviceId)
            put("nonce_value", value)
            put("sequence_number", seq)
            put("server_signature", sig)
            put("expires_at", expiresAt)
            put("issued_at", System.currentTimeMillis() / 1000)
            put("status", "ACTIVE")
        }
        
        db.writableDatabase.insert("nonce_registry", null, values)
        currentNonce = value
        sequenceNumber = seq
        Log.d(TAG, "New nonce stored: $value, seq: $seq")
    }

    fun invalidateCurrentNonce(context: Context) {
        currentNonce?.let {
            val db = SimpleDatabase.getInstance(context)
            db.writableDatabase.execSQL("UPDATE nonce_registry SET status = 'REVOKED' WHERE nonce_value = ?", arrayOf(it))
            currentNonce = null
            Log.w(TAG, "Current nonce revoked due to security event")
        }
    }
}
