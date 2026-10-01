package com.offlinewallet.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.offlinewallet.SecureStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * HighWaterStore - Monotonic store for values that can only increase.
 * Defeats clock and state rollback using hardware-sealed references.
 */
object HighWaterStore {
    private const val TAG = "HighWaterStore"
    private const val PREFS_NAME = "hwm_store"
    private lateinit var prefs: SharedPreferences

    enum class Key { 
        TIME_HWM, 
        GENESIS_EPOCH, 
        TOPUP_SEQ, 
        PASS_SERVER_SEQ, 
        COUNTER_HWM 
    }

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Bumps the HWM for a specific key.
     * Persists a hardware-sealed copy in Keystore for maximum assurance.
     */
    fun bump(key: Key, v: Long) {
        if (!::prefs.isInitialized) {
            Log.e(TAG, "HighWaterStore not initialized. Skipping bump.")
            return
        }
        val current = get(key)
        if (v > current) {
            // 1. Update fast cache
            prefs.edit().putLong(key.name, v).apply()
            
            // 2. Persist sealed reference in Keystore
            val sealed = SecureKeyStore.sealData(v.toString().toByteArray())
            if (sealed != null) {
                prefs.edit().putString("sealed_${key.name}", HexUtils.encodeHex(sealed)).apply()
            }
            Log.d(TAG, "HWM bumped for ${key.name} to $v")
        }
    }

    /**
     * Retrieves the highest seen value for a key.
     * Cross-verifies with the sealed Keystore reference.
     */
    fun get(key: Key): Long {
        if (!::prefs.isInitialized) return 0L
        val cached = prefs.getLong(key.name, 0L)
        val sealedHex = prefs.getString("sealed_${key.name}", null) ?: return cached
        
        val unsealed = SecureKeyStore.unsealData(HexUtils.decodeHex(sealedHex))
        val sealedValue = unsealed?.let { String(it).toLongOrNull() } ?: 0L
        
        return maxOf(cached, sealedValue)
    }

    /**
     * Issue 6.3: Check if the provided timestamp is acceptable given the HWM.
     * Implements a 5-minute grace period for NTP/DST drift.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun isTimeAcceptable(context: Context, nowSeconds: Long): Boolean {
        val hwm = get(Key.TIME_HWM)
        val drift = nowSeconds - hwm
        
        // 1. Clock moved forward: Accept and update HWM
        if (drift > 0) {
            bump(Key.TIME_HWM, nowSeconds)
            return true
        }
        
        // 2. Clock moved backward: Check magnitude
        val driftMagnitude = -drift
        if (driftMagnitude <= 300) { // 5 minutes grace (NTP/DST)
            Log.w(TAG, "Allowing small clock rollback: ${driftMagnitude}s")
            return true
        }
        
        // 3. Suspicious rollback (> 5 min)
        val lastSyncTime = SecureStorage.getLastSyncTime() / 1000
        if (nowSeconds - lastSyncTime < 3600) { // Synced in last hour
            Log.e(TAG, "🚨 SUSPICIOUS CLOCK ROLLBACK: ${driftMagnitude}s. Freezing bucket.")
            val walletId = SecureStorage.getWalletId() ?: "unknown"
            GlobalScope.launch(Dispatchers.IO) {
                BucketManager(context).freezeBucket(walletId, "CLOCK_ROLLBACK")
            }
            return false
        }
        
        Log.w(TAG, "Clock rollback detected (${driftMagnitude}s) but device was offline long. Logged.")
        return true
    }
}
