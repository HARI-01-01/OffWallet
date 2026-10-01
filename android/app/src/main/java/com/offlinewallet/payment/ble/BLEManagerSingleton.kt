package com.offlinewallet.payment.ble

import android.content.Context
import java.lang.ref.WeakReference

object BLEManagerSingleton {
    private var instance: BLEManager? = null
    
    fun init(context: Context): BLEManager {
        if (instance == null) {
            instance = BLEManager(context.applicationContext)
        }
        return instance!!
    }
    
    fun getInstance(): BLEManager {
        return instance ?: throw IllegalStateException("BLEManager not initialized. Call init() first.")
    }
    
    fun clear() {
        instance?.stop()
        instance = null
    }
}
