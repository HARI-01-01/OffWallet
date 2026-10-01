package com.offlinewallet.utils

import android.content.Context
import android.content.Intent
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.SimpleDatabase
import com.offlinewallet.ui.auth.LoginActivity

object AppResetUtils {
    /**
     * Wipes all local user data, databases, and keys.
     */
    fun performHardReset(context: Context) {
        // 1. Clear Secure Storage
        SecureStorage.init(context)
        SecureStorage.clear()
        
        // 2. Wipe Databases (File-level deletion to ensure no "ghost blocks")
        try {
            // First, close and reset the database instance
            SimpleDatabase.resetInstance()
            
            val dbName = "offline_wallet.db"
            context.deleteDatabase(dbName)
            // Also delete the WAL/Journal files if they exist
            context.deleteDatabase("$dbName-wal")
            context.deleteDatabase("$dbName-shm")
            android.util.Log.i("AppResetUtils", "Database files deleted successfully.")
        } catch (e: Exception) {
            android.util.Log.e("AppResetUtils", "Failed to delete database files", e)
        }
        
        // 3. Clear Preferences
        context.getSharedPreferences("secure_vault", Context.MODE_PRIVATE).edit().clear().apply()
        context.getSharedPreferences("integrity_prefs", Context.MODE_PRIVATE).edit().clear().apply()
        context.getSharedPreferences("hwm_store", Context.MODE_PRIVATE).edit().clear().apply()
        
        // 4. Redirect to Login
        val intent = Intent(context, LoginActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        context.startActivity(intent)
    }
}
