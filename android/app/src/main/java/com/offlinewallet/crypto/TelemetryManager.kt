package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import org.json.JSONObject

/**
 * TelemetryManager - Tracks app lifecycle and security events
 * for "Deep Dive" analytics on the backend dashboard.
 */
object TelemetryManager {
    private const val TAG = "TelemetryManager"

    fun logEvent(context: Context, type: String, data: Map<String, Any> = emptyMap(), localId: String? = null) {
        try {
            val db = SimpleDatabase.getInstance(context)
            val json = JSONObject(data).toString()
            
            val values = android.content.ContentValues().apply {
                put("event_type", type)
                put("event_data", json)
                put("local_id", localId)
                put("timestamp", System.currentTimeMillis() / 1000)
                put("synced", 0)
            }
            
            db.writableDatabase.insert("telemetry_log", null, values)
            Log.d(TAG, "Telemetry Logged: $type (ID: $localId) -> $json")
        } catch (e: Exception) {
            Log.e(TAG, "Telemetry error: ${e.message}")
        }
    }

    fun getUnsyncedLogs(context: Context): List<Map<String, Any>> {
        val db = SimpleDatabase.getInstance(context)
        val cursor = db.readableDatabase.query(
            "telemetry_log",
            null,
            "synced = 0",
            null, null, null,
            "timestamp ASC"
        )
        
        val logs = mutableListOf<Map<String, Any>>()
        cursor.use {
            while (it.moveToNext()) {
                logs.add(mapOf(
                    "log_id" to it.getInt(it.getColumnIndexOrThrow("log_id")),
                    "event_type" to it.getString(it.getColumnIndexOrThrow("event_type")),
                    "event_data" to it.getString(it.getColumnIndexOrThrow("event_data")),
                    "local_id" to (it.getString(it.getColumnIndexOrThrow("local_id")) ?: ""),
                    "timestamp" to it.getLong(it.getColumnIndexOrThrow("timestamp"))
                ))
            }
        }
        return logs
    }

    fun markAsSynced(context: Context, logIds: List<Int>) {
        if (logIds.isEmpty()) return
        val db = SimpleDatabase.getInstance(context)
        val ids = logIds.joinToString(",")
        db.writableDatabase.execSQL("UPDATE telemetry_log SET synced = 1 WHERE log_id IN ($ids)")
    }
}
