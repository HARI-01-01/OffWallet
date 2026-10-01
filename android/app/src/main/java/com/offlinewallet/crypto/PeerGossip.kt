package com.offlinewallet.crypto

import android.content.Context
import android.util.Log

/**
 * Peer Gossip (WP-23)
 * LRU table of (wallet_id, max_counter) to detect forks offline.
 */
object PeerGossip {
    private const val TABLE_NAME = "peer_hwm"
    private const val MAX_ENTRIES = 512

    data class GossipEntry(val walletId: String, val maxCounter: Long)

    fun update(context: Context, walletId: String, counter: Long) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        
        // 1. Check for fork (Invariant: counter must not decrease)
        val cursor = db.query(TABLE_NAME, arrayOf("max_counter"), "wallet_id = ?", arrayOf(walletId), null, null, null)
        cursor.use {
            if (it.moveToFirst()) {
                val existing = it.getLong(0)
                if (counter < existing) {
                    Log.e("PeerGossip", "🚨 FORK DETECTED! Peer $walletId showed counter $existing before, now showing $counter")
                    // Advisory flag, do not freeze here
                }
            }
        }

        // 2. Insert/Update LRU
        val values = android.content.ContentValues().apply {
            put("wallet_id", walletId)
            put("max_counter", counter)
            put("last_seen", System.currentTimeMillis() / 1000)
        }
        db.insertWithOnConflict(TABLE_NAME, null, values, android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE)

        // 3. Bound table size
        db.execSQL("DELETE FROM $TABLE_NAME WHERE wallet_id NOT IN (SELECT wallet_id FROM $TABLE_NAME ORDER BY last_seen DESC LIMIT $MAX_ENTRIES)")
    }

    fun getTop(context: Context, limit: Int = 64): List<GossipEntry> {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val cursor = db.query(TABLE_NAME, arrayOf("wallet_id", "max_counter"), null, null, null, null, "last_seen DESC", limit.toString())
        val result = mutableListOf<GossipEntry>()
        cursor.use {
            while (it.moveToNext()) {
                result.add(GossipEntry(it.getString(0), it.getLong(1)))
            }
        }
        return result
    }
}
