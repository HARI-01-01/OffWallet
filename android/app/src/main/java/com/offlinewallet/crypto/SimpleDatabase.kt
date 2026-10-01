package com.offlinewallet.crypto

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class SimpleDatabase private constructor(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "offline_wallet.db"
        private const val DATABASE_VERSION = 14
        
        @Volatile
        private var instance: SimpleDatabase? = null

        fun getInstance(context: Context): SimpleDatabase {
            return instance ?: synchronized(this) {
                instance ?: SimpleDatabase(context.applicationContext).also { instance = it }
            }
        }

        fun resetInstance() {
            synchronized(this) {
                instance?.close()
                instance = null
            }
        }
    }

    override fun onCreate(db: SQLiteDatabase) {
        android.util.Log.d("SimpleDatabase", "onCreate called (v14)")
        createLegacyTables(db)
        createSecureTables(db)
        createActiveTransactionsTable(db)
    }

    override fun onOpen(db: SQLiteDatabase) {
        super.onOpen(db)
        // PRD-FIX: Robust schema enforcement.
        ensureColumnExists(db, "blockchain", "payee_signature", "BLOB")
        ensureColumnExists(db, "blockchain", "block_data", "BLOB")
        ensureColumnExists(db, "blockchain", "node_type", "TEXT")
        ensureColumnExists(db, "blockchain", "payee_counter", "INTEGER")
        ensureColumnExists(db, "blockchain", "payee_prev_hash", "BLOB")
        
        ensureColumnExists(db, "active_transactions", "payee_signature", "BLOB")
        ensureColumnExists(db, "active_transactions", "block_data", "BLOB")
        ensureColumnExists(db, "active_transactions", "payee_counter", "INTEGER")
        ensureColumnExists(db, "active_transactions", "payee_prev_hash", "BLOB")
        
        // Data Migration
        db.execSQL("UPDATE blockchain SET node_type = 'GENESIS' WHERE counter = 0 AND node_type IS NULL")
        db.execSQL("UPDATE blockchain SET node_type = 'TOPUP' WHERE payer_id = 'SERVER' AND node_type IS NULL")
        // WP-FIX: DO NOT mark system blocks as synced automatically. 
        // Let the SyncWorker upload them so the server's sync_state head advances correctly.
    }

    private fun ensureColumnExists(db: SQLiteDatabase, table: String, column: String, type: String) {
        try {
            val cursor = db.rawQuery("PRAGMA table_info($table)", null)
            var exists = false
            cursor.use {
                while (it.moveToNext()) {
                    val name = it.getString(it.getColumnIndexOrThrow("name"))
                    if (name == column) {
                        exists = true
                        break
                    }
                }
            }
            if (!exists) {
                db.execSQL("ALTER TABLE $table ADD COLUMN $column $type")
            }
        } catch (_: Exception) {}
    }

    private fun createActiveTransactionsTable(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS active_transactions (
                local_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                payer_id TEXT,
                payee_id TEXT,
                amount INTEGER,
                block_data BLOB,
                payer_sig BLOB,
                payee_sig BLOB,
                payee_signature BLOB,
                payee_counter INTEGER,
                payee_prev_hash BLOB,
                reserved_amount INTEGER,
                created_at INTEGER,
                updated_at INTEGER,
                expiry_at INTEGER,
                retry_count INTEGER DEFAULT 0
            )
        """)
    }

    private fun createLegacyTables(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS offline_bucket (
                wallet_id TEXT PRIMARY KEY,
                balance INTEGER DEFAULT 0,
                reserved_balance INTEGER DEFAULT 0,
                counter INTEGER DEFAULT 0,
                encrypted_balance BLOB,
                encrypted_counter BLOB,
                server_signature BLOB,
                created_at INTEGER,
                updated_at INTEGER,
                expires_at INTEGER,
                last_synced INTEGER,
                status TEXT DEFAULT 'ACTIVE',
                freeze_reason TEXT
            )
        """)

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS pending_queue (
                local_id TEXT PRIMARY KEY,
                amount INTEGER NOT NULL,
                payer_id TEXT NOT NULL,
                payee_id TEXT NOT NULL,
                counter INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                payer_signature BLOB NOT NULL,
                payee_signature BLOB,
                status TEXT DEFAULT 'QUEUED',
                method TEXT DEFAULT 'ONLINE',
                retry_count INTEGER DEFAULT 0,
                my_pin TEXT,
                peer_pin TEXT,
                encrypted_data BLOB,
                encryption_iv BLOB,
                created_at INTEGER,
                updated_at INTEGER,
                synced_at INTEGER
            )
        """)
        
        db.execSQL("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_transaction 
            ON pending_queue (payer_id, payee_id, amount, local_id)
        """)
        
        db.execSQL("""
            CREATE INDEX IF NOT EXISTS idx_transaction_lookup 
            ON pending_queue (payer_id, payee_id, amount, status)
        """)
    }

    private fun createSecureTables(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS blockchain (
                block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                nonce_value TEXT NOT NULL,
                prev_block_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL UNIQUE,
                counter INTEGER NOT NULL,
                balance_before INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                payer_id TEXT NOT NULL,
                payee_id TEXT NOT NULL,
                memo TEXT,
                timestamp INTEGER NOT NULL,
                signature BLOB NOT NULL,
                payee_signature BLOB,
                block_data BLOB,
                payee_counter INTEGER,
                payee_prev_hash BLOB,
                node_type TEXT,
                synced BOOLEAN DEFAULT 0,
                sync_timestamp INTEGER,
                encrypted_data BLOB,
                encryption_iv BLOB,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS nonce_registry (
                nonce_id TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                nonce_value TEXT NOT NULL UNIQUE,
                sequence_number INTEGER NOT NULL,
                max_offline_txs INTEGER DEFAULT 10,
                max_offline_balance INTEGER DEFAULT 100000,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                server_signature BLOB NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                used_counter INTEGER DEFAULT 0
            )
        """)

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                block_hash TEXT,
                timestamp INTEGER DEFAULT (strftime('%s', 'now')),
                device_id TEXT NOT NULL,
                app_hash TEXT NOT NULL
            )
        """)

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS wallet_state (
                wallet_id TEXT PRIMARY KEY,
                current_balance INTEGER NOT NULL DEFAULT 0,
                total_counter INTEGER NOT NULL DEFAULT 0,
                last_block_hash TEXT,
                last_sync_timestamp INTEGER,
                status TEXT DEFAULT 'ACTIVE',
                freeze_reason TEXT,
                frozen_at INTEGER,
                updated_at INTEGER
            )
        """)

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_blockchain_wallet ON blockchain(wallet_id)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_blockchain_hash ON blockchain(block_hash)")
        db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS idx_blockchain_counter ON blockchain(wallet_id, counter)")

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS telemetry_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_data TEXT,
                local_id TEXT,
                timestamp INTEGER DEFAULT (strftime('%s', 'now')),
                synced BOOLEAN DEFAULT 0
            )
        """)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            try { db.execSQL("ALTER TABLE pending_queue ADD COLUMN method TEXT DEFAULT 'ONLINE'") } catch (_: Exception) {}
        }
        if (oldVersion < 3) {
            try {
                db.execSQL("ALTER TABLE pending_queue ADD COLUMN my_pin TEXT")
                db.execSQL("ALTER TABLE pending_queue ADD COLUMN peer_pin TEXT")
            } catch (_: Exception) {}
        }
        if (oldVersion < 4) { createSecureTables(db) }
        if (oldVersion < 5) {
            try {
                db.execSQL("ALTER TABLE blockchain ADD COLUMN encrypted_data BLOB")
                db.execSQL("ALTER TABLE blockchain ADD COLUMN encryption_iv BLOB")
                db.execSQL("ALTER TABLE pending_queue ADD COLUMN encrypted_data BLOB")
                db.execSQL("ALTER TABLE pending_queue ADD COLUMN encryption_iv BLOB")
                db.execSQL("CREATE TABLE IF NOT EXISTS telemetry_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, event_data TEXT, timestamp INTEGER DEFAULT (strftime('%s', 'now')), synced BOOLEAN DEFAULT 0)")
            } catch (_: Exception) {}
        }
        if (oldVersion < 6) { try { db.execSQL("ALTER TABLE offline_bucket ADD COLUMN reserved_balance INTEGER DEFAULT 0") } catch (_: Exception) {} }
        if (oldVersion < 7) { try { db.execSQL("ALTER TABLE offline_bucket ADD COLUMN freeze_reason TEXT") } catch (_: Exception) {} }
        if (oldVersion < 8) { createActiveTransactionsTable(db) }
        if (oldVersion < 9) { try { db.execSQL("ALTER TABLE wallet_state ADD COLUMN updated_at INTEGER") } catch (_: Exception) {} }
        
        // WP-FIX: Cleaned up redundant ALTER TABLE calls for version 10-13 as they are now in base schema
        if (oldVersion < 14) {
            ensureColumnExists(db, "blockchain", "node_type", "TEXT")
            ensureColumnExists(db, "blockchain", "payee_signature", "BLOB")
            ensureColumnExists(db, "blockchain", "block_data", "BLOB")
            ensureColumnExists(db, "blockchain", "payee_counter", "INTEGER")
            ensureColumnExists(db, "blockchain", "payee_prev_hash", "BLOB")
            
            ensureColumnExists(db, "active_transactions", "payee_signature", "BLOB")
            ensureColumnExists(db, "active_transactions", "block_data", "BLOB")
            ensureColumnExists(db, "active_transactions", "payee_counter", "INTEGER")
            ensureColumnExists(db, "active_transactions", "payee_prev_hash", "BLOB")
        }
    }

    // ---------- Bucket Operations ----------

    fun getBucket(walletId: String): Cursor? {
        val db = readableDatabase
        return db.query("offline_bucket", null, "wallet_id = ?", arrayOf(walletId), null, null, null)
    }

    fun insertBucket(walletId: String, balance: Long, counter: Long, encryptedBalance: ByteArray, encryptedCounter: ByteArray, serverSignature: ByteArray, expiresAt: Long): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("wallet_id", walletId); put("balance", balance); put("counter", counter)
            put("encrypted_balance", encryptedBalance); put("encrypted_counter", encryptedCounter)
            put("server_signature", serverSignature); put("expires_at", expiresAt)
            put("created_at", System.currentTimeMillis() / 1000); put("updated_at", System.currentTimeMillis() / 1000)
            put("status", "ACTIVE")
        }
        return db.insertWithOnConflict("offline_bucket", null, values, SQLiteDatabase.CONFLICT_REPLACE) != -1L
    }

    fun updateBucket(walletId: String, balance: Long, counter: Long): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply { put("balance", balance); put("counter", counter); put("updated_at", System.currentTimeMillis() / 1000) }
        return db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId)) > 0
    }

    fun updateCounter(walletId: String, newCounter: Long): Int {
        val db = writableDatabase
        return db.compileStatement("UPDATE offline_bucket SET counter = ?, updated_at = ? WHERE wallet_id = ? AND counter = ?").apply {
            bindLong(1, newCounter); bindLong(2, System.currentTimeMillis() / 1000); bindString(3, walletId); bindLong(4, newCounter - 1)
        }.executeUpdateDelete()
    }

    fun updateStatus(walletId: String, status: String): Int {
        val db = writableDatabase
        val values = ContentValues().apply { put("status", status); if (status == "ACTIVE") putNull("freeze_reason"); put("updated_at", System.currentTimeMillis() / 1000) }
        return db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
    }

    fun reserveFunds(walletId: String, amount: Long): Boolean {
        val db = writableDatabase
        db.beginTransaction()
        try {
            val cursor = db.query("offline_bucket", arrayOf("balance", "reserved_balance"), "wallet_id = ?", arrayOf(walletId), null, null, null)
            if (cursor.moveToFirst()) {
                val balance = cursor.getLong(0); val reserved = cursor.getLong(1)
                if (balance >= amount) {
                    val values = ContentValues().apply { put("balance", balance - amount); put("reserved_balance", reserved + amount); put("updated_at", System.currentTimeMillis() / 1000) }
                    db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
                    db.setTransactionSuccessful(); cursor.close(); return true
                }
            }
            cursor.close(); return false
        } finally { db.endTransaction() }
    }

    fun commitReserved(walletId: String, amount: Long): Boolean {
        val db = writableDatabase
        db.beginTransaction()
        try {
            val cursor = db.query("offline_bucket", arrayOf("reserved_balance"), "wallet_id = ?", arrayOf(walletId), null, null, null)
            if (cursor.moveToFirst()) {
                val reserved = cursor.getLong(0)
                if (reserved >= amount) {
                    val values = ContentValues().apply { put("reserved_balance", reserved - amount); put("updated_at", System.currentTimeMillis() / 1000) }
                    db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
                    db.setTransactionSuccessful(); cursor.close(); return true
                }
            }
            cursor.close(); return false
        } finally { db.endTransaction() }
    }

    fun rollbackReserved(walletId: String, amount: Long): Boolean {
        val db = writableDatabase
        db.beginTransaction()
        try {
            val cursor = db.query("offline_bucket", arrayOf("balance", "reserved_balance"), "wallet_id = ?", arrayOf(walletId), null, null, null)
            if (cursor.moveToFirst()) {
                val balance = cursor.getLong(0); val reserved = cursor.getLong(1)
                if (reserved >= amount) {
                    val values = ContentValues().apply { put("balance", balance + amount); put("reserved_balance", reserved - amount); put("updated_at", System.currentTimeMillis() / 1000) }
                    db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
                    db.setTransactionSuccessful(); cursor.close(); return true
                }
            }
            cursor.close(); return false
        } finally { db.endTransaction() }
    }

    // ---------- Queue Operations ----------

    fun insertTransaction(localId: String, amount: Int, payerId: String, payeeId: String, counter: Long, timestamp: Long, payerSignature: ByteArray, payeeSignature: ByteArray, method: String = "ONLINE", encryptedData: ByteArray? = null, encryptionIv: ByteArray? = null, status: String = "QUEUED"): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("local_id", localId); put("amount", amount); put("payer_id", payerId); put("payee_id", payeeId)
            put("counter", counter); put("timestamp", timestamp); put("payer_signature", payerSignature); put("payee_signature", payeeSignature)
            put("status", status); put("method", method); put("encrypted_data", encryptedData); put("encryption_iv", encryptionIv)
            put("retry_count", 0); put("created_at", System.currentTimeMillis() / 1000); put("updated_at", System.currentTimeMillis() / 1000)
        }
        return db.insertWithOnConflict("pending_queue", null, values, SQLiteDatabase.CONFLICT_REPLACE) != -1L
    }

    fun getPendingTransactions(limit: Int = 100): Cursor? {
        val db = readableDatabase
        return db.query("pending_queue", null, "status = ?", arrayOf("QUEUED"), null, null, "created_at ASC", limit.toString())
    }

    fun getTransaction(localId: String): Cursor? {
        val db = readableDatabase
        return db.query("pending_queue", null, "local_id = ?", arrayOf(localId), null, null, null)
    }

    fun getTransactionByDetails(payerId: String, payeeId: String, amount: Int): Cursor? {
        val db = readableDatabase
        return db.query("pending_queue", null, "payer_id = ? AND payee_id = ? AND amount = ?", arrayOf(payerId, payeeId, amount.toString()), null, null, null)
    }

    fun updateQueueStatus(localId: String, status: String): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply { put("status", status); put("updated_at", System.currentTimeMillis() / 1000) }
        return db.update("pending_queue", values, "local_id = ?", arrayOf(localId)) > 0
    }

    fun updateQueueStatusWithRetry(localId: String, status: String, retryCount: Int): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply { put("status", status); put("retry_count", retryCount); put("updated_at", System.currentTimeMillis() / 1000) }
        return db.update("pending_queue", values, "local_id = ?", arrayOf(localId)) > 0
    }

    fun deleteTransaction(localId: String): Boolean {
        val db = writableDatabase
        return db.delete("pending_queue", "local_id = ?", arrayOf(localId)) > 0
    }

    // ---------- Active Transaction Operations ----------

    fun insertActiveTransaction(data: ContentValues): Boolean {
        val db = writableDatabase
        return db.insertWithOnConflict("active_transactions", null, data, SQLiteDatabase.CONFLICT_REPLACE) != -1L
    }

    fun updateActiveTransaction(localId: String, data: ContentValues): Boolean {
        val db = writableDatabase
        return db.update("active_transactions", data, "local_id = ?", arrayOf(localId)) > 0
    }

    fun getActiveTransaction(localId: String): Cursor? {
        val db = readableDatabase
        return db.query("active_transactions", null, "local_id = ?", arrayOf(localId), null, null, null)
    }

    fun getExpiredActiveTransactions(expiryTime: Long): Cursor? {
        val db = readableDatabase
        return db.query("active_transactions", null, "created_at < ?", arrayOf(expiryTime.toString()), null, null, null)
    }

    fun getAllActiveTransactions(): Cursor? {
        val db = readableDatabase
        return db.query("active_transactions", null, null, null, null, null, "created_at DESC")
    }

    fun deleteActiveTransaction(localId: String): Boolean {
        val db = writableDatabase
        return db.delete("active_transactions", "local_id = ?", arrayOf(localId)) > 0
    }

    fun getQueueCount(status: String? = null): Int {
        val db = readableDatabase
        val cursor = if (status != null) {
            db.query("pending_queue", arrayOf("COUNT(*)"), "status = ?", arrayOf(status), null, null, null)
        } else {
            db.query("pending_queue", arrayOf("COUNT(*)"), null, null, null, null, null)
        }
        return cursor.use { if (it.moveToFirst()) it.getInt(0) else 0 }
    }

    override fun close() { super.close() }
}
