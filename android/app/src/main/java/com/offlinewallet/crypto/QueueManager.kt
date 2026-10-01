package com.offlinewallet.crypto

import android.content.Context
import android.database.Cursor
import android.util.Log
import com.offlinewallet.models.Transaction
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

class QueueManager(private val context: Context) {
    private val db = SimpleDatabase.getInstance(context)

    companion object {
        const val STATUS_QUEUED = "QUEUED"
        const val STATUS_PROCESSED = "PROCESSED"
        const val STATUS_FAILED = "FAILED_TO_PROCESS"
        const val STATUS_DUPLICATE = "DUPLICATE_DETECTED"
        const val STATUS_PENDING_MUTUAL_PIN = "PENDING_MUTUAL_PIN"
        const val STATUS_SETTLED = "SETTLED"
        const val STATUS_REFUNDED = "REFUNDED"
        const val MAX_RETRIES = 3

        // Static listener list to survive worker-to-activity context changes
        private val listeners = mutableListOf<TransactionListener>()

        fun addListener(listener: TransactionListener) {
            synchronized(listeners) { if (!listeners.contains(listener)) listeners.add(listener) }
        }

        fun removeListener(listener: TransactionListener) {
            synchronized(listeners) { listeners.remove(listener) }
        }

        private fun notifyListeners(action: (TransactionListener) -> Unit) {
            synchronized(listeners) { listeners.forEach { action(it) } }
        }
    }

    interface TransactionListener {
        fun onTransactionAdded(localId: String)
        fun onSyncCompleted()
    }

    suspend fun addTransaction(
        amount: Int,
        payerId: String,
        payeeId: String,
        counter: Long,
        payerSignature: ByteArray,
        payeeSignature: ByteArray = ByteArray(0),
        localId: String = UUID.randomUUID().toString(),
        method: String = "ONLINE",
        status: String? = null,
        encryptedData: ByteArray? = null,
        encryptionIv: ByteArray? = null
    ): String = withContext(Dispatchers.IO) {
        // Check for duplicate before inserting
        val cursor = db.getTransactionByDetails(payerId, payeeId, amount)
        cursor?.use {
            while (it.moveToNext()) {
                val s = it.getString(it.getColumnIndexOrThrow("status"))
                val existingLocalId = it.getString(it.getColumnIndexOrThrow("local_id"))
                if (s == STATUS_PROCESSED || s == STATUS_QUEUED || s == STATUS_PENDING_MUTUAL_PIN) {
                    // Update payee signature if it was missing
                    val existingPayeeSig = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                    if ((existingPayeeSig == null || existingPayeeSig.isEmpty()) && payeeSignature.isNotEmpty()) {
                        db.writableDatabase.execSQL("UPDATE pending_queue SET payee_signature = ? WHERE local_id = ?", arrayOf(payeeSignature, existingLocalId))
                    }
                    Log.w("QueueManager", "Duplicate transaction detected in DB: $existingLocalId")
                    return@withContext existingLocalId 
                }
            }
        }

        val initialStatus = status ?: if (method == "ATOMIC" || method == "ATOMIC_RECEIVE" || method == "BLE_SOCKET") 
            STATUS_PENDING_MUTUAL_PIN else STATUS_QUEUED

        db.insertTransaction(
            localId = localId,
            amount = amount,
            payerId = payerId,
            payeeId = payeeId,
            counter = counter,
            timestamp = System.currentTimeMillis() / 1000,
            payerSignature = payerSignature,
            payeeSignature = payeeSignature,
            method = method,
            encryptedData = encryptedData,
            encryptionIv = encryptionIv,
            status = initialStatus
        )
        
        withContext(Dispatchers.Main) {
            notifyListeners { it.onTransactionAdded(localId) }
        }
        localId
    }

    suspend fun getPendingTransactions(limit: Int = 100): Cursor? = withContext(Dispatchers.IO) {
        db.getPendingTransactions(limit)
    }

    suspend fun getTransaction(localId: String): Cursor? = withContext(Dispatchers.IO) {
        db.getTransaction(localId)
    }

    suspend fun markAsProcessed(localId: String): Boolean = withContext(Dispatchers.IO) {
        val success = db.updateQueueStatus(localId, STATUS_SETTLED) // Keep as SETTLED for 7 days
        if (success) {
            cleanupOldTransactions()
            withContext(Dispatchers.Main) {
                notifyListeners { it.onSyncCompleted() }
            }
        }
        success
    }

    suspend fun markAsRefunded(localId: String): Boolean = withContext(Dispatchers.IO) {
        val success = db.updateQueueStatus(localId, STATUS_REFUNDED)
        if (success) {
            withContext(Dispatchers.Main) {
                notifyListeners { it.onSyncCompleted() }
            }
        }
        success
    }

    private fun cleanupOldTransactions() {
        val sevenDaysAgo = (System.currentTimeMillis() / 1000) - (7 * 24 * 60 * 60)
        db.writableDatabase.delete("pending_queue", "status = ? AND updated_at < ?", arrayOf(STATUS_SETTLED, sevenDaysAgo.toString()))
    }

    suspend fun markAsDuplicate(localId: String): Boolean = withContext(Dispatchers.IO) {
        val success = db.updateQueueStatus(localId, STATUS_DUPLICATE)
        if (success) {
            withContext(Dispatchers.Main) {
                notifyListeners { it.onSyncCompleted() }
            }
        }
        success
    }

    suspend fun updateTransactionPins(localId: String, myPin: String, peerPin: String, status: String = STATUS_PENDING_MUTUAL_PIN): Boolean = withContext(Dispatchers.IO) {
        Log.d("QueueManager", "Updating PINs for $localId: My=$myPin, Peer=$peerPin, Status=$status")
        val values = android.content.ContentValues().apply {
            put("my_pin", myPin)
            put("peer_pin", peerPin)
            put("status", status)
            put("updated_at", System.currentTimeMillis() / 1000)
        }
        val rows = db.writableDatabase.update("pending_queue", values, "local_id = ?", arrayOf(localId))
        rows > 0
    }

    suspend fun getTransactionPins(localId: String): Pair<String?, String?> = withContext(Dispatchers.IO) {
        val cursor = db.getTransaction(localId)
        cursor?.use {
            if (it.moveToFirst()) {
                val myPin = it.getString(it.getColumnIndexOrThrow("my_pin"))
                val peerPin = it.getString(it.getColumnIndexOrThrow("peer_pin"))
                Pair(myPin, peerPin)
            } else {
                Log.w("QueueManager", "Transaction $localId not found in DB")
                Pair(null, null)
            }
        } ?: Pair(null, null)
    }

    suspend fun markAsFailed(localId: String): Boolean = withContext(Dispatchers.IO) {
        val success = db.updateQueueStatus(localId, STATUS_FAILED)
        if (success) {
            withContext(Dispatchers.Main) {
                notifyListeners { it.onSyncCompleted() }
            }
        }
        success
    }

    suspend fun incrementRetry(localId: String): Boolean = withContext(Dispatchers.IO) {
        val cursor = db.getTransaction(localId) ?: return@withContext false
        cursor.use {
            if (!it.moveToFirst()) return@withContext false
            val retryCount = it.getInt(it.getColumnIndexOrThrow("retry_count"))
            val newRetryCount = retryCount + 1
            db.updateQueueStatusWithRetry(localId, STATUS_FAILED, newRetryCount)
        }
    }

    suspend fun shouldRetry(localId: String): Pair<Boolean, String> = withContext(Dispatchers.IO) {
        val cursor = db.getTransaction(localId) ?: return@withContext Pair(false, "Transaction not found")
        cursor.use {
            if (!it.moveToFirst()) return@withContext Pair(false, "Transaction not found")

            val status = it.getString(it.getColumnIndexOrThrow("status"))
            val retryCount = it.getInt(it.getColumnIndexOrThrow("retry_count"))

            if (status != STATUS_FAILED && status != STATUS_QUEUED) {
                return@withContext Pair(false, "Status is $status, not retriable")
            }

            if (retryCount >= MAX_RETRIES) {
                return@withContext Pair(false, "Max retries ($MAX_RETRIES) exceeded")
            }

            Pair(true, "Retry ${retryCount + 1} of $MAX_RETRIES")
        }
    }

    suspend fun getQueueCount(status: String? = null): Int = withContext(Dispatchers.IO) {
        db.getQueueCount(status)
    }

    suspend fun hasPending(): Boolean = withContext(Dispatchers.IO) {
        db.getQueueCount(STATUS_QUEUED) > 0
    }

    suspend fun getPendingIncomingAmount(walletId: String): Long = withContext(Dispatchers.IO) {
        val cursor = db.readableDatabase.query(
            "pending_queue",
            arrayOf("SUM(amount)"),
            "payee_id = ? AND status = ?",
            arrayOf(walletId, STATUS_QUEUED),
            null, null, null
        )
        cursor.use {
            if (it.moveToFirst()) it.getLong(0) else 0L
        }
    }

    suspend fun getUnsettledOutgoingAmount(walletId: String): Long = withContext(Dispatchers.IO) {
        val cursor = db.readableDatabase.query(
            "pending_queue",
            arrayOf("SUM(amount)"),
            "payer_id = ? AND status = ?",
            arrayOf(walletId, STATUS_QUEUED),
            null, null, null
        )
        cursor.use {
            if (it.moveToFirst()) it.getLong(0) else 0L
        }
    }

    suspend fun getAllTransactions(): List<Transaction> = withContext(Dispatchers.IO) {
        val cursor = db.readableDatabase.query("pending_queue", null, null, null, null, null, "created_at DESC")
        val transactions = mutableListOf<Transaction>()
        cursor.use {
            while (it.moveToNext()) {
                transactions.add(
                    Transaction(
                        localId = it.getString(it.getColumnIndexOrThrow("local_id")),
                        amount = it.getInt(it.getColumnIndexOrThrow("amount")),
                        payerId = it.getString(it.getColumnIndexOrThrow("payer_id")),
                        payeeId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                        timestamp = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                        status = it.getString(it.getColumnIndexOrThrow("status")),
                        counter = it.getLong(it.getColumnIndexOrThrow("counter")),
                        method = it.getString(it.getColumnIndexOrThrow("method")),
                        payerSignature = it.getBlob(it.getColumnIndexOrThrow("payer_signature")),
                        payeeSignature = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                    )
                )
            }
        }
        transactions
    }
}
