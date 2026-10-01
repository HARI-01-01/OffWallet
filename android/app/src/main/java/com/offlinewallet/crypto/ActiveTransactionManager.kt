package com.offlinewallet.crypto

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Manages in-progress transactions to ensure crash recovery.
 */
class ActiveTransactionManager(context: Context) {
    private val db = SimpleDatabase.getInstance(context)

    enum class State {
        RESERVED, M1_SENT, M2_RECEIVED, SAS_VERIFIED, M3_SENT, M4_RECEIVED, COMPLETED, FAILED
    }

    suspend fun create(
        localId: String,
        payerId: String,
        payeeId: String,
        amount: Long,
        reservedAmount: Long
    ) = withContext(Dispatchers.IO) {
        val values = ContentValues().apply {
            put("local_id", localId)
            put("state", State.RESERVED.name)
            put("payer_id", payerId)
            put("payee_id", payeeId)
            put("amount", amount)
            put("reserved_amount", reservedAmount)
            put("created_at", System.currentTimeMillis())
            put("updated_at", System.currentTimeMillis())
        }
        db.insertActiveTransaction(values)
    }

    suspend fun updateState(localId: String, state: State) = withContext(Dispatchers.IO) {
        val values = ContentValues().apply {
            put("state", state.name)
            put("updated_at", System.currentTimeMillis())
        }
        db.updateActiveTransaction(localId, values)
    }

    suspend fun updateBlockData(localId: String, blockData: ByteArray, sig: ByteArray) = withContext(Dispatchers.IO) {
        val values = ContentValues().apply {
            put("block_data", blockData)
            put("payer_sig", sig)
            put("updated_at", System.currentTimeMillis())
        }
        db.updateActiveTransaction(localId, values)
    }

    suspend fun get(localId: String): TransactionState? = withContext(Dispatchers.IO) {
        val cursor = db.getActiveTransaction(localId)
        cursor?.use {
            if (it.moveToFirst()) {
                return@withContext TransactionState(
                    localId = it.getString(it.getColumnIndexOrThrow("local_id")),
                    state = State.valueOf(it.getString(it.getColumnIndexOrThrow("state"))),
                    payerId = it.getString(it.getColumnIndexOrThrow("payer_id")),
                    payeeId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                    amount = it.getLong(it.getColumnIndexOrThrow("amount")),
                    reservedAmount = it.getLong(it.getColumnIndexOrThrow("reserved_amount")),
                    blockData = it.getBlob(it.getColumnIndexOrThrow("block_data")),
                    payerSig = it.getBlob(it.getColumnIndexOrThrow("payer_sig"))
                )
            }
        }
        null
    }

    suspend fun delete(localId: String) = withContext(Dispatchers.IO) {
        db.deleteActiveTransaction(localId)
    }

    suspend fun getExpired(timeoutMs: Long): List<TransactionState> = withContext(Dispatchers.IO) {
        val cursor = db.getExpiredActiveTransactions(System.currentTimeMillis() - timeoutMs)
        val result = mutableListOf<TransactionState>()
        cursor?.use {
            while (it.moveToNext()) {
                result.add(TransactionState(
                    localId = it.getString(it.getColumnIndexOrThrow("local_id")),
                    state = State.valueOf(it.getString(it.getColumnIndexOrThrow("state"))),
                    payerId = it.getString(it.getColumnIndexOrThrow("payer_id")),
                    payeeId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                    amount = it.getLong(it.getColumnIndexOrThrow("amount")),
                    reservedAmount = it.getLong(it.getColumnIndexOrThrow("reserved_amount")),
                    blockData = it.getBlob(it.getColumnIndexOrThrow("block_data")),
                    payerSig = it.getBlob(it.getColumnIndexOrThrow("payer_sig"))
                ))
            }
        }
        result
    }

    suspend fun getAllActive(): List<TransactionState> = withContext(Dispatchers.IO) {
        val cursor = db.getAllActiveTransactions()
        val result = mutableListOf<TransactionState>()
        cursor?.use {
            while (it.moveToNext()) {
                result.add(TransactionState(
                    localId = it.getString(it.getColumnIndexOrThrow("local_id")),
                    state = State.valueOf(it.getString(it.getColumnIndexOrThrow("state"))),
                    payerId = it.getString(it.getColumnIndexOrThrow("payer_id")),
                    payeeId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                    amount = it.getLong(it.getColumnIndexOrThrow("amount")),
                    reservedAmount = it.getLong(it.getColumnIndexOrThrow("reserved_amount")),
                    blockData = it.getBlob(it.getColumnIndexOrThrow("block_data")),
                    payerSig = it.getBlob(it.getColumnIndexOrThrow("payer_sig"))
                ))
            }
        }
        result
    }

    data class TransactionState(
        val localId: String,
        val state: State,
        val payerId: String,
        val payeeId: String,
        val amount: Long,
        val reservedAmount: Long,
        val blockData: ByteArray? = null,
        val payerSig: ByteArray? = null
    )
}
