package com.offlinewallet

import android.content.Context
import android.util.Log
import com.offlinewallet.firebase.FirebaseService
import com.offlinewallet.crypto.*
import com.offlinewallet.models.PassEnvelope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers

class SyncManager(private val context: Context) {
    private val firebase = FirebaseService(context)
    private val localDb = SimpleDatabase.getInstance(context)

    private val _syncStatus = MutableStateFlow(SyncStatus.IDLE)
    val syncStatus: StateFlow<SyncStatus> = _syncStatus

    enum class SyncStatus {
        IDLE, SYNCING, SYNCED, ERROR
    }

    suspend fun syncAll(walletId: String): SyncResult {
        _syncStatus.value = SyncStatus.SYNCING
        TelemetryManager.logEvent(context, "SYNC_START", mapOf("wallet_id" to walletId))

        return try {
            // 1. Get local pending transactions
            val localPending = getLocalPendingTransactions()
            
            // 2. Refresh Security Pass (Limits & Authorization)
            refreshSecurityPass(walletId)

            // 3. Upload to Firebase
            var synced = 0
            var failed = 0

            for (tx in localPending) {
                val result = firebase.addTransaction(tx)
                if (result.isSuccess) {
                    // Mark as synced locally
                    localDb.updateQueueStatus(tx["local_id"] as String, "SYNCED")
                    synced++
                } else {
                    failed++
                }
            }

            // 3. Get remote transactions and merge
            val remoteResult = firebase.getPendingTransactions(walletId)
            if (remoteResult.isSuccess) {
                val remoteTx = remoteResult.getOrNull() ?: emptyList()
                for (tx in remoteTx) {
                    val localId = tx["local_id"] as? String ?: ""
                    if (localId.isNotEmpty() && !localTransactionExists(localId)) {
                        saveLocalTransaction(tx)
                    }
                }
            }

            _syncStatus.value = SyncStatus.SYNCED
            SyncResult(synced = synced, failed = failed)

        } catch (e: Exception) {
            _syncStatus.value = SyncStatus.ERROR
            SyncResult(synced = 0, failed = 0, error = e.message)
        }
    }

    private fun getLocalPendingTransactions(): List<Map<String, Any>> {
        val cursor = localDb.getPendingTransactions()
        val transactions = mutableListOf<Map<String, Any>>()
        cursor?.use {
            while (it.moveToNext()) {
                val tx = mutableMapOf<String, Any>()
                tx["local_id"] = it.getString(it.getColumnIndexOrThrow("local_id"))
                tx["amount"] = it.getInt(it.getColumnIndexOrThrow("amount"))
                tx["payer_id"] = it.getString(it.getColumnIndexOrThrow("payer_id"))
                tx["payee_id"] = it.getString(it.getColumnIndexOrThrow("payee_id"))
                tx["counter"] = it.getInt(it.getColumnIndexOrThrow("counter"))
                tx["timestamp"] = it.getLong(it.getColumnIndexOrThrow("timestamp"))
                
                val pSig = it.getBlob(it.getColumnIndexOrThrow("payer_signature"))
                tx["payer_signature"] = android.util.Base64.encodeToString(pSig, android.util.Base64.DEFAULT)
                
                val paySig = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                if (paySig != null) {
                    tx["payee_signature"] = android.util.Base64.encodeToString(paySig, android.util.Base64.DEFAULT)
                }
                
                tx["status"] = it.getString(it.getColumnIndexOrThrow("status"))
                transactions.add(tx)
            }
        }
        return transactions
    }

    private fun localTransactionExists(localId: String): Boolean {
        val cursor = localDb.getTransaction(localId)
        val exists = cursor?.use { it.moveToFirst() } ?: false
        return exists
    }

    private fun saveLocalTransaction(tx: Map<String, Any>) {
        val localId = tx["local_id"] as? String ?: return
        val amount = (tx["amount"] as? Number)?.toInt() ?: 0
        val payerId = tx["payer_id"] as? String ?: ""
        val payeeId = tx["payee_id"] as? String ?: ""
        val counter = (tx["counter"] as? Number)?.toInt() ?: 0
        val timestamp = (tx["timestamp"] as? Number)?.toLong() ?: 0
        
        val payerSigStr = tx["payer_signature"] as? String ?: ""
        val payerSig = android.util.Base64.decode(payerSigStr, android.util.Base64.DEFAULT)
        
        val payeeSigStr = tx["payee_signature"] as? String ?: ""
        val payeeSig = if (payeeSigStr.isNotEmpty()) {
            android.util.Base64.decode(payeeSigStr, android.util.Base64.DEFAULT)
        } else {
            ByteArray(0)
        }

        localDb.insertTransaction(
            localId = localId,
            amount = amount,
            payerId = payerId,
            payeeId = payeeId,
            counter = counter.toLong(),
            timestamp = timestamp,
            payerSignature = payerSig,
            payeeSignature = payeeSig
        )
    }

    private suspend fun refreshSecurityPass(walletId: String) = withContext(Dispatchers.IO) {
        try {
            val networkManager = NetworkManager(context, Config.BASE_URL)
            val pubKey = SecureStorage.getPublicKey() ?: return@withContext
            
            // Generate nonce for integrity check
            val nonce = ShadowProtocol.sha256(
                android.util.Base64.decode(pubKey, android.util.Base64.NO_WRAP) + 
                walletId.toByteArray(Charsets.UTF_8) + 
                "sync_refresh".toByteArray()
            )
            
            val integrityToken = IntegrityManager.fetchIntegrityToken(context, nonce)
                ?: return@withContext // Mandatory integrity
            
            val res = networkManager.refreshPass(integrityToken)
            
            if (res.isSuccess) {
                val passEnv = res.getOrNull()!!
                SecureStorage.savePass(passEnv)
                Log.d("SyncManager", "✅ Security Pass refreshed. New limit: ${passEnv.pass.aggregateCapP}")
            }
        } catch (e: Exception) {
            Log.e("SyncManager", "Failed to refresh pass during sync", e)
        }
    }
}

data class SyncResult(
    val synced: Int,
    val failed: Int,
    val error: String? = null
)
