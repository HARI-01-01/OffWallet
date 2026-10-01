package com.offlinewallet.payment.smart

import android.content.Context
import android.util.Log
import androidx.work.*
import com.offlinewallet.NetworkManager
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.HashChainManager
import com.offlinewallet.crypto.HexUtils
import com.offlinewallet.crypto.MicroPaymentHandshake
import com.offlinewallet.crypto.SimpleDatabase
import com.offlinewallet.crypto.ShadowProtocol
import com.offlinewallet.models.OfflineSyncRequest
import com.offlinewallet.models.SyncTransactionItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class SyncWorker(appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            SecureStorage.init(applicationContext)
            if (!SecureStorage.isRegistered()) return@withContext Result.success()

            val walletId = SecureStorage.getWalletId() ?: return@withContext Result.failure()

            // Connectivity check
            val connectivityManager = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val network = connectivityManager.activeNetwork
            val capabilities = connectivityManager.getNetworkCapabilities(network)
            val hasInternet = capabilities?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            
            if (!hasInternet) return@withContext Result.retry()

            val networkManager = NetworkManager(applicationContext, com.offlinewallet.Config.BASE_URL)

            // WP-Sync: Ensure we have a valid Pass (and thus the correct Genesis Epoch) before fetching blocks
            if (SecureStorage.getPass() == null) {
                try {
                    val passIntegrityToken = com.offlinewallet.crypto.IntegrityManager.fetchIntegrityToken(applicationContext, ByteArray(16)) ?: ""
                    networkManager.refreshPass(passIntegrityToken).onSuccess { passEnvelope ->
                        SecureStorage.savePass(passEnvelope)
                    }
                } catch (e: Exception) {
                    Log.w("SyncWorker", "Failed to pre-fetch pass, continuing with stored epoch")
                }
            }

            val pass = SecureStorage.getPass()
            val lastSettled = pass?.pass?.lastSettledCounter ?: 0L
            Log.d("SyncWorker", "Fetching blocks since lastSettledCounter: $lastSettled")
            
            val blocks = HashChainManager.getHistorySince(applicationContext, walletId, lastSettled)
            if (blocks.isEmpty()) return@withContext Result.success()

            val queueManager = com.offlinewallet.crypto.QueueManager(applicationContext)
            val syncItems = blocks.map { block ->
                // Try to find the localId in pending_queue by counter
                var localIdFromQueue: String? = null
                try {
                    val cursor = SimpleDatabase.getInstance(applicationContext).readableDatabase.query(
                        "pending_queue", arrayOf("local_id"), 
                        "payer_id = ? AND counter = ?", 
                        arrayOf(block.walletId, block.counter.toString()), null, null, null
                    )
                    cursor.use { if (it.moveToFirst()) localIdFromQueue = it.getString(0) }
                } catch (_: Exception) {}

                SyncTransactionItem(
                    block = block, 
                    sig = HexUtils.encodeHex(block.payerSig ?: ByteArray(0)),
                    localId = localIdFromQueue ?: "blk_${block.counter}"
                )
            }

            // Issue 4 & 5: Bind Play Integrity to device identity
            // Fix: Use decodeSafe because the stored public key is Base64 (starts with 'MF' in logs)
            val devicePubkey = SecureStorage.getPublicKey()?.let { HexUtils.decodeSafe(it) } ?: ByteArray(32)
            val challenge = ByteArray(16).apply { java.security.SecureRandom().nextBytes(this) }
            val nonce = ShadowProtocol.sha256(devicePubkey + walletId.toByteArray() + challenge)
            val integrityToken = com.offlinewallet.crypto.IntegrityManager.fetchIntegrityToken(applicationContext, nonce)

            if (integrityToken == null) {
                Log.e("SyncWorker", "Integrity token fetch failed. Retrying later...")
                return@withContext Result.retry()
            }

            val request = OfflineSyncRequest(
                walletId = walletId,
                transactions = syncItems,
                integrityToken = integrityToken,
                devicePubKeyHash = HexUtils.encodeHex(ShadowProtocol.sha256(devicePubkey))
            )

            val result = networkManager.syncOffline(request)
            
            if (result.isSuccess) {
                SecureStorage.saveLastSyncTime(System.currentTimeMillis())
                
                val data = result.getOrNull()
                
                val queueManager = com.offlinewallet.crypto.QueueManager(applicationContext)
                val bucketManager = com.offlinewallet.crypto.BucketManager(applicationContext)
                
                data?.results?.forEach { res ->
                    when (res.status) {
                        "SETTLED", "DUPLICATE", "ALREADY_SETTLED" -> {
                            queueManager.markAsProcessed(res.localId)
                            // WP-FIX: Use counter to find the block if localId is auto-generated
                            val counter = try { res.localId.substringAfter("blk_").toLong() } catch(_:Exception) { -1L }
                            val item = syncItems.find { it.localId == res.localId || it.block.counter == counter }
                            
                            // If server provided a missing signature, update the block
                            res.payeeSignature?.let { sigHex ->
                                val block = item?.block
                                if (block != null) {
                                    HashChainManager.updatePayeeSignature(applicationContext, walletId, block.counter, HexUtils.decodeSafe(sigHex))
                                }
                            }
                            if (item != null) {
                                HashChainManager.markAsSynced(applicationContext, walletId, item.block.counter)
                            }
                        }
                        "AUTHORIZED_REFUND" -> {
                            // Find the block to refund
                            val item = syncItems.find { 
                                it.localId == res.localId || 
                                it.block.walletId + it.block.counter == res.localId || 
                                it.block.ts.toString() == res.localId ||
                                HexUtils.encodeHex(ShadowProtocol.sha256(MicroPaymentHandshake.encodeDebitBlockData(it.block))).take(16) == res.localId
                            }
                            if (item != null) {
                                Log.i("SyncWorker", "Reconciling AUTHORIZED_REFUND for Block #${item.block.counter}")
                                HashChainManager.markAsRefunded(applicationContext, walletId, item.block.counter)
                                bucketManager.addFundsDirectly(walletId, item.block.amountP.toInt())
                                queueManager.markAsRefunded(res.localId)
                            }
                        }
                        "PENDING_OTHER_USER" -> {
                            Log.d("SyncWorker", "Tx ${res.localId} is pending Bob's sync. Funds remain reserved.")
                        }
                    }
                }
                
                // ... syncItems mark as synced logic ...
                
                // WP-FIX: Reset Alice's offline budget using fresh pass from server
                // Moved to AFTER marking blocks as synced to avoid Ledger Divergence during BLE handshake
                if (data?.newPass != null) {
                    SecureStorage.savePass(data.newPass)
                    // WP-FIX: Broadcast UI update so limits reset (0/10) on screen immediately
                    val intent = android.content.Intent("com.offlinewallet.SYNC_COMPLETE")
                    applicationContext.sendBroadcast(intent)
                }

                if (data?.message == "RESYNC_REQUIRED") {
                    Log.e("SyncWorker", "Server requested full resync. Chain is divergent.")
                }

                // Show Notification
                val settledCount = data?.results?.count { it.status == "SETTLED" || it.status == "ALREADY_SETTLED" } ?: 0
                val refundCount = data?.results?.count { it.status == "AUTHORIZED_REFUND" } ?: 0
                
                if (settledCount > 0 || refundCount > 0) {
                    val msg = buildString {
                        if (settledCount > 0) append("Confirmed $settledCount payments. ")
                        if (refundCount > 0) append("Refunded $refundCount failed transfers. ")
                    }
                    com.offlinewallet.utils.NotificationHelper.showSyncNotification(applicationContext, msg)
                }
                
                Result.success()
            } else {
                val error = result.exceptionOrNull()
                Log.e("SyncWorker", "Sync failed: ${error?.message}")
                
                // WP-Fix: Do not retry on 404 (Not Found) or 401 (Unauthorized)
                // These are configuration or auth issues, not transient network errors.
                if (error is retrofit2.HttpException) {
                    val code = error.code()
                    if (code == 404 || code == 401 || code == 403) {
                        Log.e("SyncWorker", "Terminal error $code. Giving up.")
                        return@withContext Result.failure()
                    }
                }
                
                if (error?.message?.contains("404") == true) {
                    return@withContext Result.failure()
                }

                Result.retry()
            }
        } catch (e: Exception) {
            Log.e("SyncWorker", "Background sync failed", e)
            Result.retry()
        }
    }

    companion object {
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val request = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "OfflineSyncV1",
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
