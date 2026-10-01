package com.offlinewallet.payment.smart

import android.content.Context
import android.util.Log
import com.offlinewallet.NetworkManager
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.*
import com.offlinewallet.models.OfflineSyncRequest
import com.offlinewallet.models.SyncTransactionItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ManualSyncManager(private val context: Context) {

    suspend fun performSync(
        onProgress: (SyncSessionProgress) -> Unit
    ) = withContext(Dispatchers.IO) {
        try {
            onProgress(SyncSessionProgress(SyncPhase.PREPARING, "Checking internet connection..."))
            
            val walletId = SecureStorage.getWalletId() ?: throw Exception("Wallet not registered")
            val networkManager = NetworkManager(context, com.offlinewallet.Config.BASE_URL)

            // 1. Refresh security pass to update limits
            onProgress(SyncSessionProgress(SyncPhase.PREPARING, "Refreshing security pass..."))
            val passIntegrityToken = IntegrityManager.fetchIntegrityToken(context, ByteArray(16)) ?: ""
            networkManager.refreshPass(passIntegrityToken).onSuccess {
                SecureStorage.savePass(it)
            }.onFailure { Log.w("ManualSync", "Pass refresh failed, using stored limits") }

            // 2. Fetch Blocks
            onProgress(SyncSessionProgress(SyncPhase.FETCHING, "Reading local hardware ledger..."))
            val blocksWithSigs = HashChainManager.getAllBlocks(context, walletId)
            if (blocksWithSigs.isEmpty()) {
                onProgress(SyncSessionProgress(SyncPhase.SUCCESS, "Ledger is already up to date."))
                return@withContext
            }

            val syncItems = blocksWithSigs.map { (block, sig) ->
                var localIdFromQueue: String? = null
                try {
                    val cursor = SimpleDatabase.getInstance(context).readableDatabase.query(
                        "pending_queue", arrayOf("local_id"), 
                        "payer_id = ? AND counter = ?", 
                        arrayOf(block.walletId, block.counter.toString()), null, null, null
                    )
                    cursor.use { if (it.moveToFirst()) localIdFromQueue = it.getString(0) }
                } catch (_: Exception) {}

                SyncTransactionItem(block, HexUtils.encodeHex(sig), localIdFromQueue)
            }

            // 3. Integrity Token
            onProgress(SyncSessionProgress(SyncPhase.INTEGRITY, "Fetching hardware integrity token..."))
            val devicePubkey = SecureStorage.getPublicKey()?.let { HexUtils.decodeSafe(it) } ?: ByteArray(32)
            val nonce = ShadowProtocol.sha256(devicePubkey + walletId.toByteArray())
            val integrityToken = IntegrityManager.fetchIntegrityToken(context, nonce) ?: throw Exception("Integrity failed")

            // 4. Upload
            onProgress(SyncSessionProgress(SyncPhase.UPLOADING, "Syncing ${syncItems.size} transactions to cloud..."))
            val request = OfflineSyncRequest(
                walletId = walletId,
                transactions = syncItems,
                integrityToken = integrityToken,
                devicePubKeyHash = HexUtils.encodeHex(ShadowProtocol.sha256(devicePubkey))
            )

            val result = networkManager.syncOffline(request)
            if (result.isSuccess) {
                val data = result.getOrNull()!!
                onProgress(SyncSessionProgress(SyncPhase.PROCESSING, "Processing server settlement..."))

                val queueManager = QueueManager(context)
                val bucketManager = BucketManager(context)
                
                var settled = 0
                var refunded = 0
                val resultDetails = mutableListOf<SyncResultDetail>()

                data.results.forEach { res ->
                    // WP-FIX: Robust matching. Try localId first, then counter-based fallback.
                    val localId = res.localId ?: "unknown"
                    val item = syncItems.find { 
                        it.localId == localId || 
                        "blk_${it.block.counter}" == localId 
                    }
                    
                    val amount = item?.block?.amountP ?: 0L
                    val peer = item?.block?.payeeWalletId ?: "Unknown"
                    
                    when (res.status) {
                        "SETTLED", "DUPLICATE", "ALREADY_SETTLED", "DUPLICATE_IN_REQUEST" -> {
                            if (res.localId != null) queueManager.markAsProcessed(res.localId)
                            settled++
                            res.payeeSignature?.let { sigHex ->
                                if (item != null) {
                                    HashChainManager.updatePayeeSignature(context, walletId, item.block.counter, HexUtils.decodeSafe(sigHex))
                                }
                            }
                            if (item != null) {
                                HashChainManager.markAsSynced(context, walletId, item.block.counter)
                            }
                            resultDetails.add(SyncResultDetail(localId, amount, "SETTLED", peer))
                        }
                        "AUTHORIZED_REFUND" -> {
                            if (item != null) {
                                HashChainManager.markAsRefunded(context, walletId, item.block.counter)
                                bucketManager.addFundsDirectly(walletId, item.block.amountP.toInt())
                                if (res.localId != null) queueManager.markAsRefunded(res.localId)
                                refunded++
                                resultDetails.add(SyncResultDetail(localId, amount, "REFUNDED", peer))
                                
                                com.offlinewallet.utils.NotificationHelper.showPaymentNotification(
                                    context, 
                                    "💰 Wallet Refunded", 
                                    "Failed payment of ₹${amount/100.0} was released back to your balance by the server."
                                )
                            }
                        }
                        else -> {
                            resultDetails.add(SyncResultDetail(localId, amount, res.status, peer))
                        }
                    }
                }

                SecureStorage.saveLastSyncTime(System.currentTimeMillis())
                
                // WP-FIX: Notify user of settlement success
                if (settled > 0 || refunded > 0) {
                    val msg = buildString {
                        if (settled > 0) append("Confirmed $settled payments. ")
                        if (refunded > 0) append("Refunded $refunded failed transfers. ")
                    }
                    com.offlinewallet.utils.NotificationHelper.showSyncNotification(context, msg)
                }

                // WP-FIX: Reset Alice's offline budget by using the fresh pass returned by the server
                if (data.newPass != null) {
                    Log.d("ManualSync", "✅ Security Pass Reset from Sync. New anchor: ${data.newPass.pass.lastSettledHead.take(8)}")
                    SecureStorage.savePass(data.newPass)
                } else {
                    // Fallback to manual refresh if not in response
                    onProgress(SyncSessionProgress(SyncPhase.PROCESSING, "Refreshing security parameters..."))
                    try {
                        val finalIntegrityToken = IntegrityManager.fetchIntegrityToken(context, ByteArray(16)) ?: ""
                        networkManager.refreshPass(finalIntegrityToken).onSuccess {
                            SecureStorage.savePass(it)
                        }
                    } catch (_: Exception) {}
                }

                onProgress(SyncSessionProgress(SyncPhase.SUCCESS, "Sync complete!", settledCount = settled, refundCount = refunded, results = resultDetails))
            } else {
                throw result.exceptionOrNull() ?: Exception("Unknown server error")
            }

        } catch (e: Exception) {
            Log.e("ManualSync", "Sync Failed", e)
            onProgress(SyncSessionProgress(SyncPhase.ERROR, e.message ?: "Sync failed", errorCode = "SYNC_FAIL"))
        }
    }
}
