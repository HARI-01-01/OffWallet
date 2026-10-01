package com.offlinewallet.payment.smart

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.offlinewallet.crypto.ActiveTransactionManager
import com.offlinewallet.crypto.BucketManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Periodically cleans up orphaned reservations stuck in RESERVED state for too long.
 */
class ReservationCleanupWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    private val atm = ActiveTransactionManager(context)
    private val bucketManager = BucketManager(context)

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            // Find transactions stuck for more than 50 seconds as requested
            val expired = atm.getExpired(50_000L)
            for (tx in expired) {
                if (tx.state == ActiveTransactionManager.State.RESERVED || 
                    tx.state == ActiveTransactionManager.State.M1_SENT ||
                    tx.state == ActiveTransactionManager.State.M2_RECEIVED) {
                    
                    Log.w("Cleanup", "Rolling back orphaned reservation: ${tx.localId}")
                    val success = bucketManager.rollbackReservedFunds(tx.payerId, tx.reservedAmount)
                    if (success) {
                        atm.delete(tx.localId)
                        // Notify user that their funds were restored
                        com.offlinewallet.utils.NotificationHelper.showSyncNotification(
                            applicationContext, 
                            "Incomplete payment of ₹${tx.reservedAmount / 100.0} has been restored to your wallet."
                        )
                    }
                } else if (tx.state == ActiveTransactionManager.State.FAILED) {
                    atm.delete(tx.localId)
                }
            }
            Result.success()
        } catch (e: Exception) {
            Log.e("Cleanup", "Cleanup failed", e)
            Result.retry()
        }
    }
}
