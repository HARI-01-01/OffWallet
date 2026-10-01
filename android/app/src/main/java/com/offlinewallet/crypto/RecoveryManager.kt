package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Handles recovery of transactions that were interrupted by app crashes or network failures.
 */
class RecoveryManager(private val context: Context) {
    private val atm = ActiveTransactionManager(context)
    private val bucketManager = BucketManager(context)
    private val queueManager = QueueManager(context)

    suspend fun recoverPendingTransactions(bleManager: com.offlinewallet.payment.ble.BLEManager) = withContext(Dispatchers.IO) {
        val allActive = atm.getExpired(0) // Get all for recovery at startup
        for (tx in allActive) {
            when (tx.state) {
                ActiveTransactionManager.State.M3_SENT -> {
                    // Payer sent M3 but never got M4.
                    // We should ideally wait for the next time Alice meets Bob,
                    // or try to find Bob if he's still advertising.
                    Log.i("Recovery", "Transaction ${tx.localId} stuck in M3_SENT. Manual re-sync recommended.")
                }
                ActiveTransactionManager.State.M4_RECEIVED -> {
                    // Alice got the receipt but crashed before finishing up.
                    Log.i("Recovery", "Transaction ${tx.localId} was received but not completed. Finalizing.")
                    queueManager.markAsProcessed(tx.localId)
                    atm.delete(tx.localId)
                }
                ActiveTransactionManager.State.FAILED -> {
                    // Clean up failed transaction reservations
                    bucketManager.rollbackReservedFunds(tx.payerId, tx.reservedAmount)
                    atm.delete(tx.localId)
                }
                else -> {
                    // RESERVED, M1_SENT, M2_RECEIVED - If they stay in this state too long, 
                    // the ReservationCleanupWorker will handle them.
                }
            }
        }
    }
}
