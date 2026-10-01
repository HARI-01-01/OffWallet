package com.offlinewallet.payment.smart

import android.content.Context
import android.util.Log
import com.offlinewallet.NetworkManager
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.*
import com.offlinewallet.payment.SMSPaymentHandler
import com.offlinewallet.payment.ble.BLEManager
import com.offlinewallet.payment.ble.BLEManagerSingleton
import com.offlinewallet.payment.ble.BLEPaymentFlow
import kotlinx.coroutines.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap

class SmartPayManager(
    private val context: Context,
    private val networkManager: NetworkManager
) {
    private val auditor = ConnectivityAuditor(context, networkManager)
    private val queueManager = QueueManager(context)

    companion object {
        // Double-spending protection: cache recent payments for 1 second
        private val recentPayments = ConcurrentHashMap<String, Long>()
        private const val DUPLICATE_WINDOW_MS = 1000L
    }

    suspend fun initiatePayment(
        payeeId: String,
        amount: Int,
        memo: String? = null,
        preferredMethod: ConnectivityAuditor.ConnectionMethod = ConnectivityAuditor.ConnectionMethod.NONE
    ): PaymentResult = withContext(Dispatchers.IO) {
        val payerId = SecureStorage.getWalletId() ?: return@withContext PaymentResult.Error("No wallet found")
        
        // 1. Double-spending check
        val paymentKey = "$payerId|$payeeId|$amount"
        val lastTime = recentPayments[paymentKey] ?: 0L
        val now = System.currentTimeMillis()
        if (now - lastTime < DUPLICATE_WINDOW_MS) {
            return@withContext PaymentResult.Error("Duplicate payment detected. Please wait.")
        }
        recentPayments[paymentKey] = now
        cleanupRecentPayments()

        // 2. Determine method priority
        val methods = if (preferredMethod != ConnectivityAuditor.ConnectionMethod.NONE) {
            listOf(preferredMethod)
        } else {
            // LLD Solution A: Dynamic Priority List
            listOf(
                ConnectivityAuditor.ConnectionMethod.ONLINE,
                ConnectivityAuditor.ConnectionMethod.BLE,
                ConnectivityAuditor.ConnectionMethod.SMS
            )
        }

        // 3. Sequential Execution with Fallback
        val errors = mutableListOf<String>()
        for (method in methods) {
            val availability = checkHardwareAvailability(method)
            if (!availability.first) {
                if (methods.size == 1) return@withContext PaymentResult.Error(availability.second)
                errors.add("${method.name}: ${availability.second}")
                continue
            }

            Log.i("Routing", "Attempting payment via $method")
            val result = try {
                when (method) {
                    ConnectivityAuditor.ConnectionMethod.ONLINE -> executeOnlinePayment(payerId, payeeId, amount, memo)
                    ConnectivityAuditor.ConnectionMethod.BLE -> executeBLEPayment(payerId, payeeId, amount)
                    ConnectivityAuditor.ConnectionMethod.SMS -> executeSMSPayment(payerId, payeeId, amount)
                    else -> PaymentResult.Error("Unsupported method")
                }
            } catch (e: Exception) {
                PaymentResult.Error(e.message ?: "Unknown error")
            }

            // If success or ActionRequired (handover to UI), return.
            // If hard Error, try next method in loop.
            if (result !is PaymentResult.Error) return@withContext result
            
            val msg = (result as PaymentResult.Error).message
            Log.w("Routing", "Method $method failed: $msg. Falling back...")
            errors.add("${method.name}: $msg")
        }

        return@withContext PaymentResult.Error("Payment Failed. Reasons:\n" + errors.joinToString("\n"))
    }

    private fun checkHardwareAvailability(method: ConnectivityAuditor.ConnectionMethod): Pair<Boolean, String> {
        return when (method) {
            ConnectivityAuditor.ConnectionMethod.ONLINE -> Pair(true, "")
            ConnectivityAuditor.ConnectionMethod.BLE -> {
                val adapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter()
                if (adapter == null) Pair(false, "Device has no Bluetooth hardware")
                else if (!adapter.isEnabled) Pair(false, "Bluetooth is turned off")
                else Pair(true, "")
            }
            ConnectivityAuditor.ConnectionMethod.SMS -> {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as android.telephony.TelephonyManager
                if (tm.simState != android.telephony.TelephonyManager.SIM_STATE_READY) Pair(false, "No SIM card or cellular signal")
                else Pair(true, "")
            }
            else -> Pair(false, "Method not supported")
        }
    }

    private suspend fun executeOnlinePayment(payerId: String, payeeId: String, amount: Int, memo: String?): PaymentResult {
        // Online payment is routed back to MainActivity to show the progress dialog
        return PaymentResult.ActionRequired("ONLINE_PAY", payeeId, amount)
    }


    private suspend fun executeBLEPayment(payerId: String, payeeId: String, amount: Int): PaymentResult {
        return try {
            BLEManagerSingleton.init(context)
            val flow = BLEPaymentFlow(context)
            
            // Note: In this architecture, the bleId should be passed from the QR scan
            // For background execution, we try to resolve it from the peerId or previous scans
            // For now, we handover to MainActivity if the ID is missing to ensure UI visibility
            
            PaymentResult.ActionRequired("BLE_PAY", payeeId, amount)
        } catch (e: Exception) {
            PaymentResult.Error("BLE setup failed: ${e.message}")
        }
    }

    private suspend fun executeSMSPayment(payerId: String, payeeId: String, amount: Int): PaymentResult {
        return try {
            val aesKeyHex = SecureStorage.getAesKey()
            val privKeyHex = SecureStorage.getPrivateKey()
            
            val aesKey = aesKeyHex?.let { HexUtils.decodeHex(it) }
            val privKey = privKeyHex?.let { HexUtils.decodeHex(it) }
            
            val handler = SMSPaymentHandler(context)
            val result = handler.processPayment(payerId, payeeId, amount, aesKey, privKey)
            
            if (result.success) {
                PaymentResult.Success(result.message, SecureStorage.getBalance())
            } else {
                PaymentResult.Error(result.message)
            }
        } catch (e: Exception) {
            PaymentResult.Error(e.message ?: "SMS initiation failed")
        }
    }

    private fun cleanupRecentPayments() {
        val now = System.currentTimeMillis()
        recentPayments.entries.removeIf { now - it.value > DUPLICATE_WINDOW_MS * 2 }
    }

    sealed class PaymentResult {
        data class Success(val message: String, val newBalance: Long) : PaymentResult()
        data class Error(val message: String) : PaymentResult()
        data class ActionRequired(val action: String, val payeeId: String, val amount: Int) : PaymentResult()
    }
}
