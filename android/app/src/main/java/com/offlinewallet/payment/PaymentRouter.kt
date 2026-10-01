package com.offlinewallet.payment

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.bluetooth.BluetoothAdapter
import android.telephony.TelephonyManager
import android.util.Log
import com.offlinewallet.NetworkManager
import com.offlinewallet.crypto.*
import com.offlinewallet.payment.ble.BLEManager
import com.offlinewallet.payment.ble.BLEManagerSingleton
import com.offlinewallet.payment.ble.BLEPaymentFlow
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

class PaymentRouter(private val context: Context) {
    private val TAG = "PaymentRouter"

    enum class PaymentMethod {
        ONLINE,      // Internet available → Real-time payment
        BLE,         // No internet, BLE available → Bluetooth
        SMS,         // No internet, no BLE → SMS fallback
        FAILED       // No method available
    }

    data class PaymentResult(
        val success: Boolean,
        val method: PaymentMethod,
        val message: String,
        val transactionId: String = "",
        val balanceAfter: Int = 0
    )

    /**
     * Smart Payment Router - Automatically chooses the best method with fallbacks
     */
    suspend fun processPayment(
        payerId: String,
        payeeId: String,
        amount: Int,
        aesKey: ByteArray?,
        privateKey: ByteArray?
    ): PaymentResult {
        val priorityList = getPaymentMethodPriority()
        var lastError = "No payment method available"
        
        for (method in priorityList) {
            Log.d(TAG, "Attempting payment via: $method")
            val result = when (method) {
                PaymentMethod.ONLINE -> processOnline(payerId, payeeId, amount)
                PaymentMethod.BLE -> processOfflineBLE(payerId, payeeId, amount, aesKey, privateKey)
                PaymentMethod.SMS -> processOfflineSMS(payerId, payeeId, amount, aesKey, privateKey)
                PaymentMethod.FAILED -> null
            }
            
            if (result != null && result.success) {
                // Securely wipe keys from memory before returning success
                wipeSensitiveData(aesKey, privateKey)
                return result
            }
            
            if (result != null) {
                lastError = result.message
                Log.w(TAG, "Method $method failed: $lastError")
            }
        }

        // Wipe keys even on failure
        wipeSensitiveData(aesKey, privateKey)
        
        return PaymentResult(
            success = false,
            method = PaymentMethod.FAILED,
            message = "All payment methods failed: $lastError"
        )
    }

    private fun getPaymentMethodPriority(): List<PaymentMethod> {
        val methods = mutableListOf<PaymentMethod>()
        if (isInternetAvailable()) methods.add(PaymentMethod.ONLINE)
        if (isBLEAvailable()) methods.add(PaymentMethod.BLE)
        if (isSMSAvailable()) methods.add(PaymentMethod.SMS)
        return if (methods.isEmpty()) listOf(PaymentMethod.FAILED) else methods
    }

    private fun wipeSensitiveData(aesKey: ByteArray?, privateKey: ByteArray?) {
        aesKey?.fill(0)
        privateKey?.fill(0)
    }

    // ---------- Method Handlers ----------

    private suspend fun processOnline(
        payerId: String,
        payeeId: String,
        amount: Int
    ): PaymentResult {
        return try {
            // URL should be in BuildConfig
            val networkManager = NetworkManager(context, "https://mazily-preutilizable-lucy.ngrok-free.dev")
            val result = networkManager.processOnlinePayment(payerId, payeeId, amount)
            PaymentResult(
                success = result.success,
                method = PaymentMethod.ONLINE,
                message = result.message,
                transactionId = result.transactionId,
                balanceAfter = result.balanceAfter
            )
        } catch (e: Exception) {
            PaymentResult(false, PaymentMethod.ONLINE, "❌ Online failed: ${e.message}")
        }
    }


    private suspend fun processOfflineBLE(
        payerId: String,
        payeeId: String,
        amount: Int,
        aesKey: ByteArray?,
        privateKey: ByteArray?
    ): PaymentResult {
        return try {
            BLEManagerSingleton.init(context)
            val flow = BLEPaymentFlow(context)
            
            // For the router's automated logic, we need to know the BLE ID.
            // If it's not provided, we handover to MainActivity which has the QR scan context.
            PaymentResult(true, PaymentMethod.BLE, "Handover to BLE Flow")
        } catch (e: Exception) {
            PaymentResult(false, PaymentMethod.BLE, "BLE setup failed: ${e.message}")
        }
    }

    private suspend fun processOfflineSMS(
        payerId: String,
        payeeId: String,
        amount: Int,
        aesKey: ByteArray?,
        privateKey: ByteArray?
    ): PaymentResult {
        return try {
            val result = SMSPaymentHandler(context).processPayment(payerId, payeeId, amount, aesKey, privateKey)
            PaymentResult(result.success, PaymentMethod.SMS, result.message, result.transactionId, result.balanceAfter)
        } catch (e: Exception) {
            PaymentResult(false, PaymentMethod.SMS, "❌ SMS failed: ${e.message}")
        }
    }

    // ---------- Device Capability Checks ----------

    private fun isInternetAvailable(): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }


    private fun isBLEAvailable(): Boolean {
        val bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
        return bluetoothAdapter != null && bluetoothAdapter.isEnabled
    }

    private fun isSMSAvailable(): Boolean {
        val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return telephonyManager.simState == TelephonyManager.SIM_STATE_READY
    }
}
