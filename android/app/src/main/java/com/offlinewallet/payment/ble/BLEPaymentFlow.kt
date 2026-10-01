package com.offlinewallet.payment.ble

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.util.*

class BLEPaymentFlow(private val context: Context) {
    private val TAG = "BLEPaymentFlow"
    private val bleManager = BLEManagerSingleton.getInstance()
    
    /**
     * Start as PAYEE (Receiver) - Advertising
     */
    fun startAsPayee(bleId: String, callbacks: BLEManager.PaymentCallbacks) {
        Log.d(TAG, "Starting as Payee with ID: $bleId")
        bleManager.paymentCallbacks = callbacks
        bleManager.startAdvertising(bleId)
    }

    fun stop() {
        Log.d(TAG, "Stopping BLE Flow")
        bleManager.stop()
    }
}
