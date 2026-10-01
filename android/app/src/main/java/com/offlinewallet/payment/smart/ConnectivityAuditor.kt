package com.offlinewallet.payment.smart

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.nfc.NfcAdapter
import android.telephony.TelephonyManager
import com.offlinewallet.NetworkManager

class ConnectivityAuditor(
    private val context: Context,
    private val networkManager: NetworkManager
) {
    enum class ConnectionMethod {
        ONLINE,
        NFC,
        BLE,
        SMS,
        NONE
    }

    private var lastCheckTime = 0L
    private var cachedResult: ConnectionMethod? = null
    private val CACHE_DURATION = 5000L  // 5 seconds

    suspend fun getBestAvailableMethod(): ConnectionMethod {
        val now = System.currentTimeMillis()
        if (cachedResult != null && (now - lastCheckTime) < CACHE_DURATION) {
            return cachedResult!!
        }

        val method = determineMethod()
        
        lastCheckTime = now
        cachedResult = method
        return method
    }

    private suspend fun determineMethod(): ConnectionMethod {
        // 1. Check Online
        if (isInternetAvailable()) {
            try {
                val healthRes = networkManager.checkHealth()
                if (healthRes.isSuccess) {
                    return ConnectionMethod.ONLINE
                }
            } catch (_: Exception) {}
        }

        // 2. Check BLE
        if (isBLEAvailable()) {
            return ConnectionMethod.BLE
        }

        // 3. Check SMS
        if (isSMSAvailable()) {
            return ConnectionMethod.SMS
        }

        return ConnectionMethod.NONE
    }

    fun isInternetAvailable(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    fun isNFCAvailable(): Boolean {
        val hasHardware = context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC)
        if (!hasHardware) return false
        
        val adapter = NfcAdapter.getDefaultAdapter(context)
        return adapter != null && adapter.isEnabled
    }

    fun isBLEAvailable(): Boolean {
        val adapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter()
        return adapter != null && adapter.isEnabled
    }

    fun isSMSAvailable(): Boolean {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return tm.simState == TelephonyManager.SIM_STATE_READY
    }

    fun invalidateCache() {
        cachedResult = null
        lastCheckTime = 0L
    }
}
