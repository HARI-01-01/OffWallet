package com.offlinewallet

import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.google.firebase.FirebaseApp
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

class HealthMonitor(
    context: Context,
    private val networkManager: NetworkManager
) {
    private val appContext = context.applicationContext

    enum class Status {
        OK,         // Functional and connected
        WARNING,    // Functional but offline or limited
        ERROR,      // Critical failure or disconnected
        DISABLED    // Hardware disabled by user
    }

    data class SystemHealth(
        val backendStatus: Status = Status.DISABLED,
        val backendMessage: String = "Waiting...",
        val firebaseStatus: Status = Status.ERROR,
        val connectivityStatus: Status = Status.ERROR,
        val bleStatus: Status = Status.DISABLED,
        val smsStatus: Status = Status.DISABLED,
        val lastUpdated: Long = System.currentTimeMillis()
    )

    private val _health = MutableStateFlow(SystemHealth())
    val health: StateFlow<SystemHealth> = _health.asStateFlow()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var monitorJob: Job? = null

    private val hardwareReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d("HealthMonitor", "Hardware Broadcast Received: ${intent?.action}")
            scope.launch { updateHardwareStatus() }
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d("HealthMonitor", "Network Available")
            scope.launch { updateConnectivityStatus() }
        }

        override fun onLost(network: Network) {
            Log.d("HealthMonitor", "Network Lost")
            scope.launch { updateConnectivityStatus() }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            scope.launch { updateConnectivityStatus() }
        }
    }

    fun startMonitoring() {
        if (monitorJob?.isActive == true) return
        
        // Initial immediate checks in parallel
        scope.launch { updateHardwareStatus() }
        scope.launch { updateConnectivityStatus() }
        scope.launch { updateBackendStatus() }

        // 1. Register for Hardware Changes
        val filter = IntentFilter().apply {
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
            addAction(BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED)
        }
        ContextCompat.registerReceiver(appContext, hardwareReceiver, filter, ContextCompat.RECEIVER_EXPORTED)

        // 2. Register for Network Changes
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build(), networkCallback)

        // 3. Keep background polling for Backend only
        monitorJob = scope.launch {
            while (isActive) {
                delay(10000) // Backend check every 10 seconds is enough
                updateBackendStatus()
            }
        }
    }

    fun stopMonitoring() {
        try {
            appContext.unregisterReceiver(hardwareReceiver)
            val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {}
        monitorJob?.cancel()
    }

    /**
     * Fast update for hardware (BLE, SMS)
     */
    suspend fun updateHardwareStatus() = withContext(Dispatchers.IO) {
        try {
            val ble = checkBLE()
            val sms = checkSMS()
            
            _health.update { it.copy(
                bleStatus = ble,
                smsStatus = sms,
                lastUpdated = System.currentTimeMillis()
            )}
        } catch (e: Exception) {
            Log.e("HealthMonitor", "Error updating hardware status: ${e.message}")
        }
    }

    /**
     * Update Connectivity and Firebase (Moderate speed)
     */
    suspend fun updateConnectivityStatus() {
        val connectivity = checkConnectivity()
        val firebase = checkFirebase(connectivity)
        
        _health.update { it.copy(
            connectivityStatus = connectivity,
            firebaseStatus = firebase,
            lastUpdated = System.currentTimeMillis()
        )}
    }

    /**
     * Update Backend (Slow speed - involves network IO)
     */
    suspend fun updateBackendStatus() {
        val connectivity = _health.value.connectivityStatus
        val backend = if (connectivity == Status.OK) {
            _health.update { it.copy(backendMessage = "Checking...") }
            checkBackend()
        } else {
            Pair(Status.ERROR, "No Internet")
        }
        
        _health.update { it.copy(
            backendStatus = backend.first,
            backendMessage = backend.second,
            lastUpdated = System.currentTimeMillis()
        )}
    }

    // Legacy method for forced manual refresh (used by MainActivity)
    suspend fun updateHealth() {
        updateHardwareStatus()
        updateConnectivityStatus()
        updateBackendStatus()
    }

    private fun checkConnectivity(): Status {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return Status.ERROR
        val caps = cm.getNetworkCapabilities(network) ?: return Status.ERROR
        return if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) Status.OK else Status.WARNING
        } else {
            Status.ERROR
        }
    }

    private suspend fun checkBackend(): Pair<Status, String> {
        return try {
            val result = networkManager.checkHealth()
            if (result.isSuccess) {
                Pair(Status.OK, "Connected")
            } else {
                Pair(Status.ERROR, result.exceptionOrNull()?.message ?: "Unreachable")
            }
        } catch (e: Exception) {
            Pair(Status.ERROR, e.localizedMessage ?: "Unknown Error")
        }
    }

    private fun checkFirebase(connectivity: Status): Status {
        return try {
            FirebaseApp.getInstance()
            if (connectivity == Status.OK) Status.OK else Status.WARNING
        } catch (e: Exception) {
            Status.ERROR
        }
    }


    private fun checkBLE(): Status {
        return try {
            val bluetoothManager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
            val adapter = bluetoothManager?.adapter ?: BluetoothAdapter.getDefaultAdapter()
            
            if (adapter == null) {
                Status.ERROR
            } else {
                // Potential SecurityException here on Android 12+ if permissions not granted
                if (adapter.isEnabled) Status.OK else Status.DISABLED
            }
        } catch (e: SecurityException) {
            Log.w("HealthMonitor", "BLE Status inaccessible (Permissions?): ${e.message}")
            Status.DISABLED // Treat as disabled if we can't check
        } catch (e: Exception) {
            Log.w("HealthMonitor", "BLE Check Failed: ${e.message}")
            Status.DISABLED
        }
    }

    private fun checkSMS(): Status {
        return try {
            val tm = appContext.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (tm.simState == TelephonyManager.SIM_STATE_READY) Status.OK else Status.DISABLED
        } catch (e: Exception) {
            Log.w("HealthMonitor", "SMS Check Failed: ${e.message}")
            Status.DISABLED
        }
    }
}
