package com.offlinewallet

import android.Manifest
import android.app.Activity
import android.app.Dialog
import android.app.PendingIntent
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.*
import android.text.InputType
import android.util.Base64
import android.util.Log
import android.view.HapticFeedbackConstants
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.Lifecycle
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.offlinewallet.crypto.*
import com.offlinewallet.models.*
import com.offlinewallet.payment.SMSPaymentHandler
import com.offlinewallet.payment.ble.BLEManager
import com.offlinewallet.payment.ble.BLEManagerSingleton
import com.offlinewallet.payment.ble.BLEPaymentFlow
import com.offlinewallet.payment.smart.SyncWorker
import com.offlinewallet.ui.TransactionAdapter
import com.offlinewallet.ui.auth.LoginActivity
import com.offlinewallet.payment.ble.*
import com.offlinewallet.ui.payment.*
import com.offlinewallet.ui.utils.QRCodeHelper
import android.content.ComponentName
import android.provider.Settings
import kotlinx.coroutines.*
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import java.io.IOException
import java.security.KeyPair
import java.security.SecureRandom
import java.util.*

/**
 * MainActivity - Shadow v1 Orchestrator
 * Handles the dashboard, payment initiation, and background sync triggers.
 */
class MainActivity : AppCompatActivity(), QueueManager.TransactionListener {

    // UI Components
    private lateinit var statusText: TextView
    private lateinit var balanceText: TextView
    private lateinit var settledText: TextView
    private lateinit var reserveText: TextView
    private lateinit var provisionalText: TextView
    private lateinit var capacityValueText: TextView
    private lateinit var tvTxCount: TextView
    private lateinit var tvLastSettled: TextView
    private lateinit var capacityProgressBar: ProgressBar
    private lateinit var layoutStaleReserve: View
    
    private lateinit var balanceHeader: View
    private lateinit var balanceDetailsContainer: View
    private lateinit var ivExpandBalance: ImageView
    
    private lateinit var receiveBtn: View
    private lateinit var syncBtn: View
    private lateinit var payBtn: View
    private lateinit var loadLiteBtn: Button
    private lateinit var headerTitle: TextView
    private lateinit var headerSubtitle: TextView
    private lateinit var avatarInitial: TextView
    private lateinit var mainFab: View
    private lateinit var btnRefresh: ImageButton
    private lateinit var btnResolveSecurity: Button
    private lateinit var btnExplorerActionMain: View
    private lateinit var btnSeeAllHistory: View
    private lateinit var activityTab: View
    private lateinit var vaultTab: View
    private lateinit var profileTab: View
    private lateinit var offlineBanner: View
    private lateinit var cardPendingResolution: View
    private lateinit var btnResolveAll: Button
    private lateinit var tvOfflineStatus: TextView
    private lateinit var tvBleStatusMini: TextView
    private lateinit var tvBackendStatusMini: TextView
    private lateinit var protocolLabBtn: View
    private lateinit var transactionList: RecyclerView
    private lateinit var transactionAdapter: TransactionAdapter

    // Managers & Core
    private lateinit var walletCore: WalletCore
    private lateinit var bucketManager: BucketManager
    private lateinit var queueManager: QueueManager
    private lateinit var bleManager: BLEManager
    private lateinit var networkManager: NetworkManager
    private lateinit var healthMonitor: HealthMonitor

    // Session State
    private var walletId: String? = null
    private var serverPublicKey: ByteArray? = null
    private var publicKey: ByteArray? = null
    private var sessionBottomSheet: PaymentSessionBottomSheet? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var pendingRecoveryId: String? = null
    
    // Protocol Fields (v1 Handshake)
    private var isPayer = false
    private var currentAmount: Long = 0L
    private var currentSessionId: String? = null
    private var ephemeralKeyPair: KeyPair? = null
    private var myChallenge: ByteArray? = null
    private var activeSwapId: String? = null
    private var qrDialog: AlertDialog? = null
    private var activeV1QR: V1QR? = null
    private var isHandshakeInProgress = false

    private var lastScanTime = 0L
    private var lastHandshakeTime = 0L
    
    private val BASE_URL = Config.BASE_URL
    private val RC_SMART_PAY = 1002

    private fun launchQRScannerForRecovery() {
        val options = com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(com.google.mlkit.vision.barcode.common.Barcode.FORMAT_QR_CODE)
            .build()
        val scanner = com.google.mlkit.vision.codescanner.GmsBarcodeScanning.getClient(this, options)
        scanner.startScan()
            .addOnSuccessListener { barcode: com.google.mlkit.vision.barcode.common.Barcode ->
                val contents = barcode.rawValue
                if (contents != null) {
                    val v1 = QRCodeHelper.parseV1QR(contents)
                    if (v1 != null) {
                        startBleProtocolV1(v1)
                    } else {
                        val qd = QRCodeHelper.parseQRData(contents)
                        if (qd != null) handleRecoveryQRScanned(qd)
                        else Toast.makeText(this, "Invalid QR Code", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .addOnFailureListener { e: Exception ->
                Toast.makeText(this, "Scan failed: ${e.message}", Toast.LENGTH_SHORT).show()
            }
    }

    private val bleEventReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val localId = intent?.getStringExtra("LOCAL_ID")
            
            when (intent?.action) {
                SMSPaymentHandler.SMS_DELIVERED_ACTION -> {
                    localId?.let { lid ->
                        lifecycleScope.launch {
                            queueManager.markAsProcessed(lid)
                            updateBalanceUI()
                            Log.i("SMS", "✅ SMS Delivered for $lid")
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!SecureStorage.isAuthenticated()) {
            showOnboardingPrompt()
        } else {
            // Check current connectivity to set initial banner state
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(network)
            val isOnline = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            
            offlineBanner.visibility = if (isOnline) View.GONE else View.VISIBLE
            if (!isOnline) updateOfflineStatusText()
            
            setupBleCallbacks()
            lifecycleScope.launch { 
                healthMonitor.updateHealth() // Force immediate health check

                // WP-FIX: Auto-Recovery for Stale Reservations. 
                // If Alice has reserved funds but NO handshake is in progress, return them to balance.
                val id = walletId
                if (id != null && !isHandshakeInProgress) {
                    val bucket = bucketManager.getBucket(id)
                    bucket?.use {
                        if (it.moveToFirst()) {
                            val rb = it.getLong(it.getColumnIndexOrThrow("reserved_balance"))
                            if (rb > 0) {
                                Log.w("Shadow", "Found stale reservation of ₹${rb/100.0}. Auto-rolling back.")
                                bucketManager.rollbackReservedFunds(id, rb)
                            }
                        }
                    }
                }
                
                refreshWalletState() 
            }
            
            if (isPayer && activeV1QR != null) {
                Log.d("Shadow", "Resuming BLE Payer Flow")
            }
        }
    }

    override fun onPause() {
        super.onPause()
        if (isPayer) {
            Log.d("Shadow", "Pausing BLE Payer Flow")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        
        // WP-Reset: One-time wipe for "old user" as requested
        val prefs = getSharedPreferences("app_upgrade", MODE_PRIVATE)
        if (!prefs.getBoolean("v1_reset_done", false)) {
            prefs.edit().putBoolean("v1_reset_done", true).apply()
            com.offlinewallet.utils.AppResetUtils.performHardReset(this)
            finish()
            return
        }

        if (!SecureStorage.isAuthenticated()) {
            showOnboardingPrompt()
            return
        }

        try {
            setContentView(R.layout.activity_main)

            // WP-EdgeToEdge: Apply system insets to avoid overlapping with status bar/notch/nav bar
            ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.customAppBar)) { v, insets ->
                val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                v.updatePadding(top = bars.top)
                insets
            }
            ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.bottomNav)) { v, insets ->
                val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                v.updatePadding(bottom = bars.bottom)
                insets
            }

            initUi()
            initManagers()
            setupListeners()
            setupBle()
            setupWorkers()
            lifecycleScope.launch { 
                RecoveryManager(this@MainActivity).recoverPendingTransactions(bleManager)
                refreshWalletState() 
            }
        } catch (e: Exception) {
            Log.e("Shadow", "Initialization Error", e)
        }
    }

    private fun initUi() {
        statusText = findViewById(R.id.statusText)
        balanceText = findViewById(R.id.balanceText)
        settledText = findViewById(R.id.settledText)
        reserveText = findViewById(R.id.reserveText)
        provisionalText = findViewById(R.id.provisionalText)
        capacityValueText = findViewById(R.id.capacityValueText)
        tvTxCount = findViewById(R.id.tvTxCount)
        tvLastSettled = findViewById(R.id.tvLastSettled)
        capacityProgressBar = findViewById(R.id.capacityProgressBar)
        layoutStaleReserve = findViewById(R.id.layoutStaleReserve)
        
        balanceHeader = findViewById(R.id.balanceHeader)
        balanceDetailsContainer = findViewById(R.id.balanceDetailsContainer)
        ivExpandBalance = findViewById(R.id.ivExpandBalance)
        
        receiveBtn = findViewById(R.id.btnReceiveAction)
        syncBtn = findViewById(R.id.btnSyncAction)
        payBtn = findViewById(R.id.btnPayAction)
        loadLiteBtn = findViewById(R.id.loadLiteBtn)
        transactionList = findViewById(R.id.transactionList)
        headerTitle = findViewById(R.id.headerTitle)
        headerSubtitle = findViewById(R.id.headerSubtitle)
        avatarInitial = findViewById(R.id.avatarInitial)
        mainFab = findViewById(R.id.mainFab)
        btnRefresh = findViewById(R.id.btnRefresh)
        btnResolveSecurity = findViewById(R.id.btnResolveSecurity)
        btnExplorerActionMain = findViewById(R.id.btnExplorerActionMain)
        btnSeeAllHistory = findViewById(R.id.btnSeeAllHistory)
        activityTab = findViewById(R.id.activityTab)
        vaultTab = findViewById(R.id.vaultTab)
        profileTab = findViewById(R.id.profileTab)
        offlineBanner = findViewById(R.id.offlineBanner)
        cardPendingResolution = findViewById(R.id.cardPendingResolution)
        btnResolveAll = findViewById(R.id.btnResolveAll)
        tvOfflineStatus = findViewById(R.id.tvOfflineStatus)
        tvBleStatusMini = findViewById(R.id.tvBleStatusMini)
        tvBackendStatusMini = findViewById(R.id.tvBackendStatusMini)
        protocolLabBtn = findViewById(R.id.btnProtocolLab)
    }

    private fun initManagers() {
        walletCore = WalletCore(this)
        bucketManager = BucketManager(this)
        queueManager = QueueManager(this)
        BLEManagerSingleton.init(this)
        bleManager = BLEManagerSingleton.getInstance()
        networkManager = NetworkManager(this, BASE_URL)
        QueueManager.addListener(this)
        healthMonitor = HealthMonitor(this, networkManager)
        healthMonitor.startMonitoring()
        setupBleCallbacks()

        // WP-FIX: Refresh UI on sync complete to reset limits (0/10)
        val syncReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: android.content.Intent?) {
                lifecycleScope.launch {
                    updateBalanceUI()
                    updateStatus("✅ Sync Complete. Offline limits reset.")
                }
            }
        }
        val filter = android.content.IntentFilter("com.offlinewallet.SYNC_COMPLETE")
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(syncReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(syncReceiver, filter)
        }
    }

    private fun setupListeners() {
        receiveBtn.setOnClickListener { checkRegistrationAndExecute { showMyQRCode() } }
        payBtn.setOnClickListener { checkRegistrationAndExecute { startActivityForResult(Intent(this, com.offlinewallet.ui.payment.SmartPayActivity::class.java), RC_SMART_PAY) } }
        loadLiteBtn.setOnClickListener { checkRegistrationAndExecute { showLoadLiteDialog() } }
        syncBtn.setOnClickListener { checkRegistrationAndExecute { showManualSync() } }
        btnExplorerActionMain.setOnClickListener { startActivity(Intent(this, BlockchainExplorerActivity::class.java)) }
        mainFab.setOnClickListener { 
            vibrate()
            checkRegistrationAndExecute { showMyQRCode() } 
        }
        btnResolveSecurity.setOnClickListener { performSecurityRecovery() }
        btnSeeAllHistory.setOnClickListener { startActivity(Intent(this, com.offlinewallet.ui.FullHistoryActivity::class.java)) }
        activityTab.setOnClickListener { startActivity(Intent(this, com.offlinewallet.ui.FullHistoryActivity::class.java)) }
        vaultTab.setOnClickListener { startActivity(Intent(this, com.offlinewallet.ui.VaultActivity::class.java)) }
        profileTab.setOnClickListener { startActivity(Intent(this, com.offlinewallet.ui.ProfileActivity::class.java)) }
        
        balanceHeader.setOnClickListener {
            android.transition.TransitionManager.beginDelayedTransition(findViewById(R.id.balShell))
            val isExpanded = balanceDetailsContainer.visibility == View.VISIBLE
            balanceDetailsContainer.visibility = if (isExpanded) View.GONE else View.VISIBLE
            ivExpandBalance.animate().rotation(if (isExpanded) 0f else 180f).setDuration(300).start()
        }
        
        btnRefresh.setOnClickListener { performManualRefresh() }
        btnResolveAll.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Resolve All Funds")
                .setMessage("Checking status for all unconfirmed transactions with the server...")
                .setPositiveButton("Sync Now") { _, _ -> performManualRefresh() }
                .setNegativeButton("Cancel", null)
                .show()
        }

        protocolLabBtn.setOnClickListener {
            startActivity(Intent(this, com.offlinewallet.ui.test.ProtocolTestActivity::class.java))
        }

        observeHealth()
    }

    private fun showManualSync() {
        ManualSyncBottomSheet.newInstance().show(supportFragmentManager, ManualSyncBottomSheet.TAG)
    }

    private fun performManualRefresh() {
        lifecycleScope.launch {
            try {
                // 1. UI State: Start Animation
                btnRefresh.isEnabled = false
                btnRefresh.animate().rotationBy(360f * 5).setDuration(5000).start()
                Toast.makeText(this@MainActivity, "🔄 Refreshing Wallet State...", Toast.LENGTH_SHORT).show()

                // 2. Sequential Tasks: Ensure sync completes before UI refresh
                val refreshJob = launch {
                    syncWithServerSuspend()
                    refreshWalletState()
                }

                // 3. Forced 5s delay as requested to ensure UI stability
                delay(5000)
                refreshJob.join()

            } catch (e: Exception) {
                Log.e("Shadow", "Refresh failed", e)
            } finally {
                withContext(Dispatchers.Main) {
                    btnRefresh.isEnabled = true
                    btnRefresh.rotation = 0f
                    Toast.makeText(this@MainActivity, "✅ Sync Complete", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun setupBle() {
        val filter = IntentFilter().apply {
            addAction(SMSPaymentHandler.SMS_DELIVERED_ACTION)
        }
        LocalBroadcastManager.getInstance(this).registerReceiver(bleEventReceiver, filter)
    }

    private fun setupWorkers() {
        SyncWorker.schedule(this)
        
        // Schedule Reservation Cleanup
        val cleanupRequest = androidx.work.PeriodicWorkRequestBuilder<com.offlinewallet.payment.smart.ReservationCleanupWorker>(15, java.util.concurrent.TimeUnit.MINUTES).build()
        androidx.work.WorkManager.getInstance(this).enqueueUniquePeriodicWork("ReservationCleanup", androidx.work.ExistingPeriodicWorkPolicy.KEEP, cleanupRequest)

        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), 
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    runOnUiThread { 
                        offlineBanner.visibility = View.GONE 
                    }
                    triggerImmediateSync()
                }

                override fun onLost(network: Network) {
                    runOnUiThread { 
                        offlineBanner.visibility = View.VISIBLE 
                        updateOfflineStatusText()
                    }
                }
            })
    }

    private fun updateOfflineStatusText() {
        if (isFinishing || isDestroyed) return
        if (!::tvOfflineStatus.isInitialized) return

        val pass = SecureStorage.getPass()?.pass ?: return
        
        lifecycleScope.launch {
            val id = walletId ?: SecureStorage.getWalletId() ?: return@launch
            
            // Check for doubtful blocks
            val hasDoubtful = withContext(Dispatchers.IO) {
                com.offlinewallet.crypto.HashChainManager.hasDoubtfulBlock(this@MainActivity, id)
            }
            
            val aggregateCap = pass.aggregateCapP
            val unsettledAmount = queueManager.getUnsettledOutgoingAmount(id)
            val remainingCapacity = maxOf(0L, aggregateCap - unsettledAmount)
            
            if (isFinishing || isDestroyed) return@launch
            
            withContext(Dispatchers.Main) {
                if (hasDoubtful) {
                    tvOfflineStatus.text = "⚠️ Unconfirmed payment. Tap 'Sync' to resolve."
                    tvOfflineStatus.setTextColor(android.graphics.Color.RED)
                } else {
                    tvOfflineStatus.text = String.format(Locale.US, "📴 Offline Mode · ₹%,.0f spendable", 
                        remainingCapacity / 100.0)
                    tvOfflineStatus.setTextColor(android.graphics.Color.WHITE)
                }
            }
        }
    }

    private fun triggerImmediateSync() {
        val req = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(androidx.work.Constraints.Builder().setRequiredNetworkType(androidx.work.NetworkType.CONNECTED).build())
            .setBackoffCriteria(androidx.work.BackoffPolicy.EXPONENTIAL, 30, java.util.concurrent.TimeUnit.SECONDS)
            .build()
        
        WorkManager.getInstance(this).enqueueUniqueWork(
            "ImmediateSyncV1",
            androidx.work.ExistingWorkPolicy.KEEP,
            req
        )
    }

    private suspend fun refreshWalletState() {
        val isReg = SecureStorage.isRegistered()
        walletId = SecureStorage.getWalletId()
        
        val hasDoubtful = if (walletId != null) com.offlinewallet.crypto.HashChainManager.hasDoubtfulBlock(this, walletId!!) else false

        runOnUiThread {
            cardPendingResolution.visibility = if (hasDoubtful) View.VISIBLE else View.GONE
        }

        if (isReg) {
            withContext(Dispatchers.IO) {
                try {
                    val sPub = SecureStorage.getServerPublicKey()
                    if (!sPub.isNullOrEmpty()) serverPublicKey = HexUtils.decodeSafe(sPub)
                    
                    val pubK = SecureStorage.getPublicKey()
                    if (!pubK.isNullOrEmpty()) publicKey = HexUtils.decodeSafe(pubK)
                } catch (e: Exception) {
                    Log.e("Shadow", "Error loading keys", e)
                }
            }
            updateUserHeader()
            setupTransactionList()
            updateBalanceUI()
            refreshHistory()
        }
    }

    private fun updateUserHeader() {
        val name = SecureStorage.getWalletName() ?: "User"
        runOnUiThread {
            headerTitle.text = name
            headerSubtitle.text = SecureStorage.getEmail() ?: "Not logged in"
            avatarInitial.text = name.take(1).uppercase()
        }
    }

    private suspend fun updateBalanceUI() {
        val id = walletId ?: return
        val bc = bucketManager.getBucket(id)
        var bb = 0L; var rb = 0L; var st = "ACTIVE"; var fr = ""
        bc?.use {
            if (it.moveToFirst()) {
                bb = it.getLong(it.getColumnIndexOrThrow("balance"))
                rb = it.getLong(it.getColumnIndexOrThrow("reserved_balance"))
                st = it.getString(it.getColumnIndexOrThrow("status"))
                fr = it.getString(it.getColumnIndexOrThrow("freeze_reason")) ?: "Violation"
            }
        }
        val ob = SecureStorage.getBalance().toLong()
        
        val pass = SecureStorage.getPass()?.pass
        val aggregateCap = pass?.aggregateCapP ?: 200000L
        val unsettledAmount = queueManager.getUnsettledOutgoingAmount(id)
        val remainingCapacity = maxOf(0L, aggregateCap - unsettledAmount)
        
        val currentTxCount = withContext(Dispatchers.IO) {
            HashChainManager.getAllUnsyncedBlocks(this@MainActivity, id).size
        }
        val maxTxs = pass?.txnCountCap ?: 10L

        val lastSync = SecureStorage.getLastSyncTime()
        val lastSyncStr = if (lastSync == 0L) "Never" else {
            java.text.SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()).format(java.util.Date(lastSync))
        }

        withContext(Dispatchers.Main) {
            balanceText.text = String.format(Locale.US, "₹%,.2f", bb / 100.0)
            
            settledText.text = String.format(Locale.US, "₹%,.2f", ob / 100.0)
            reserveText.text = String.format(Locale.US, "₹%,.2f", rb / 100.0)
            provisionalText.text = String.format(Locale.US, "₹%,.2f", bb / 100.0)

            layoutStaleReserve.visibility = if (rb > 0) View.VISIBLE else View.GONE

            capacityValueText.text = String.format(Locale.US, "₹%,.0f / ₹%,.0f", remainingCapacity / 100.0, aggregateCap / 100.0)
            tvTxCount.text = "Transactions Used: $currentTxCount / $maxTxs"
            tvLastSettled.text = "Last Settled: $lastSyncStr"
            capacityProgressBar.max = (aggregateCap / 100).toInt()
            capacityProgressBar.progress = (remainingCapacity / 100).toInt()

            if (st == "FROZEN") {
                balanceText.setTextColor(Color.RED)
                statusText.text = "🚨 FROZEN: $fr"
                statusText.visibility = View.VISIBLE
                btnResolveSecurity.visibility = View.VISIBLE
            } else {
                balanceText.setTextColor(Color.parseColor("#0A0B0F"))
                btnResolveSecurity.visibility = View.GONE
                statusText.visibility = View.GONE
            }
        }
    }

    private fun showLoadLiteDialog() {
        val v = layoutInflater.inflate(R.layout.dialog_topup, null)
        val etAmount = v.findViewById<EditText>(R.id.etTopupAmount)
        val btnConfirm = v.findViewById<Button>(R.id.btnConfirmTopup)
        val btnCancel = v.findViewById<Button>(R.id.btnCancelTopup)

        val dialog = AlertDialog.Builder(this)
            .setView(v)
            .setCancelable(true)
            .create()

        btnConfirm.setOnClickListener {
            val s = etAmount.text.toString()
            if (s.isNotEmpty()) {
                val amountRupees = s.toDoubleOrNull() ?: 0.0
                val paisa = (amountRupees * 100).toInt()
                lifecycleScope.launch { executeLiteTopup(paisa) }
                dialog.dismiss()
            } else {
                etAmount.error = "Enter amount"
            }
        }
        
        btnCancel.setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private suspend fun executeLiteTopup(paisa: Int) {
        if (!SecureStorage.isAuthenticated()) {
            showOnboardingPrompt()
            return
        }
        
        val id = walletId ?: return
        val loading = withContext(Dispatchers.Main) {
            AlertDialog.Builder(this@MainActivity)
                .setView(R.layout.dialog_auth_loading)
                .setCancelable(false)
                .show()
        }

        try {
            val res = networkManager.topupBucket(id, paisa)
            loading.dismiss()

            if (res.isSuccess) {
                val d = res.getOrNull()!!
                val aesHex = SecureStorage.getAesKey()
                if (aesHex == null) {
                    updateStatus("❌ Error: Secure keys missing. Please re-register.")
                    return
                }
                
                val aes = HexUtils.decodeSafe(aesHex)
                val spubH = d.serverPublicKey ?: SecureStorage.getServerPublicKey()
                if (spubH == null) {
                    updateStatus("❌ Error: Server trust anchor missing.")
                    return
                }

                if (d.serverPublicKey != null) SecureStorage.saveServerPublicKey(d.serverPublicKey)
                val spub = HexUtils.decodeSafe(spubH)
                val ssig = HexUtils.decodeSafe(d.serverSignature)
                
                val (success, newBal) = bucketManager.addFunds(
                    walletId = id,
                    amount = paisa,
                    newBalance = d.balance,
                    counter = d.counter,
                    expiresAt = d.expiresAt,
                    aesKey = aes,
                    serverPublicKey = spub,
                    serverSignature = ssig,
                    issuedAt = d.issuedAt,
                    prevHashOverride = d.prevHash
                )
                
                if (success) {
                    SecureStorage.saveBalance(d.mainBalanceAfter)
                    queueManager.addTransaction(
                        amount = paisa,
                        payerId = "SERVER",
                        payeeId = id,
                        counter = d.counter,
                        payerSignature = ssig,
                        payeeSignature = ByteArray(0),
                        localId = "TOPUP_${System.currentTimeMillis()}",
                        method = "TOPUP",
                        status = QueueManager.STATUS_SETTLED
                    )
                    updateBalanceUI()
                    
                    withContext(Dispatchers.Main) {
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("✅ Vault Loaded")
                            .setMessage("Success! ₹${paisa / 100.0} has been securely moved to your hardware vault.\n\nOffline Spending Balance:\n₹${newBal / 100.0}")
                            .setPositiveButton("Done", null)
                            .show()
                    }
                } else {
                    updateStatus("❌ Top-up verification failed.")
                }
            } else {
                updateStatus("❌ Top-up failed: ${res.exceptionOrNull()?.message}")
            }
        } catch (e: Exception) {
            loading.dismiss()
            updateStatus("❌ Error: ${e.message}")
        }
    }

    // --- Shadow v1 Protocol ---

    private fun startBleProtocolV1(v1qr: V1QR) {
        if (isHandshakeInProgress) {
            Log.d("Shadow", "Handshake already in progress. Ignoring additional trigger.")
            return
        }
        isHandshakeInProgress = true
        
        activeV1QR = v1qr
        isPayer = true
        currentAmount = v1qr.amountP ?: 0L
        currentSessionId = v1qr.sid
        
        Log.d("Shadow", "Starting BLE Protocol V1. Amount: $currentAmount")

        lifecycleScope.launch {
            val diag = PreflightAuditDialog(this@MainActivity).apply { show() }
            
            // WP-Audit: Alice audits Bob's history from QR
            val bobPub = com.offlinewallet.crypto.KeyManager.bytesToPublicKey(com.offlinewallet.crypto.HexUtils.decodeSafe(v1qr.pass.pass.devicePubKey ?: ""), "EC")
            if (bobPub == null || !com.offlinewallet.crypto.HashChainManager.verifyHistory(v1qr.history, v1qr.pass.pass.lastSettledHead, bobPub)) {
                diag.dismiss()
                updateStatus("❌ Recipient Audit Failed: Chain Divergent")
                isHandshakeInProgress = false
                return@launch
            }

            val auditRes = bucketManager.reserveFunds(walletId!!, currentAmount, diag)
            if (auditRes is BucketManager.ReservationResult.Error) {
                diag.dismiss()
                updateStatus("❌ Self-Audit Failed: ${auditRes.message}")
                isHandshakeInProgress = false
                return@launch
            }
            
            // Revert the reservation from the pre-flight check - BLEManager will do the real one
            bucketManager.rollbackReservedFunds(walletId!!, currentAmount)
            diag.dismiss()
            
            bleManager.startPayerFlow(
                payerId = walletId!!,
                amount = currentAmount.toInt(),
                sid = v1qr.sid,
                bobPass = v1qr.pass,
                bobEpk = HexUtils.decodeSafe(v1qr.epk_B),
                bobChal = HexUtils.decodeSafe(v1qr.chal_B),
                callbacks = object : BLEManager.PaymentCallbacks {
                    override fun onPaymentInitiated() {}
                    override fun onChallengeReceived(challenge: ByteArray) {}
                    override fun onPaymentAccepted(receipt: Receipt) {
                        runOnUiThread {
                            lifecycleScope.launch { updateBalanceUI(); refreshHistory(); syncWithServer() }
                        }
                    }
                    override fun onPaymentError(error: String) {
                        isHandshakeInProgress = false
                        runOnUiThread { sessionBottomSheet?.dismiss() }
                    }
                    override fun onPaymentComplete(newBalance: Int) {
                        isHandshakeInProgress = false
                        runOnUiThread { 
                            updateStatus("✅ Payment Sent!")
                            sessionBottomSheet?.dismiss()
                        }
                        lifecycleScope.launch { updateBalanceUI(); refreshHistory() } 
                    }
                }
            )
        }
    }

    private fun handleRecoveryQRScanned(qd: QRCodeData) {
        val rid = pendingRecoveryId ?: return
        pendingRecoveryId = null
        lifecycleScope.launch {
            val tx = queueManager.getTransaction(rid)
            var amt = 0
            tx?.use { if (it.moveToFirst()) amt = it.getInt(it.getColumnIndexOrThrow("amount")) }
            val pins = queueManager.getTransactionPins(rid)
            if (pins.first != null) {
                OTPAtomicSwap.startSwap(walletId!!, qd.walletId, amt, rid)
                val s = OTPAtomicSwap.getSwapState(rid)!!
                s.myPin = pins.first
                s.peerPin = pins.second
            }
        }
    }

    private suspend fun syncWithServerSuspend() {
        try {
            if (!SecureStorage.isRegistered()) return
            Log.d("Shadow", "Starting manual sync...")
            val id = walletId ?: return
            val did = SecureStorage.getDeviceId() ?: return
            
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(network)
            val isOnline = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

            if (isOnline) {
                networkManager.getBalance(id).onSuccess { bal ->
                    SecureStorage.saveBalance(bal)
                }

                networkManager.requestNonce(id, did).onSuccess { r ->
                    NonceVault.saveNewNonce(this@MainActivity, r.nonceId, id, did, r.nonceValue, r.sequenceNumber, HexUtils.decodeSafe(r.serverSignature), r.expiresAt)
                }
                
                try {
                    val manualSync = com.offlinewallet.payment.smart.ManualSyncManager(this)
                    manualSync.performSync { progress ->
                        Log.d("Shadow", "Manual Sync Progress: ${progress.phase} - ${progress.message}")
                    }
                } catch (e: Exception) {
                    Log.e("Shadow", "Manual Sync logic failed", e)
                    triggerImmediateSync() // Fallback to background worker
                }
            }
            refreshWalletState()
        } catch (e: Exception) {
            Log.e("Shadow", "Manual Sync Error", e)
        }
    }

    private fun syncWithServer() {
        lifecycleScope.launch { syncWithServerSuspend() }
    }

    private suspend fun finalizeAtomicPayment(lid: String, ms: ByteArray, ps: ByteArray) {
        val res = OTPAtomicSwap.commitSwap(lid)
        if (res.success && res.state != null) {
            val s = res.state!!
            if (s.payerId == walletId) {
                val block = DebitBlock(1, "prod", walletId!!, 0L, ByteArray(32), s.amount.toLong(), ByteArray(32), "payee", ByteArray(32), "", "", 1L, 0L)
                val r = bucketManager.commitReservedFunds(walletId!!, s.amount.toLong(), lid, ms, block)
                if (r.first) { SecureStorage.saveBalance(r.second); queueManager.markAsProcessed(lid) }
            } else {
                val r = bucketManager.addFundsDirectly(walletId!!, s.amount, lid)
                if (r.first) { SecureStorage.saveBalance(r.second.toLong()); queueManager.addTransaction(s.amount, s.payerId, walletId!!, 0L, ps, ms, localId = lid, method = "ATOMIC_RECEIVE"); queueManager.markAsProcessed(lid) }
            }
            withContext(Dispatchers.Main) { updateBalanceUI(); refreshHistory() }
        }
    }

    private fun showMutualPinDialog(txId: String, amount: Int, myCode: String, peerCode: String) {
        val v = layoutInflater.inflate(R.layout.dialog_mutual_pin, null)
        v.findViewById<TextView>(R.id.tvMyPinCode).text = myCode
        v.findViewById<TextView>(R.id.tvPinAmount).text = String.format(Locale.US, "₹%.2f", amount / 100.0)
        
        val d = AlertDialog.Builder(this)
            .setView(v)
            .setCancelable(false)
            .setPositiveButton("Verify", null)
            .create()
            
        d.setOnShowListener {
            d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (v.findViewById<EditText>(R.id.etPeerPinInput).text.toString() == peerCode) {
                    OTPAtomicSwap.markAsVerified(txId)
                    lifecycleScope.launch {
                        if (!isPayer) finalizeAtomicPayment(txId, ByteArray(0), ByteArray(0))
                        else {
                            val s = OTPAtomicSwap.getSwapState(txId)
                            if (s != null) {
                                val td = queueManager.getTransaction(txId)
                                var sig: ByteArray? = null
                                td?.use { if (it.moveToFirst()) sig = it.getBlob(it.getColumnIndexOrThrow("payer_signature")) }
                                val block = DebitBlock(1, "prod", walletId!!, 0L, ByteArray(32), s.amount.toLong(), ByteArray(32), "payee", ByteArray(32), "", "", 1L, 0L)
                                val r = bucketManager.commitReservedFunds(walletId!!, s.amount.toLong(), txId, sig ?: ByteArray(0), block)
                                if (r.first) { SecureStorage.saveBalance(r.second); queueManager.markAsProcessed(txId) }
                            }
                            refreshWalletState()
                        }
                        runOnUiThread { d.dismiss() }
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Invalid PIN", Toast.LENGTH_SHORT).show()
                }
            }
        }
        d.show()
    }

    private fun setupTransactionList() {
        transactionAdapter = TransactionAdapter(emptyList<com.offlinewallet.models.Transaction>(), walletId, 
            onVerifyClick = { tx ->
                lifecycleScope.launch {
                    val pins = queueManager.getTransactionPins(tx.localId)
                    if (tx.payeeId == walletId) {
                        if (pins.first != null && pins.second != null) showMutualPinDialog(tx.localId, tx.amount, pins.first!!, pins.second!!)
                    } else {
                        pendingRecoveryId = tx.localId
                        launchQRScannerForRecovery()
                    }
                }
            },
            onCancelClick = { tx ->
                AlertDialog.Builder(this).setTitle("Cancel Payment?")
                    .setPositiveButton("Yes") { _, _ ->
                        lifecycleScope.launch {
                            if (bucketManager.rollbackReservedFunds(walletId!!, tx.amount.toLong())) {
                                queueManager.markAsFailed(tx.localId)
                                refreshWalletState()
                            }
                        }
                    }.setNegativeButton("No", null).show()
            },
            onItemClick = { tx ->
                if (tx.status == QueueManager.STATUS_QUEUED || tx.status == "PENDING_RECEIPT") {
                    resolveDoubtfulTransaction(tx)
                } else {
                    val intent = Intent(this, com.offlinewallet.ui.payment.TransactionDetailActivity::class.java).apply {
                        putExtra("TX_ID", tx.localId)
                    }
                    startActivity(intent)
                }
            })
        transactionList.adapter = transactionAdapter
    }

    private fun resolveDoubtfulTransaction(tx: com.offlinewallet.models.Transaction) {
        val dialog = AlertDialog.Builder(this).setTitle("Resolve Transaction").setMessage("Checking status...").setCancelable(false).show()
        lifecycleScope.launch {
            triggerImmediateSync()
            delay(3000)
            val updatedTx = queueManager.getTransaction(tx.localId)
            var status = "PENDING"
            updatedTx?.use { if (it.moveToFirst()) status = it.getString(it.getColumnIndexOrThrow("status")) }
            runOnUiThread {
                dialog.dismiss()
                Toast.makeText(this@MainActivity, "Status: $status", Toast.LENGTH_SHORT).show()
                lifecycleScope.launch { refreshWalletState() }
            }
        }
    }

    private fun generateAndShowQR() {
        isPayer = false
        val id = walletId ?: return
        
        lifecycleScope.launch {
            var p = SecureStorage.getPass()
            if (p == null) {
                updateStatus("🔐 Preparing hardware security pass...")
                syncWithServerSuspend()
                p = SecureStorage.getPass()
                
                if (p == null) {
                    Log.e("Shadow", "Failed to fetch pass after sync")
                    withContext(Dispatchers.Main) {
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("Security Setup Required")
                            .setMessage("Your hardware security pass could not be retrieved. Please ensure you are online and try again.")
                            .setPositiveButton("Retry") { _, _ -> generateAndShowQR() }
                            .setNegativeButton("Cancel", null)
                            .show()
                    }
                    return@launch
                }
            }
            
            val sid = UUID.randomUUID().toString().take(16)
            Log.d("Shadow", "🚀 [GENERATE_QR] New SID: $sid")
            val eph = withContext(Dispatchers.Default) { SecureKeyStore.generateEphemeralKeyPair() } ?: return@launch
            ephemeralKeyPair = eph
            val bleUuid = UUID.randomUUID()
            
            // WP-FIX: Limit QR history to first 4 blocks after anchor to prevent "Data too big" error.
            // If Bob has more than 4 unsynced blocks, Alice will audit the first 4 and 
            // then Bob can sync to clear the backlog.
            val history = withContext(Dispatchers.IO) { 
                HashChainManager.getHistorySince(this@MainActivity, id, p!!.pass.lastSettledCounter).take(4)
            }
            
            val myChal = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
            val v1 = V1QR(1, p!!, sid, HexUtils.encodeHex(KeyManager.publicKeyToBytes(eph.public)), HexUtils.encodeHex(myChal), bleUuid.toString(), null, history)

            // Pre-compute readable data for Verify QR section
            val readableContent = buildString {
                append("--- SHADOW SESSION ---\n")
                append("Session ID: $sid\n")
                append("Payer ID: $id\n")
                append("Counter: ${HashChainManager.nextCounter(this@MainActivity, id)}\n")
                append("Limit: ₹${p!!.pass.aggregateCapP / 100.0}\n")
                append("History Blocks: ${history.size}\n\n")
                append("--- ENCODED PAYLOAD ---\n")
            }

                try {
                    bleManager.paymentCallbacks = object : BLEManager.PaymentCallbacks {
                        override fun onPaymentInitiated() {}
                        override fun onChallengeReceived(challenge: ByteArray) {}
                        override fun onPaymentAccepted(receipt: Receipt) {
                            runOnUiThread {
                                lifecycleScope.launch { updateBalanceUI(); refreshHistory(); syncWithServer() }
                            }
                        }
                        override fun onPaymentError(error: String) { 
                            updateStatus("❌ Error: $error") 
                            runOnUiThread { sessionBottomSheet?.dismiss() }
                        }
                        override fun onPaymentComplete(newBalance: Int) { 
                            runOnUiThread { 
                                updateStatus("✅ Payment Received!")
                                sessionBottomSheet?.dismiss()
                            }
                            lifecycleScope.launch { updateBalanceUI(); refreshHistory() } 
                        }
                    }
                    bleManager.onPhaseChanged = { progress ->
                        if (progress.phase.ordinal >= PaymentPhase.CONNECTING.ordinal) {
                            runOnUiThread { qrDialog?.dismiss() }
                        }
                        showSessionProgress(progress)
                    }

                    bleManager.startPayeeFlow(sid, bleManager.paymentCallbacks!!, existingEphKey = eph, bobChallenge = myChal)
                } catch (e: Exception) { 
                    updateStatus("❌ Hardware Error: ${e.message}")
                    return@launch 
                }

            val (bitmap, qrString) = withContext(Dispatchers.Default) {
                val b = QRCodeHelper.generateV1QR(v1)
                
                // Also pre-compute Base45 for the "Verify" section
                val canonBytes = com.offlinewallet.crypto.MicroPaymentHandshake.encodeV1QR(v1)
                val bos = java.io.ByteArrayOutputStream()
                val deflater = java.util.zip.Deflater(java.util.zip.Deflater.BEST_COMPRESSION)
                deflater.setInput(canonBytes)
                deflater.finish()
                val buf = ByteArray(1024)
                while (!deflater.finished()) { 
                    val count = deflater.deflate(buf)
                    bos.write(buf, 0, count) 
                }
                deflater.end()
                val qs = com.offlinewallet.crypto.ShadowProtocol.base45Encode(bos.toByteArray())
                Pair(b, qs)
            }

            if (bitmap != null) {
                val v = layoutInflater.inflate(R.layout.dialog_qr_code, null)
                v.findViewById<ImageView>(R.id.ivQRCode).setImageBitmap(bitmap)
                v.findViewById<TextView>(R.id.tvWalletId)?.text = "Wallet: $id"
                
                v.findViewById<TextView>(R.id.tvQRRawData)?.text = readableContent + qrString
                
                v.findViewById<View>(R.id.ivQRCode).setOnClickListener {
                    val sv = v.findViewById<View>(R.id.svQRData)
                    sv.visibility = if (sv.visibility == View.VISIBLE) View.GONE else View.VISIBLE
                    vibrate()
                }

                val dialog = AlertDialog.Builder(this@MainActivity).setView(v).setCancelable(true).create()
                qrDialog = dialog
                v.findViewById<View>(R.id.btnCloseQR)?.setOnClickListener { dialog.dismiss() }
                dialog.show()
                dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
        }
    }

    private fun vibrate() {
        val vibrator = getSystemService(VIBRATOR_SERVICE) as Vibrator
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE))
        } else {
            @Suppress("DEPRECATION") vibrator.vibrate(100)
        }
    }


    private fun checkBlePermissions(): Boolean { 
        val perms = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) 
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT) 
            else arrayOf(Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN, Manifest.permission.ACCESS_FINE_LOCATION)
        if (perms.any { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }) {
            ActivityCompat.requestPermissions(this, perms, 101)
            return false
        }
        return true
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == RC_SMART_PAY && resultCode == RESULT_OK && data != null) {
            val status = data.getStringExtra("STATUS")
            if (status == "SUCCESS") {
                lifecycleScope.launch { refreshWalletState() }
                return
            }
            
            val action = data.getStringExtra("ACTION")
            if (action == "BLE_PAY_V1" || action == "BLE_PAY") {
                val qrStr = data.getStringExtra("V1_QR_DATA")
                val amount = data.getIntExtra("AMOUNT", 0).toLong()
                if (qrStr != null) {
                    val v1qr = QRCodeHelper.parseV1QR(qrStr)
                    if (v1qr != null) {
                        val finalV1QR = if (amount > 0) v1qr.copy(amountP = amount) else v1qr
                        startBleProtocolV1(finalV1QR)
                    }
                }
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101 && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) showMyQRCode()
    }

    private fun showMyQRCode() { if (checkBlePermissions()) generateAndShowQR() }
    
    private fun refreshHistory() { 
        lifecycleScope.launch { 
            val completedTxs = queueManager.getAllTransactions()
            val activeTxs = ActiveTransactionManager(this@MainActivity).getAllActive()
            val mergedList = mutableListOf<com.offlinewallet.models.Transaction>()
            mergedList.addAll(completedTxs)
            val completedIds = completedTxs.map { it.localId }.toSet()
            for (active in activeTxs) {
                if (!completedIds.contains(active.localId)) {
                    mergedList.add(com.offlinewallet.models.Transaction(localId = active.localId, amount = active.amount.toInt(), payerId = active.payerId, payeeId = active.payeeId, timestamp = System.currentTimeMillis() / 1000, status = active.state.name, counter = 0, method = "OFFLINE_ACTIVE"))
                }
            }
            val sortedList = mergedList.sortedByDescending { it.timestamp }
            withContext(Dispatchers.Main) { transactionAdapter.updateData(sortedList, walletId) }
        } 
    }
    private fun updateStatus(m: String) { runOnUiThread { statusText.text = m; Toast.makeText(this, m, Toast.LENGTH_SHORT).show() } }

    private fun showSessionProgress(progress: PaymentSessionProgress) {
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            
            Log.d("ShadowUI", "Phase: ${progress.phase}, IsPayer: $isPayer, QR Showing: ${qrDialog?.isShowing}")

            // PRD-FIX: Auto-transition for Bob (Payee). 
            if (!isPayer && progress.phase != PaymentPhase.DISCOVERY) {
                if (qrDialog?.isShowing == true) {
                    Log.i("ShadowUI", "Dismissing QR Dialog for active session")
                    qrDialog?.dismiss()
                }
            }

            // Alice (Payer) or connected Bob (Payee)
            val shouldShowSheet = isPayer || (progress.phase != PaymentPhase.DISCOVERY)

            if (shouldShowSheet) {
                if (sessionBottomSheet == null || !sessionBottomSheet!!.isAdded) {
                    sessionBottomSheet = PaymentSessionBottomSheet.newInstance()
                    sessionBottomSheet!!.show(supportFragmentManager, PaymentSessionBottomSheet.TAG)
                }
                sessionBottomSheet!!.updateProgress(progress)
            } else if (progress.phase == PaymentPhase.DISCOVERY) {
                // Bob in initial discovery state
                updateStatus("📡 QR Displayed. Waiting for Alice...")
            }
        }
    }
    private fun observeHealth() {
        lifecycleScope.launch {
            healthMonitor.health.collect { health ->
                runOnUiThread {
                    tvBleStatusMini.text = if (health.bleStatus == HealthMonitor.Status.OK) "BLE: ON" else "BLE: OFF"
                    tvBleStatusMini.setTextColor(if (health.bleStatus == HealthMonitor.Status.OK) Color.parseColor("#4CAF50") else Color.parseColor("#808080"))
                    tvBackendStatusMini.text = "BACKEND: ${if (health.backendStatus == HealthMonitor.Status.OK) "CONNECTED" else "OFFLINE"}"
                    tvBackendStatusMini.setTextColor(if (health.backendStatus == HealthMonitor.Status.OK) Color.parseColor("#4CAF50") else Color.parseColor("#F44336"))
                    if (health.connectivityStatus == HealthMonitor.Status.OK) offlineBanner.visibility = View.GONE 
                    else { offlineBanner.visibility = View.VISIBLE; updateOfflineStatusText() }
                }
            }
        }
    }
    private fun setupBleCallbacks() {
        bleManager.onPhaseChanged = { progress ->
            showSessionProgress(progress)
        }
        bleManager.onError = { error -> 
            isHandshakeInProgress = false
            Log.e("Shadow", "PROTOCOL_BREAK: $error")
            runOnUiThread {
                Toast.makeText(this, "Protocol Break: $error", Toast.LENGTH_LONG).show()
            }
        }
    }
    
    private fun checkRegistrationAndExecute(action: () -> Unit) {
        if (SecureStorage.isRegistered()) {
            val id = SecureStorage.getWalletId()!!
            if (!SecureKeyStore.isKeyValid(id)) {
                AlertDialog.Builder(this).setTitle("Security Key Invalid").setMessage("Please re-register.").setPositiveButton("Re-register") { _, _ -> 
                    SecureStorage.clear()
                    showOnboardingPrompt()
                }.show()
                return
            }
            action()
        } else showOnboardingPrompt()
    }
    private fun showOnboardingPrompt() { 
        val intent = Intent(this, com.offlinewallet.ui.auth.LoginActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
    private fun performSecurityRecovery() {
        lifecycleScope.launch {
            val loading = AlertDialog.Builder(this@MainActivity).setView(R.layout.dialog_auth_loading).setCancelable(false).show()
            try {
                IntegrityGuardian.init(this@MainActivity)
                delay(1000)
                if (IntegrityGuardian.checkIntegrity()) {
                    if (bucketManager.activateBucket(walletId!!)) { updateStatus("✅ Wallet Unfrozen!"); refreshWalletState() }
                } else updateStatus("🚨 Integrity compromised")
            } catch (e: Exception) { updateStatus("❌ Recovery failed") } finally { loading.dismiss() }
        }
    }
    override fun onTransactionAdded(localId: String) { lifecycleScope.launch { refreshHistory() } }
    override fun onSyncCompleted() { lifecycleScope.launch { updateBalanceUI(); refreshHistory() } }
}
