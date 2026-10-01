package com.offlinewallet.ui.test

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.*
import com.offlinewallet.models.Receipt
import com.offlinewallet.models.V1QR
import com.offlinewallet.payment.ble.*
import com.offlinewallet.ui.utils.QRCodeHelper
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.barcode.common.Barcode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.*

class ProtocolTestActivity : AppCompatActivity() {

    private lateinit var modeSelection: View
    private lateinit var labActiveView: View
    private lateinit var tvActiveModeTitle: TextView
    private lateinit var ivTestQr: ImageView
    private lateinit var qrProgress: ProgressBar
    private lateinit var peerInfoCard: View
    private lateinit var tvPeerName: TextView
    private lateinit var tvPeerId: TextView
    private lateinit var tvAuditStatus: TextView
    private lateinit var tvProtocolLogs: TextView
    private lateinit var btnStopLab: View
    private lateinit var btnAliceScan: View

    private lateinit var bleManager: BLEManager
    private var isBobMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_protocol_test)

        initUi()
        initBle()

        findViewById<View>(R.id.btnBobMode).setOnClickListener { startBobMode() }
        findViewById<View>(R.id.btnAliceMode).setOnClickListener { startAliceMode() }
        btnStopLab.setOnClickListener { stopLab() }
    }

    private fun initUi() {
        modeSelection = findViewById(R.id.modeSelection)
        labActiveView = findViewById(R.id.labActiveView)
        tvActiveModeTitle = findViewById(R.id.tvActiveModeTitle)
        ivTestQr = findViewById(R.id.ivTestQr)
        qrProgress = findViewById(R.id.qrProgress)
        peerInfoCard = findViewById(R.id.peerInfoCard)
        tvPeerName = findViewById(R.id.tvPeerName)
        tvPeerId = findViewById(R.id.tvPeerId)
        tvAuditStatus = findViewById(R.id.tvAuditStatus)
        tvProtocolLogs = findViewById(R.id.tvProtocolLogs)
        btnStopLab = findViewById(R.id.btnStopLab)
        
        // Dynamic scan button for Alice
        btnAliceScan = android.widget.Button(this).apply {
            text = "📸 Scan Bob's Test QR"
            visibility = View.GONE
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 24 }
            setOnClickListener { launchScanner() }
        }
        (labActiveView as android.widget.LinearLayout).addView(btnAliceScan, 3)
    }

    private fun initBle() {
        BLEManagerSingleton.init(this)
        bleManager = BLEManagerSingleton.getInstance()
        bleManager.onPhaseChanged = { progress ->
            updateProgress(progress)
        }
        bleManager.onDataReceived = { data ->
            log("Raw Data Received: ${data.size} bytes")
        }
    }

    private fun startBobMode() {
        isBobMode = true
        modeSelection.visibility = View.GONE
        labActiveView.visibility = View.VISIBLE
        tvActiveModeTitle.text = "📥 Bob Mode (Payee)"
        ivTestQr.visibility = View.GONE
        qrProgress.visibility = View.VISIBLE
        peerInfoCard.visibility = View.GONE
        btnAliceScan.visibility = View.GONE
        tvProtocolLogs.text = "Initializing Bob Lab..."

        lifecycleScope.launch {
            val walletId = SecureStorage.getWalletId() ?: "unknown"
            val pass = SecureStorage.getPass() ?: run {
                log("Error: No security pass found. Please sync first.")
                return@launch
            }

            val sid = UUID.randomUUID().toString().take(8)
            val eph = withContext(Dispatchers.Default) { SecureKeyStore.generateEphemeralKeyPair() }
            if (eph == null) {
                log("Error: Hardware key generation failed.")
                return@launch
            }

            val bleUuid = UUID.randomUUID().toString()
            val history = withContext(Dispatchers.IO) { HashChainManager.getAllUnsyncedBlocks(this@ProtocolTestActivity, walletId) }
            
            val myChal = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
            val v1 = V1QR(
                v = 1,
                pass = pass,
                sid = sid,
                epk_B = HexUtils.encodeHex(KeyManager.publicKeyToBytes(eph.public)),
                chal_B = HexUtils.encodeHex(myChal),
                bleUuid = bleUuid,
                amountP = 0L,
                history = history
            )

            bleManager.paymentCallbacks = object : BLEManager.PaymentCallbacks {
                override fun onPaymentInitiated() { log("Payment Initiated") }
                override fun onChallengeReceived(challenge: ByteArray) { log("Challenge Received") }
                override fun onPaymentAccepted(receipt: Receipt) { log("Payment Accepted - M3 Block Verified ✓") }
                override fun onPaymentError(error: String) { log("Error: $error") }
                override fun onPaymentComplete(newBalance: Int) { log("Complete: Receipt Issued (M4)") }
            }

            bleManager.startPayeeFlow(sid, bleManager.paymentCallbacks!!, existingEphKey = eph, bobChallenge = myChal)
            log("Bob is advertising SID: $sid")

            val bitmap = withContext(Dispatchers.Default) { QRCodeHelper.generateV1QR(v1) }
            qrProgress.visibility = View.GONE
            ivTestQr.visibility = View.VISIBLE
            ivTestQr.setImageBitmap(bitmap)
            log("Test QR generated. Waiting for Alice...")
        }
    }

    private fun startAliceMode() {
        isBobMode = false
        modeSelection.visibility = View.GONE
        labActiveView.visibility = View.VISIBLE
        tvActiveModeTitle.text = "💸 Alice Mode (Payer)"
        ivTestQr.visibility = View.GONE
        qrProgress.visibility = View.GONE
        peerInfoCard.visibility = View.GONE
        btnAliceScan.visibility = View.VISIBLE
        tvProtocolLogs.text = "Initializing Alice Lab...\nTap Scan to start."
    }

    private fun launchScanner() {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .enableAutoZoom()
            .build()

        val scanner = GmsBarcodeScanning.getClient(this, options)
        scanner.startScan()
            .addOnSuccessListener { result: Barcode ->
                val rawValue = result.rawValue
                if (rawValue != null) {
                    processScannedData(rawValue)
                }
            }
            .addOnFailureListener { e: Exception ->
                log("Scan failed: ${e.message}")
            }
    }

    private fun processScannedData(data: String) {
        log("QR Scanned. Decoding protocol payload...")
        val v1 = try {
            QRCodeHelper.parseV1QR(data)
        } catch (e: Exception) {
            log("Error: Invalid V1 QR format.")
            return
        }

        if (v1 == null) {
            log("Error: Data decoded but V1 object is null.")
            return
        }

        log("Decoded SID: ${v1.sid}. Connecting to Bob...")
        
        val payerId = SecureStorage.getWalletId() ?: "unknown"
        
        bleManager.paymentCallbacks = object : BLEManager.PaymentCallbacks {
            override fun onPaymentInitiated() { log("Payment Initiated (M1 Sent)") }
            override fun onChallengeReceived(challenge: ByteArray) { log("Hardware Challenge Received") }
            override fun onPaymentAccepted(receipt: Receipt) { log("Payment Accepted by Bob") }
            override fun onPaymentError(error: String) { log("Error: $error") }
            override fun onPaymentComplete(newBalance: Int) { log("Success: Receipt (M4) Verified ✓") }
        }

        // In Lab Mode, we use amount 0 to avoid reserve logic
        bleManager.startPayerFlow(
            payerId = payerId,
            amount = 0,
            sid = v1.sid,
            bobPass = v1.pass,
            bobEpk = HexUtils.decodeSafe(v1.epk_B),
            bobChal = HexUtils.decodeSafe(v1.chal_B),
            callbacks = bleManager.paymentCallbacks!!
        )
    }

    private fun updateProgress(p: PaymentSessionProgress) {
        runOnUiThread {
            log("${p.phase.name}: ${p.message}")
            
            if (p.phase == PaymentPhase.IDENTITY && p.peerName != null) {
                peerInfoCard.visibility = View.VISIBLE
                tvPeerName.text = "Name: ${p.peerName}"
                tvPeerId.text = "Wallet ID: ${p.peerId ?: "unknown"}"
            }

            if (p.phase == PaymentPhase.AUDIT) {
                tvAuditStatus.text = "🛡️ History Audit: Verified ✓"
                tvAuditStatus.setTextColor(getColor(R.color.verified_green))
            }
            
            if (p.errorCode != null) {
                log("ERROR: ${p.errorCode}")
            }
        }
    }

    private fun log(msg: String) {
        runOnUiThread {
            val current = tvProtocolLogs.text.toString()
            tvProtocolLogs.text = "$current\n> $msg"
        }
    }

    private fun stopLab() {
        bleManager.stop()
        modeSelection.visibility = View.VISIBLE
        labActiveView.visibility = View.GONE
        btnAliceScan.visibility = View.GONE
    }

    override fun onDestroy() {
        super.onDestroy()
        bleManager.stop()
    }
}
