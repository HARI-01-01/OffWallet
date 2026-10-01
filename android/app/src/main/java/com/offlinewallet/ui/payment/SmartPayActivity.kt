package com.offlinewallet.ui.payment

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.textfield.TextInputLayout
import com.offlinewallet.NetworkManager
import com.offlinewallet.R
import com.offlinewallet.models.QRCodeData
import com.offlinewallet.payment.smart.ConnectivityAuditor
import com.offlinewallet.payment.smart.SmartPayManager
import com.offlinewallet.ui.utils.QRCodeHelper
import com.offlinewallet.payment.ble.*
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import kotlinx.coroutines.launch

class SmartPayActivity : AppCompatActivity() {

    private lateinit var etPayeeId: EditText
    private lateinit var tilPayee: TextInputLayout
    private lateinit var tvPayeeName: TextView
    private lateinit var etAmount: EditText
    private lateinit var btnPayNow: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var toggleMethod: MaterialButtonToggleGroup
    private lateinit var tvMethodDescription: TextView

    private lateinit var layoutInputState: View
    private lateinit var btnBack: View
    private lateinit var btnClose: View

    private lateinit var networkManager: NetworkManager
    private lateinit var smartPayManager: SmartPayManager
    private var sessionBottomSheet: PaymentSessionBottomSheet? = null

    private var identifiedPayeeId: String? = null
    private var identifiedPayeePubKey: String? = null
    private var preferredMethod: ConnectivityAuditor.ConnectionMethod = ConnectivityAuditor.ConnectionMethod.ONLINE
    private var scannnedV1QR: String? = null

    private fun handleScannedContents(contents: String) {
        val v1qr = QRCodeHelper.parseV1QR(contents)
        if (v1qr != null) {
            // Shadow v1 detected - Show verification dialog
            showPayeeVerificationDialog(v1qr, contents)
            return
        }
        // ... rest of the method handles legacy QR ...

        val qrData = QRCodeHelper.parseQRData(contents)
        if (qrData != null) {
            identifiedPayeePubKey = qrData.publicKeyHex
            onPayeeIdentified(qrData.walletId, qrData.name)

            // Always clear amount for Alice to enter manually as per new flow
            etAmount.setText("")

            // Always stay on this screen to let user choose method and amount
            if (qrData.bleId != null || qrData.btName != null) {
                this.intent.putExtra("BLE_ID", qrData.bleId)
                this.intent.putExtra("BT_NAME", qrData.btName)
                // If QR has BLE info, switch toggle to BLE as a suggestion, but stay here
                toggleMethod.check(R.id.btnMethodBLE)
            } else {
                // Default to Online for regular QRs
                toggleMethod.check(R.id.btnMethodOnline)
            }

            etAmount.requestFocus()
            etAmount.postDelayed({
                val imm = getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                imm.showSoftInput(etAmount, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
            }, 200)
            
            Toast.makeText(this, "Review details and tap Pay Securely", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Invalid QR Code", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_smart_pay)

        val root = findViewById<View>(R.id.btnBack).parent as View
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top)
            
            // Apply bottom padding to the button container
            findViewById<View>(R.id.btnPayNow).updatePadding(bottom = bars.bottom)
            
            insets
        }

        layoutInputState = findViewById(R.id.layoutInputState)
        btnBack = findViewById(R.id.btnBack)
        btnClose = findViewById(R.id.btnClose)

        etPayeeId = findViewById(R.id.etPayeeId)
        tilPayee = findViewById(R.id.tilPayee)
        tvPayeeName = findViewById(R.id.tvPayeeName)
        etAmount = findViewById(R.id.etAmount)
        btnPayNow = findViewById(R.id.btnPayNow)
        progressBar = findViewById(R.id.payProgressBar)
        toggleMethod = findViewById(R.id.toggleMethod)
        tvMethodDescription = findViewById(R.id.tvMethodDescription)

        setLoading(false)

        networkManager = NetworkManager(this, com.offlinewallet.Config.BASE_URL)
        smartPayManager = SmartPayManager(this, networkManager)

        setupMethodToggle()
        tilPayee.setEndIconOnClickListener { launchQRScanner() }

        btnPayNow.setOnClickListener { attemptSmartPay() }
        
        btnBack.setOnClickListener { 
            finish()
        }
        btnClose.setOnClickListener { finish() }

        etPayeeId.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) {
                val input = etPayeeId.text.toString().trim()
                if (input.isNotEmpty()) performUserLookup(input)
            }
        }

        // Auto-launch scanner if empty with small delay
        if (etPayeeId.text.isEmpty()) {
            lifecycleScope.launch {
                kotlinx.coroutines.delay(500)
                launchQRScanner()
            }
        }

        checkConnectivityAndAdjustMethods()
    }

    override fun onResume() {
        super.onResume()
        checkConnectivityAndAdjustMethods()
    }

    override fun onDestroy() {
        super.onDestroy()
        val bleManager = BLEManagerSingleton.getInstance()
        bleManager.onPhaseChanged = null
        bleManager.onError = null
        bleManager.onDataReceived = null
    }

    private fun checkConnectivityAndAdjustMethods() {
        val auditor = ConnectivityAuditor(this, networkManager)
        val isOnline = auditor.isInternetAvailable()
        
        runOnUiThread {
            if (!isOnline) {
                // Network lost: Force BLE only
                toggleMethod.check(R.id.btnMethodBLE)
                findViewById<View>(R.id.btnMethodOnline).isEnabled = false
                findViewById<View>(R.id.btnMethodNFC).visibility = View.GONE
                tvMethodDescription.text = "📴 Network lost: Offline Bluetooth payment only."
                preferredMethod = ConnectivityAuditor.ConnectionMethod.BLE
            } else {
                findViewById<View>(R.id.btnMethodOnline).isEnabled = true
                findViewById<View>(R.id.btnMethodNFC).visibility = View.GONE
                findViewById<View>(R.id.btnMethodBLE).isEnabled = true
            }
        }
    }

    private fun launchQRScanner() {
        val options = com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(com.google.mlkit.vision.barcode.common.Barcode.FORMAT_QR_CODE)
            .enableAutoZoom()
            .build()

        val scanner = com.google.mlkit.vision.codescanner.GmsBarcodeScanning.getClient(this, options)
        scanner.startScan()
            .addOnSuccessListener { result: com.google.mlkit.vision.barcode.common.Barcode ->
                // The result is of type Barcode
                val rawValue = result.rawValue
                if (rawValue != null) {
                    handleScannedContents(rawValue)
                }
            }
            .addOnFailureListener { e: Exception ->
                Toast.makeText(this, "Scan failed: ${e.message}", Toast.LENGTH_SHORT).show()
            }
    }

    private fun setupMethodToggle() {
        toggleMethod.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                preferredMethod = when (checkedId) {
                    R.id.btnMethodOnline -> {
                        tvMethodDescription.text = "Force real-time cloud payment"
                        ConnectivityAuditor.ConnectionMethod.ONLINE
                    }
                    R.id.btnMethodNFC -> {
                        tvMethodDescription.text = "Force offline tap-to-pay"
                        ConnectivityAuditor.ConnectionMethod.NFC
                    }
                    R.id.btnMethodBLE -> {
                        tvMethodDescription.text = "Force offline Bluetooth payment"
                        ConnectivityAuditor.ConnectionMethod.BLE
                    }
                    else -> ConnectivityAuditor.ConnectionMethod.ONLINE
                }
            }
        }
        // NFC is being deprecated for BLE
        findViewById<View>(R.id.btnMethodNFC).visibility = View.GONE
    }

    private fun performUserLookup(input: String) {
        if (input != identifiedPayeeId) {
            scannnedV1QR = null
        }
        lifecycleScope.launch {
            setLoading(true)
            val result = networkManager.lookupUser(
                walletId = if (input.startsWith("user_")) input else null,
                email = if (input.contains("@")) input else null,
                phone = if (input.startsWith("+")) input else null
            )
            
            if (result.isSuccess) {
                val data = result.getOrNull()!!
                onPayeeIdentified(data.walletId, data.walletName)
            } else {
                // Check if it's a network error (offline)
                val exception = result.exceptionOrNull()
                if (exception is java.net.ConnectException || exception is java.net.UnknownHostException || 
                    exception?.message?.contains("Unable to resolve host") == true || 
                    exception?.message?.contains("timed out") == true) {
                    
                    tvPayeeName.visibility = View.VISIBLE
                    tvPayeeName.text = "Verified Offline"
                    tvPayeeName.setTextColor(getColor(R.color.warning))
                    identifiedPayeeId = input // ✅ IMPORTANT: Set this so attemptSmartPay succeeds
                    layoutInputState.visibility = View.VISIBLE
                } else {
                    tvPayeeName.visibility = View.VISIBLE
                    tvPayeeName.text = "User not found"
                    tvPayeeName.setTextColor(getColor(R.color.error))
                    identifiedPayeeId = null
                }
            }
            setLoading(false)
        }
    }

    private fun onPayeeIdentified(id: String, name: String) {
        identifiedPayeeId = id
        etPayeeId.setText(id)
        tvPayeeName.visibility = View.VISIBLE
        tvPayeeName.text = "Pay to: $name"
        tvPayeeName.setTextColor(getColor(R.color.primary))
        layoutInputState.visibility = View.VISIBLE
    }

    private fun attemptSmartPay() {
        val payeeId = identifiedPayeeId ?: etPayeeId.text.toString().trim()
        val amountStr = etAmount.text.toString().trim()

        if (payeeId.isEmpty()) {
            Toast.makeText(this, "Please enter payee", Toast.LENGTH_SHORT).show()
            return
        }

        val amount = (amountStr.toDoubleOrNull()?.let { (it * 100).toInt() }) ?: 0
        if (amount <= 0) {
            Toast.makeText(this, "Please enter valid amount", Toast.LENGTH_SHORT).show()
            return
        }

        // Prepare for Bluetooth Discovery
        setLoading(true)

        lifecycleScope.launch {
            try {
                setLoading(true)
                val result = smartPayManager.initiatePayment(payeeId, amount, preferredMethod = preferredMethod)
                handlePaymentResult(result)
            } catch (e: Exception) {
                setLoading(false)
                Toast.makeText(this@SmartPayActivity, "Payment failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun handlePaymentResult(result: SmartPayManager.PaymentResult) {
        when (result) {
            is SmartPayManager.PaymentResult.Success -> {
                setLoading(false)
                Toast.makeText(this, result.message, Toast.LENGTH_LONG).show()
                finish()
            }
            is SmartPayManager.PaymentResult.Error -> {
                setLoading(false)
                Toast.makeText(this, result.message, Toast.LENGTH_LONG).show()
            }
            is SmartPayManager.PaymentResult.ActionRequired -> {
                val intent = Intent()
                var action = result.action
                
                // If it's a standard BLE_PAY request but we have V1 data, upgrade it to BLE_V1
                if ((action == "BLE_PAY" || action == "NFC_PAY" || action == "NFC_PAY_V1") && scannnedV1QR != null) {
                    action = "BLE_PAY_V1"
                    intent.putExtra("V1_QR_DATA", scannnedV1QR)
                }
                
                if (action == "BLE_PAY_V1") {
                    val qrStr = intent.getStringExtra("V1_QR_DATA") ?: scannnedV1QR
                    if (qrStr != null) {
                        val v1qr = QRCodeHelper.parseV1QR(qrStr)
                        if (v1qr != null) {
                            // PRD-FIX: DO NOT call setLoading(false) here. 
                            // Hide input and show progress immediately.
                            layoutInputState.visibility = View.GONE
                            
                            val initials = v1qr.pass.pass.displayName.take(1).uppercase()
                            showSessionProgress(PaymentSessionProgress(
                                phase = PaymentPhase.DISCOVERY, 
                                message = "Initializing connection...",
                                amountP = result.amount.toLong(),
                                peerName = v1qr.pass.pass.displayName,
                                payeeInitials = initials,
                                isPayer = true
                            ))
                            
                            startBleProtocolV1(v1qr, result.amount.toLong())
                            return
                        }
                    }
                }

                // For other actions (like ONLINE_PAY), we might still want to finish or transition
                setLoading(false)
                intent.putExtra("ACTION", action)
                intent.putExtra("PAYEE_ID", result.payeeId)
                intent.putExtra("AMOUNT", result.amount)
                intent.putExtra("PAYEE_PUB_KEY", identifiedPayeePubKey)
                
                // Pass through BLE/BT info if it was stored from QR scan
                val bleId = this.intent.getStringExtra("BLE_ID")
                val btName = this.intent.getStringExtra("BT_NAME")
                if (bleId != null) intent.putExtra("BLE_ID", bleId)
                if (btName != null) intent.putExtra("BT_NAME", btName)
                
                setResult(RESULT_OK, intent)
                finish()
            }
        }
    }

    private fun startBleProtocolV1(v1qr: com.offlinewallet.models.V1QR, amount: Long) {
        val bleManager = BLEManagerSingleton.getInstance()
        val finalV1QR = if (amount > 0) v1qr.copy(amountP = amount) else v1qr
        
        bleManager.onPhaseChanged = { progress ->
            showSessionProgress(progress)
        }

        bleManager.startPayerFlow(
            payerId = com.offlinewallet.SecureStorage.getWalletId()!!,
            amount = finalV1QR.amountP?.toInt() ?: 0,
            sid = finalV1QR.sid,
            bobPass = finalV1QR.pass,
            bobEpk = com.offlinewallet.crypto.HexUtils.decodeSafe(finalV1QR.epk_B),
            bobChal = com.offlinewallet.crypto.HexUtils.decodeSafe(finalV1QR.chal_B),
            callbacks = object : BLEManager.PaymentCallbacks {
                override fun onPaymentInitiated() {}
                override fun onChallengeReceived(challenge: ByteArray) {
                    // WP-FIX: Alice (Payer) might receive a challenge for re-auth (optional in v1)
                    Log.d("SmartPay", "Challenge received: ${challenge.size} bytes")
                }
                override fun onPaymentAccepted(receipt: com.offlinewallet.models.Receipt) {
                    // Bob accepted M3. Alice is now finalizing M4.
                    Log.i("SmartPay", "Payment Accepted by recipient. Finalizing...")
                }
                override fun onPaymentError(error: String) {
                    runOnUiThread {
                        setLoading(false)
                        layoutInputState.visibility = View.VISIBLE
                        Toast.makeText(this@SmartPayActivity, "Payment Error: $error", Toast.LENGTH_LONG).show()
                    }
                }
                override fun onPaymentComplete(newBalance: Int) {
                    runOnUiThread { 
                        Toast.makeText(this@SmartPayActivity, "Payment Successful!", Toast.LENGTH_LONG).show()
                        sessionBottomSheet?.dismiss()
                        // Notify parent to refresh
                        val resultIntent = Intent()
                        resultIntent.putExtra("STATUS", "SUCCESS")
                        resultIntent.putExtra("NEW_BALANCE", newBalance)
                        setResult(RESULT_OK, resultIntent)
                        finish()
                    }
                }
            }
        )
    }

    private fun showSessionProgress(progress: PaymentSessionProgress) {
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            
            if (sessionBottomSheet == null || !sessionBottomSheet!!.isAdded) {
                sessionBottomSheet = PaymentSessionBottomSheet.newInstance()
                try {
                    sessionBottomSheet!!.show(supportFragmentManager, PaymentSessionBottomSheet.TAG)
                } catch (e: Exception) {
                    android.util.Log.e("SmartPay", "Failed to show progress sheet", e)
                }
            }
            sessionBottomSheet!!.updateProgress(progress)
        }
    }


    private fun setLoading(isLoading: Boolean) {
        if (isFinishing || isDestroyed) return
        progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
        btnPayNow.isEnabled = !isLoading
        btnPayNow.text = if (isLoading) "Processing..." else "Pay Securely"
        etPayeeId.isEnabled = !isLoading
        etAmount.isEnabled = !isLoading
    }

    private fun showPayeeVerificationDialog(v1qr: com.offlinewallet.models.V1QR, raw: String) {
        val p = v1qr.pass.pass
        val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.getDefault())
        
        // WP-History: Audit Bob's chain before showing the dialog
        val bobPub = com.offlinewallet.crypto.KeyManager.bytesToPublicKey(com.offlinewallet.crypto.HexUtils.decodeSafe(p.devicePubKey ?: ""))
        Log.d("SmartPay", "[AUDIT] Alice auditing Bob: ${v1qr.history.size} blocks in QR. Anchor: ${p.lastSettledHead.take(8)}")
        val isHistoryValid = bobPub != null && com.offlinewallet.crypto.HashChainManager.verifyHistory(v1qr.history, p.lastSettledHead, bobPub)
        
        val message = buildString {
            append("--- RECIPIENT IDENTITY ---\n")
            append("Name: ${p.displayName}\n")
            append("Wallet: ${p.walletId}\n")
            append("Tier: ${p.attestTier}\n")
            append("Counter: ${p.lastSettledCounter}\n\n")
            
            append("--- LIVE LEDGER AUDIT ---\n")
            if (isHistoryValid) {
                append("History: verified ✓ (${v1qr.history.size} blocks)\n")
                append("Anchor: ${p.lastSettledHead.take(8)}... OK\n\n")
            } else {
                append("🚨 SECURITY ALERT: History Divergent\n")
                append("💡 Solution: Recipient must sync with the server to fix their ledger.\n\n")
                append("Transaction blocked for safety.\n\n")
            }
            
            append("--- SESSION SECURITY ---\n")
            append("Session ID: ${v1qr.sid}\n")
            append("BLE Link ID: ${v1qr.bleUuid}\n")
            append("Expires: ${sdf.format(java.util.Date(p.expiresAt * 1000))}\n\n")
            
            append("--- PROTOCOL --- \n")
            append("1. Bluetooth Low Energy (BLE): Secure Data Transfer\n")
            append("2. Tap-to-Pay removed for improved reliability.\n")
        }

        val scroll = android.widget.ScrollView(this)
        val tv = TextView(this).apply {
            text = message
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            setPadding(48, 48, 48, 48)
            setTextColor(if (isHistoryValid) android.graphics.Color.BLACK else android.graphics.Color.RED)
        }
        scroll.addView(tv)

        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(if (isHistoryValid) "Verify Recipient" else "⚠️ SECURITY ALERT")
            .setView(scroll)
            .setNegativeButton("Cancel", null)

        if (isHistoryValid) {
            dialog.setPositiveButton("Proceed") { _, _ ->
                scannnedV1QR = raw
                identifiedPayeeId = p.walletId
                identifiedPayeePubKey = p.devicePubKeyHash
                onPayeeIdentified(identifiedPayeeId!!, p.displayName)
                
                toggleMethod.check(R.id.btnMethodBLE)
                etAmount.requestFocus()
                etAmount.postDelayed({
                    val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                    imm.showSoftInput(etAmount, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
                }, 200)
                
                Toast.makeText(this, "Identity Verified. Ready for Bluetooth Pay.", Toast.LENGTH_SHORT).show()
            }
        }
        
        dialog.show()
    }
}
