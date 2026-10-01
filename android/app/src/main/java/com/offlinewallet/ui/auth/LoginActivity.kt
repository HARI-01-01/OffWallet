package com.offlinewallet.ui.auth

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.offlinewallet.MainActivity
import com.offlinewallet.NetworkManager
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.*
import com.offlinewallet.models.UserLoginRequest
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

class LoginActivity : AppCompatActivity() {

    private lateinit var etEmail: EditText
    private lateinit var etPassword: EditText
    private lateinit var btnLogin: Button
    private lateinit var tvSignUpLink: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var networkManager: NetworkManager
    private var loadingDialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        etEmail = findViewById(R.id.etEmail)
        etPassword = findViewById(R.id.etPassword)
        btnLogin = findViewById(R.id.btnLogin)
        tvSignUpLink = findViewById(R.id.tvSignUpLink)
        progressBar = findViewById(R.id.progressBar)

        SecureStorage.init(this)
        networkManager = NetworkManager(this, com.offlinewallet.Config.BASE_URL)

        btnLogin.setOnClickListener { attemptLogin() }
        tvSignUpLink.setOnClickListener {
            startActivity(Intent(this, RegistrationActivity::class.java))
        }

        findViewById<Button>(R.id.btnHardReset).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Factory Reset")
                .setMessage("This will delete all hardware keys, ledger history, and local wallet data. This action is irreversible. Proceed?")
                .setPositiveButton("Reset Everything") { _, _ ->
                    com.offlinewallet.utils.AppResetUtils.performHardReset(this)
                    finish()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun attemptLogin() {
        val email = etEmail.text.toString().trim()
        val password = etPassword.text.toString().trim()

        if (email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "Please enter email and password", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            try {
                setLoading(true, "🔐 Authenticating...")
                
                // --- 1. Firebase Authentication ---
                val auth = com.google.firebase.auth.FirebaseAuth.getInstance()
                try {
                    val authResult = auth.signInWithEmailAndPassword(email, password).await()
                    val tokenResult = authResult.user?.getIdToken(true)?.await()
                    val token = tokenResult?.token
                    if (token != null) {
                        SecureStorage.saveApiKey(token)
                    }
                } catch (e: Exception) {
                    Log.e("Login", "Firebase auth failed, attempting backend with fallback", e)
                }

                // --- 2. Backend Login ---
                val loginRequest = UserLoginRequest(email = email, password = password)
                val result = networkManager.loginUser(loginRequest)

                if (result.isSuccess) {
                    val data = result.getOrNull()!!
                    Log.d("Login", "Successfully logged in user: ${data.walletId}, walletName: ${data.walletName}")
                    
                    // 1. Store Authentication Data Securely
                    SecureStorage.saveWalletId(data.walletId)
                    SecureStorage.saveEmail(data.email)
                    SecureStorage.saveWalletName(data.walletName)
                    SecureStorage.saveBalance(data.balance)
                    
                    // Priority: data.devToken > current firebase token > data.firebaseToken > fallback
                    val finalToken = data.devToken ?: SecureStorage.getApiKey() ?: data.firebaseToken ?: "dev_${data.walletId}"
                    SecureStorage.saveApiKey(finalToken)
                    
                    // Security Note: We no longer store private_key from server for production.
                    // Access is hardware-bound. Re-registration required on new devices.
                    data.publicKey?.let { SecureStorage.savePublicKey(it) }
                    data.serverPublicKey?.let { SecureStorage.saveServerPublicKey(it) }
                    data.serverSignature?.let { SecureStorage.saveServerSignature(it) }
                    
                    SecureStorage.setAuthenticated(true)
                    
                    // 2. Initialize local bucket
                    // Check if we have hardware keys first
                    SecureKeyStore.init()
                    val hasHardwareKeys = SecureKeyStore.keyExists(data.walletId)
                    
                    if (hasHardwareKeys && SecureStorage.getAesKey() != null) {
                        Toast.makeText(this@LoginActivity, "Welcome back!", Toast.LENGTH_SHORT).show()
                        navigateToDashboard()
                    } else if (data.privateKey != null && data.aesKey != null && data.serverPublicKey != null && data.serverSignature != null) {
                        initializeLocalBucket(data)
                    } else {
                        Toast.makeText(this@LoginActivity, "Login successful. Note: Limited offline access on this device.", Toast.LENGTH_LONG).show()
                        navigateToDashboard()
                    }
                } else {
                    setLoading(false)
                    Toast.makeText(this@LoginActivity, "Login failed: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                }

            } catch (e: Exception) {
                setLoading(false)
                Toast.makeText(this@LoginActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun navigateToDashboard() {
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }

    private suspend fun initializeLocalBucket(data: com.offlinewallet.models.UserLoginResponse) {
        try {
            val bucketManager = com.offlinewallet.crypto.BucketManager(this)
            val aesKeyBytes = HexUtils.decodeSafe(data.aesKey!!)
            val serverPubBytes = HexUtils.decodeSafe(data.serverPublicKey!!)
            val serverSigBytes = HexUtils.decodeSafe(data.serverSignature!!)

            val success = bucketManager.createBucket(
                walletId = data.walletId,
                initialBalance = data.balance,
                counter = data.counter,
                aesKey = aesKeyBytes,
                serverPublicKey = serverPubBytes,
                serverSignature = serverSigBytes
            )

            if (success) {
                Toast.makeText(this, "Welcome back to OfflineWallet!", Toast.LENGTH_LONG).show()
                navigateToDashboard()
            } else {
                setLoading(false)
                Toast.makeText(this, "Failed to initialize wallet storage", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            setLoading(false)
            Toast.makeText(this, "Error initializing bucket: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setLoading(isLoading: Boolean, message: String = "Authorizing...") {
        runOnUiThread {
            if (isLoading) {
                if (loadingDialog == null) {
                    loadingDialog = AlertDialog.Builder(this)
                        .setView(R.layout.dialog_auth_loading)
                        .setCancelable(false)
                        .create()
                }
                loadingDialog?.show()
                loadingDialog?.findViewById<TextView>(R.id.tvAuthLoadingMessage)?.text = message
            } else {
                loadingDialog?.dismiss()
                loadingDialog = null
            }

            progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
            btnLogin.isEnabled = !isLoading
            etEmail.isEnabled = !isLoading
            etPassword.isEnabled = !isLoading
        }
    }
}
