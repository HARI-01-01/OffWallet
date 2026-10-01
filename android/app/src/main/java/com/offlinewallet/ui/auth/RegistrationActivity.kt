package com.offlinewallet.ui.auth

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.offlinewallet.MainActivity
import com.offlinewallet.NetworkManager
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.auth.PhoneAuthHelper
import com.offlinewallet.crypto.*
import com.offlinewallet.models.ActivateRequest
import com.offlinewallet.models.UserRegisterRequest
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.FirebaseException
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

class RegistrationActivity : AppCompatActivity() {

    private lateinit var etEmail: EditText
    private lateinit var etPassword: EditText
    private lateinit var etWalletName: EditText
    private lateinit var btnRegister: Button
    private lateinit var tvLoginLink: TextView
    private lateinit var progressBar: ProgressBar

    private lateinit var networkManager: NetworkManager
    private var loadingDialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_registration)

        etEmail = findViewById(R.id.etEmail)
        etPassword = findViewById(R.id.etPassword)
        etWalletName = findViewById(R.id.etWalletName)
        btnRegister = findViewById(R.id.btnRegister)
        tvLoginLink = findViewById(R.id.tvLoginLink)
        progressBar = findViewById(R.id.progressBar)

        SecureStorage.init(this)
        HighWaterStore.init(this)
        networkManager = NetworkManager(this, com.offlinewallet.Config.BASE_URL)

        btnRegister.setOnClickListener { attemptRegistration() }
        tvLoginLink.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java))
        }
    }

    private fun attemptRegistration() {
        val walletName = etWalletName.text.toString().trim()
        val email = etEmail.text.toString().trim()
        val password = etPassword.text.toString().trim()
        
        if (walletName.isEmpty() || email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "Please fill all fields", Toast.LENGTH_SHORT).show()
            return
        }

        setLoading(true, "🔐 Creating Firebase Account...")
        val auth = FirebaseAuth.getInstance()
        
        auth.createUserWithEmailAndPassword(email, password)
            .addOnCompleteListener(this) { task ->
                if (task.isSuccessful) {
                    val user = auth.currentUser
                    user?.getIdToken(true)?.addOnCompleteListener { tokenTask ->
                        if (tokenTask.isSuccessful) {
                            val token = tokenTask.result?.token
                            if (token != null) {
                                proceedWithBackendRegistration(token)
                            } else {
                                setLoading(false)
                                Toast.makeText(this, "Failed to get auth token", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else {
                    setLoading(false)
                    val error = task.exception?.message ?: "Registration failed"
                    // If user already exists, try signing in instead to get the token
                    if (error.contains("already in use", ignoreCase = true)) {
                        signInAndProceed(email, password)
                    } else {
                        Toast.makeText(this, error, Toast.LENGTH_LONG).show()
                    }
                }
            }
    }

    private fun signInAndProceed(email: String, password: String) {
        setLoading(true, "🔓 Authenticating existing account...")
        FirebaseAuth.getInstance().signInWithEmailAndPassword(email, password)
            .addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    val user = FirebaseAuth.getInstance().currentUser
                    user?.getIdToken(true)?.addOnCompleteListener { tokenTask ->
                        val token = tokenTask.result?.token
                        if (token != null) proceedWithBackendRegistration(token)
                        else setLoading(false)
                    }
                } else {
                    setLoading(false)
                    Toast.makeText(this, "Auth failed: ${task.exception?.message}", Toast.LENGTH_SHORT).show()
                }
            }
    }

    private fun proceedWithBackendRegistration(token: String) {
        val walletName = etWalletName.text.toString().trim()
        val email = etEmail.text.toString().trim()

        lifecycleScope.launch {
            try {
                SecureStorage.saveApiKey(token)
                SecureStorage.saveEmail(email)

                // --- O1: REGISTER ---
                setLoading(true, "📡 Registering on Shadow Network...")
                val regRequest = UserRegisterRequest(walletName = walletName)
                val regResult = networkManager.registerUser(regRequest)
                
                if (regResult.isSuccess) {
                    val regData = regResult.getOrNull()!!
                    val walletId = regData.walletId
                    
                    // Critical Fix: Save the Server Public Key (Trust Anchor) provided during registration
                    // This is needed to verify the Genesis block signature in the next step.
                    if (regData.serverSpkiHash.isNotEmpty()) {
                        Log.d("REG", "Seeding Server Public Key from Registration: ${regData.serverSpkiHash}")
                        SecureStorage.saveServerPublicKey(regData.serverSpkiHash)
                    }
                    
                    val challengeB64 = regData.attestChallenge
                    val challenge = Base64.decode(challengeB64, Base64.DEFAULT)
                    val serverEphemeralPub = HexUtils.decodeHex(regData.ephemeralServerPubKey)

                    // --- O2: KEY CEREMONY (LOCAL) ---
                    setLoading(true, "🔐 Performing Hardware Key Ceremony...")
                    SecureKeyStore.init()
                    val keyPair = SecureKeyStore.generateAndStoreKeyPair(
                        this@RegistrationActivity, 
                        walletId, 
                        challenge = challenge
                    )

                    if (keyPair == null) {
                        throw Exception("Failed to generate hardware keys")
                    }

                    // Issue 2: AES Key Wrap
                    val dbk = Encryptor.generateKey() // Local DBK
                    val encryptedAesKey = KeyManager.encryptAesKeyWithServerEphemeral(dbk.encoded, serverEphemeralPub)
                    val encryptedAesKeyB64 = Base64.encodeToString(encryptedAesKey, Base64.NO_WRAP)

                    val devicePubKeyBytes = keyPair.public.encoded
                    val devicePubKey = Base64.encodeToString(devicePubKeyBytes, Base64.NO_WRAP)
                    val attestationChain = SecureKeyStore.getAttestationChain(walletId) ?: emptyList()

                    // Production requirement: Mandatory Play Integrity Token
                    setLoading(true, "🛡️ Verifying Device Integrity...")
                    val integrityNonce = ShadowProtocol.sha256(devicePubKeyBytes + walletId.toByteArray(Charsets.UTF_8) + challenge)
                    val integrityToken = IntegrityManager.fetchIntegrityToken(this@RegistrationActivity, integrityNonce)
                        ?: throw Exception("Device Integrity check failed. Cannot activate wallet on insecure device.")

                    // --- O3: ACTIVATE ---
                    setLoading(true, "🚀 Activating Hardware Wallet...")
                    val activateReq = ActivateRequest(
                        walletId = walletId,
                        devicePubKey = devicePubKey,
                        attestationChain = attestationChain,
                        integrityToken = integrityToken,
                        encryptedAesKey = encryptedAesKeyB64,
                        deviceLabel = android.os.Build.MODEL
                    )

                    val activateResult = networkManager.activateWallet(activateReq)
                    if (activateResult.isSuccess) {
                        val activateData = activateResult.getOrNull()!!
                        
                        // Save the Server Public Key from Activation (Trust Anchor)
                        activateData.serverPublicKey?.let { 
                            Log.d("REG", "Seeding Server Public Key from Activation: $it")
                            SecureStorage.saveServerPublicKey(it) 
                        }
                        
                        // --- O4: GENESIS & PERSISTENCE ---
                        setLoading(true, "📦 Sealing Genesis Block...")
                        SecureStorage.saveWalletId(walletId)
                        SecureStorage.saveWalletName(walletName)
                        SecureStorage.savePublicKey(devicePubKey)
                        SecureStorage.saveBalance(activateData.genesis.balanceP)
                        SecureStorage.saveLastSyncTime(System.currentTimeMillis())
                        SecureStorage.setAuthenticated(true)
                        
                        // Save Active Device Token and ID
                        SecureStorage.saveApiKey(activateData.activeDeviceToken)
                        SecureStorage.saveDeviceId(activateData.deviceId)
                        
                        // Save DBK
                        SecureStorage.saveAesKey(HexUtils.encodeHex(dbk.encoded))

                        // WP-13: Recovery Setup
                        val mnemonic = MnemonicManager.generateMnemonic()
                        SecureStorage.saveMnemonic(mnemonic)
                        if (activateData.recoveryShard1 != null) {
                            CloudBackupManager.backupShard(activateData.recoveryShard1)
                        }

                        // Initialize local database with genesis state
                        val bucketManager = BucketManager(this@RegistrationActivity)
                        val success = bucketManager.createBucketV1(
                            walletId = walletId,
                            genesis = activateData.genesis,
                            serverSignature = HexUtils.decodeHex(activateData.sig),
                            serverPublicKeyOverride = activateData.serverPublicKey
                        )

                        if (success) {
                            // --- O5: REFRESH PASS ---
                            setLoading(true, "🎟️ Fetching Security Pass...")
                            // Fetch a fresh integrity token for the pass refresh (IntegrityManager handles throttling internally)
                            val passNonce = ShadowProtocol.sha256(devicePubKeyBytes + walletId.toByteArray() + "pass_refresh".toByteArray())
                            val passIntegrityToken = IntegrityManager.fetchIntegrityToken(this@RegistrationActivity, passNonce)
                                ?: throw Exception("Failed to verify integrity for security pass")
                            
                            val passResult = networkManager.refreshPass(passIntegrityToken)
                            if (passResult.isSuccess) {
                                val passEnv = passResult.getOrNull()!!
                                SecureStorage.savePass(passEnv)
                                
                                setLoading(false)
                                Toast.makeText(this@RegistrationActivity, "Shadow Wallet Activated!", Toast.LENGTH_LONG).show()
                                startActivity(Intent(this@RegistrationActivity, MainActivity::class.java).apply {
                                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                                })
                                finish()
                            } else {
                                throw Exception("Initial pass fetch failed")
                            }
                        } else {
                            throw Exception("Local vault initialization failed")
                        }
                    } else {
                        throw Exception("Activation failed: ${activateResult.exceptionOrNull()?.message}")
                    }
                } else {
                    throw Exception("Registration failed: ${regResult.exceptionOrNull()?.message}")
                }

            } catch (e: Exception) {
                setLoading(false)
                Log.e("REG", "Error", e)
                Toast.makeText(this@RegistrationActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun setLoading(isLoading: Boolean, message: String = "Please wait...") {
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
            btnRegister.isEnabled = !isLoading
            
            etEmail.isEnabled = !isLoading
            etPassword.isEnabled = !isLoading
            etWalletName.isEnabled = !isLoading
        }
    }
}
