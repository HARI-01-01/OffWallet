package com.offlinewallet.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.BiometricHelper
import com.offlinewallet.crypto.HexUtils
import com.offlinewallet.crypto.ShadowProtocol
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class ProfileActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_profile)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById<View>(R.id.profileHeader).parent as View) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top, bottom = bars.bottom)
            insets
        }

        findViewById<TextView>(R.id.tvProfileName).text = SecureStorage.getWalletName() ?: "User"
        findViewById<TextView>(R.id.tvProfileEmail).text = SecureStorage.getEmail() ?: "Not logged in"
        findViewById<TextView>(R.id.tvWalletId).text = SecureStorage.getWalletId() ?: "user_none"
        
        val pubKey = SecureStorage.getPublicKey()
        if (pubKey != null) {
            val hash = ShadowProtocol.sha256(HexUtils.decodeSafe(pubKey))
            findViewById<TextView>(R.id.tvPubKeyHash).text = "SHA256: ${HexUtils.encodeHex(hash).take(16)}..."
        } else {
            findViewById<TextView>(R.id.tvPubKeyHash).text = "Hardware Key Not Initialized"
        }

        findViewById<Button>(R.id.btnLogoutProfile).setOnClickListener {
            val bio = BiometricHelper(this)
            bio.authenticate(
                this,
                "Authenticate to Logout",
                "Confirm your identity to wipe local data and logout.",
                "Use fingerprint or device lock",
                onSuccess = {
                    lifecycleScope.launch {
                        SecureStorage.clear()
                        val intent = Intent(this@ProfileActivity, com.offlinewallet.ui.auth.LoginActivity::class.java)
                        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                        startActivity(intent)
                        finish()
                    }
                },
                onFailure = { error ->
                    Toast.makeText(this, "Logout cancelled: $error", Toast.LENGTH_SHORT).show()
                }
            )
        }

        findViewById<Button>(R.id.btnHardResetProfile).setOnClickListener {
            val bio = BiometricHelper(this)
            bio.authenticate(
                this,
                "Authenticate for Hard Reset",
                "This will PERMANENTLY WIPE all hardware keys and ledger data.",
                "Fingerprint required",
                onSuccess = {
                    com.offlinewallet.utils.AppResetUtils.performHardReset(this@ProfileActivity)
                    finish()
                },
                onFailure = { error ->
                    Toast.makeText(this, "Reset cancelled: $error", Toast.LENGTH_SHORT).show()
                }
            )
        }

        findViewById<Button>(R.id.btnBackProfile).setOnClickListener { finish() }
    }
}
