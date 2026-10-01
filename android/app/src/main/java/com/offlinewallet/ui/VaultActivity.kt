package com.offlinewallet.ui

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

class VaultActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_vault)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById<View>(R.id.tvVaultTitle).parent as View) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top, bottom = bars.bottom)
            insets
        }

        val tvMnemonic = findViewById<TextView>(R.id.tvMnemonicPlaceholder)
        val btnReveal = findViewById<Button>(R.id.btnRevealMnemonic)
        val btnBack = findViewById<Button>(R.id.btnBack)

        btnReveal.setOnClickListener {
            val mnemonic = SecureStorage.getMnemonic() ?: "No mnemonic found. Please re-register."
            tvMnemonic.text = mnemonic
            tvMnemonic.letterSpacing = 0.05f
            btnReveal.isEnabled = false
            btnReveal.text = "Phrase Revealed"
        }

        btnBack.setOnClickListener { finish() }
    }
}
