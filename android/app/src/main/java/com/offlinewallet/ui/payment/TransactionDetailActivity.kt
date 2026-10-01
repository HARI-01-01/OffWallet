package com.offlinewallet.ui.payment

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
import androidx.lifecycle.lifecycleScope
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.QueueManager
import com.offlinewallet.models.Transaction
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.*

class TransactionDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_transaction_detail)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.detailAppBar)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top)
            
            // Handle bottom insets for the CTA button
            findViewById<View>(R.id.ctaContainer).updatePadding(bottom = bars.bottom)
            
            insets
        }

        findViewById<View>(R.id.btnBack).setOnClickListener { finish() }
        findViewById<Button>(R.id.btnViewOnChain).setOnClickListener {
            startActivity(Intent(this, BlockchainExplorerActivity::class.java))
        }

        val txId = intent.getStringExtra("TX_ID") ?: return
        
        lifecycleScope.launch {
            val tx = withContext(Dispatchers.IO) {
                val qm = QueueManager(this@TransactionDetailActivity)
                qm.getAllTransactions().find { it.localId == txId }
            }

            tx?.let { populateUi(it) }
        }
    }

    private fun populateUi(tx: Transaction) {
        findViewById<TextView>(R.id.tvCurrentBalance).text = String.format(Locale.US, "₹%,.2f", SecureStorage.getBalance() / 100.0)
        
        val isIncoming = tx.payeeId == SecureStorage.getWalletId()
        findViewById<TextView>(R.id.tvTargetName).text = if (isIncoming) "From: ${tx.payerId}" else "To: ${tx.payeeId}"
        
        findViewById<TextView>(R.id.tvMethod).text = String.format(Locale.US, "%s · hardware-bound", tx.method)
        findViewById<TextView>(R.id.tvAmount).text = String.format(Locale.US, "%s₹%,.2f", if (isIncoming) "+" else "−", tx.amount / 100.0)
        findViewById<TextView>(R.id.tvChainPos).text = String.format(Locale.US, "Block #%d · %s", tx.counter, tx.status)
        findViewById<TextView>(R.id.tvBlockHash).text = String.format(Locale.US, "%s...", tx.localId.take(16))
    }
}
