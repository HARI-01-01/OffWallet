package com.offlinewallet.ui

import android.os.Bundle
import android.view.View
import android.widget.ImageButton
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.RecyclerView
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.QueueManager
import kotlinx.coroutines.launch

class FullHistoryActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_history)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.historyToolbar)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top)
            insets
        }

        findViewById<ImageButton>(R.id.btnBackHistory).setOnClickListener { finish() }

        val rv = findViewById<RecyclerView>(R.id.rvFullHistory)
        val emptyState = findViewById<View>(R.id.emptyHistoryState)
        
        val walletId = SecureStorage.getWalletId()
        val queueManager = QueueManager(this)
        
        val adapter = TransactionAdapter(emptyList(), walletId, 
            onVerifyClick = { /* Handled in MainActivity primarily, but could add here */ },
            onCancelClick = { /* Optional */ }
        )
        rv.adapter = adapter

        lifecycleScope.launch {
            val transactions = queueManager.getAllTransactions()
            if (transactions.isEmpty()) {
                emptyState.visibility = View.VISIBLE
                rv.visibility = View.GONE
            } else {
                emptyState.visibility = View.GONE
                rv.visibility = View.VISIBLE
                adapter.updateData(transactions, walletId)
            }
        }
    }
}
