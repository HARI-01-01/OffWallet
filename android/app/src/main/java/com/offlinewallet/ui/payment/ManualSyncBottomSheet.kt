package com.offlinewallet.ui.payment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.offlinewallet.R
import com.offlinewallet.payment.smart.ManualSyncManager
import com.offlinewallet.payment.smart.SyncPhase
import com.offlinewallet.payment.smart.SyncSessionProgress
import kotlinx.coroutines.launch

class ManualSyncBottomSheet : BottomSheetDialogFragment() {

    private lateinit var tvStatus: TextView
    private lateinit var tvDetail: TextView
    private lateinit var progressMain: ProgressBar
    private lateinit var btnClose: Button
    
    private var syncManager: ManualSyncManager? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.bottom_sheet_manual_sync, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        tvStatus = view.findViewById(R.id.tvSyncStatus)
        tvDetail = view.findViewById(R.id.tvSyncDetail)
        progressMain = view.findViewById(R.id.progressSync)
        btnClose = view.findViewById(R.id.btnSyncClose)

        btnClose.setOnClickListener { dismiss() }
        
        syncManager = ManualSyncManager(requireContext())
        startSync()
    }

    private fun startSync() {
        lifecycleScope.launch {
            syncManager?.performSync { progress ->
                updateUi(progress)
            }
        }
    }

    private fun updateUi(p: SyncSessionProgress) {
        activity?.runOnUiThread {
            tvStatus.text = when(p.phase) {
                SyncPhase.PREPARING -> "Preparing Sync"
                SyncPhase.FETCHING -> "Reading Ledger"
                SyncPhase.INTEGRITY -> "Hardware Audit"
                SyncPhase.UPLOADING -> "Syncing with Cloud"
                SyncPhase.PROCESSING -> "Settling Transactions"
                SyncPhase.SUCCESS -> "Sync Successful"
                SyncPhase.ERROR -> "Sync Failed"
            }
            
            tvDetail.text = p.message
            if (p.phase == SyncPhase.SUCCESS) {
                val summary = buildString {
                    append("Confirmed: ${p.settledCount} | Refunded: ${p.refundCount}\n\n")
                    if (p.results.isNotEmpty()) {
                        append("Ledger Changes:\n")
                        p.results.forEach { res ->
                            val prefix = if (res.status == "SETTLED") "✓" else "↺"
                            append("$prefix ₹${res.amountP/100.0} to ${res.peerId.takeLast(6)} (${res.status})\n")
                        }
                    } else {
                        append("Everything is already settled.")
                    }
                }
                tvDetail.text = summary
                progressMain.visibility = View.GONE
                btnClose.visibility = View.VISIBLE
            } else if (p.phase == SyncPhase.ERROR) {
                progressMain.visibility = View.GONE
                btnClose.visibility = View.VISIBLE
            } else {
                progressMain.visibility = View.VISIBLE
                btnClose.visibility = View.GONE
            }
        }
    }

    companion object {
        const val TAG = "ManualSyncBottomSheet"
        fun newInstance() = ManualSyncBottomSheet()
    }
}
