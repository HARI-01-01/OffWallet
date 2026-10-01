package com.offlinewallet.ui.payment

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import java.util.Locale
import androidx.core.content.ContextCompat
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.offlinewallet.R
import com.offlinewallet.payment.ble.PaymentPhase
import com.offlinewallet.payment.ble.PaymentSessionProgress

class PaymentSessionBottomSheet : BottomSheetDialogFragment() {

    private lateinit var tvStatus: TextView
    private lateinit var tvDetail: TextView
    private lateinit var tvResolution: TextView
    private lateinit var tvPeerName: TextView
    private lateinit var tvSessionAmount: TextView
    private lateinit var tvPayeeInitials: TextView
    private lateinit var ivStepDiscovery: ImageView
    private lateinit var ivStepIdentity: ImageView
    private lateinit var ivStepSecurity: ImageView
    private lateinit var progressCircular: ProgressBar
    private lateinit var successContainer: View
    private lateinit var vSuccessBg: View
    private lateinit var ivSuccessCheck: ImageView
    private lateinit var btnClose: View

    private var currentProgress: PaymentSessionProgress? = null

    // Cache to prevent 0.0 or "?" when partial updates arrive
    private var lastAmount: Long? = null
    private var lastInitials: String? = null
    private var lastPeerName: String? = null
    private var lastIsPayer: Boolean = true

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.bottom_sheet_payment_session, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        tvStatus = view.findViewById(R.id.tvSessionStatus)
        tvDetail = view.findViewById(R.id.tvSessionDetail)
        tvResolution = view.findViewById(R.id.tvResolution)
        tvPeerName = view.findViewById(R.id.tvPeerName)
        tvSessionAmount = view.findViewById(R.id.tvSessionAmount)
        tvPayeeInitials = view.findViewById(R.id.tvPayeeInitials)
        
        ivStepDiscovery = view.findViewById(R.id.ivStepDiscovery)
        ivStepIdentity = view.findViewById(R.id.ivStepIdentity)
        ivStepSecurity = view.findViewById(R.id.ivStepSecurity)
        
        progressCircular = view.findViewById(R.id.progressSessionCircular)
        successContainer = view.findViewById(R.id.successContainer)
        vSuccessBg = view.findViewById(R.id.vSuccessBg)
        ivSuccessCheck = view.findViewById(R.id.ivSuccessCheck)
        btnClose = view.findViewById(R.id.btnSessionClose)

        btnClose.setOnClickListener { dismiss() }
        
        currentProgress?.let { updateUi(it) }
    }

    fun updateProgress(progress: PaymentSessionProgress) {
        currentProgress = progress
        if (isAdded) {
            updateUi(progress)
        }
    }

    private fun updateUi(p: PaymentSessionProgress) {
        // Update caches
        p.amountP?.let { lastAmount = it }
        p.payeeInitials?.let { lastInitials = it }
        p.peerName?.let { lastPeerName = it }
        lastIsPayer = p.isPayer

        tvStatus.text = when(p.phase) {
            PaymentPhase.DISCOVERY -> "Searching for recipient..."
            PaymentPhase.CONNECTING -> "Connecting..."
            PaymentPhase.IDENTITY -> "Verifying Identity..."
            PaymentPhase.AUDIT -> "Auditing Ledger..."
            PaymentPhase.DEBITING -> if (lastIsPayer) "Sending funds..." else "Receiving funds..."
            PaymentPhase.FINALIZING -> "Finalizing..."
            PaymentPhase.SUCCESS -> if (lastIsPayer) "Payment Successful" else "Received Successfully"
            PaymentPhase.ERROR -> "Transaction Failed"
            PaymentPhase.DOUBTFUL -> "Verification Required"
        }
        
        tvDetail.text = p.message
        
        lastAmount?.let { 
            if (it > 0) {
                tvSessionAmount.text = "₹${String.format(Locale.getDefault(), "%.2f", it / 100.0)}"
            } else if (!lastIsPayer) {
                tvSessionAmount.text = "Waiting for amount..."
            }
        }
        
        lastInitials?.let { tvPayeeInitials.text = it }
        lastPeerName?.let { tvPeerName.text = if (lastIsPayer) "Paying $it" else "Receiving from $it" }
        if (lastPeerName == null && !lastIsPayer) tvPeerName.text = "Incoming Payment"

        if (p.errorCode != null) {
            tvDetail.text = "${p.errorCode}: ${p.message}"
            tvDetail.setTextColor(Color.parseColor("#E53935"))
            tvResolution.visibility = View.VISIBLE
            tvResolution.text = getResolution(p.errorCode)
        } else {
            tvDetail.setTextColor(Color.parseColor("#8B90A0"))
            tvResolution.visibility = View.GONE
        }

        updateSteps(p.phase)

        when (p.phase) {
            PaymentPhase.SUCCESS -> showSuccess()
            PaymentPhase.ERROR -> showError()
            PaymentPhase.DOUBTFUL -> showDoubtful()
            else -> {
                progressCircular.visibility = View.VISIBLE
                successContainer.visibility = View.GONE
                btnClose.visibility = View.GONE
            }
        }
    }

    private fun updateSteps(phase: PaymentPhase) {
        val activeColor = ColorStateList.valueOf(Color.parseColor("#4CAF50"))
        val inactiveColor = ColorStateList.valueOf(Color.parseColor("#6B7080"))

        // Discovery Step
        if (phase.ordinal >= PaymentPhase.CONNECTING.ordinal) {
            ivStepDiscovery.imageTintList = activeColor
            ivStepDiscovery.setImageResource(android.R.drawable.checkbox_on_background)
        } else {
            ivStepDiscovery.imageTintList = inactiveColor
            ivStepDiscovery.setImageResource(android.R.drawable.presence_online)
        }

        // Identity Step
        if (phase.ordinal >= PaymentPhase.AUDIT.ordinal) {
            ivStepIdentity.imageTintList = activeColor
            ivStepIdentity.setImageResource(android.R.drawable.checkbox_on_background)
        } else {
            ivStepIdentity.imageTintList = inactiveColor
            ivStepIdentity.setImageResource(android.R.drawable.ic_lock_idle_lock)
        }

        // Security/Protocol Step
        if (phase.ordinal >= PaymentPhase.FINALIZING.ordinal) {
            ivStepSecurity.imageTintList = activeColor
            ivStepSecurity.setImageResource(android.R.drawable.checkbox_on_background)
        } else {
            ivStepSecurity.imageTintList = inactiveColor
            ivStepSecurity.setImageResource(android.R.drawable.ic_dialog_info)
        }
    }

    private fun showSuccess() {
        progressCircular.visibility = View.GONE
        successContainer.visibility = View.VISIBLE
        btnClose.visibility = View.VISIBLE
        tvStatus.setTextColor(Color.parseColor("#4285F4"))
        
        // GPay Pop Animation
        successContainer.scaleX = 0.5f
        successContainer.scaleY = 0.5f
        successContainer.animate()
            .scaleX(1.1f)
            .scaleY(1.1f)
            .setDuration(400)
            .withEndAction {
                successContainer.animate().scaleX(1.0f).scaleY(1.0f).setDuration(200).start()
            }.start()
    }

    private fun showError() {
        progressCircular.visibility = View.GONE
        successContainer.visibility = View.GONE
        btnClose.visibility = View.VISIBLE
        tvStatus.setTextColor(Color.parseColor("#E53935"))
    }

    private fun showDoubtful() {
        progressCircular.visibility = View.GONE
        successContainer.visibility = View.VISIBLE
        vSuccessBg.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#FFC107"))
        ivSuccessCheck.setImageResource(android.R.drawable.ic_dialog_alert)
        btnClose.visibility = View.VISIBLE
    }

    private fun getResolution(code: String): String {
        return when {
            code.contains("1002") || code.contains("1003") -> "💡 Solution: Peer must Sync with server."
            code.contains("2002") -> "💡 Solution: Bluetooth mismatch. Re-scan QR."
            code.contains("3000") -> "💡 Solution: Top up your offline vault."
            code.contains("5001") -> "💡 Solution: Signal interference. Try again."
            else -> "💡 Solution: Restart Bluetooth and try again."
        }
    }

    override fun onDismiss(dialog: android.content.DialogInterface) {
        super.onDismiss(dialog)
        com.offlinewallet.payment.ble.BLEManagerSingleton.getInstance().stop()
    }

    companion object {
        const val TAG = "PaymentSessionBottomSheet"
        fun newInstance() = PaymentSessionBottomSheet()
    }
}
