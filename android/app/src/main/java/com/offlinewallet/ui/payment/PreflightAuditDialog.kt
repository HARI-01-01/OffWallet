package com.offlinewallet.ui.payment

import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.ProgressBar
import com.offlinewallet.R
import com.offlinewallet.crypto.BucketManager

class PreflightAuditDialog(context: Context) : Dialog(context, R.style.NfcPaymentDialogTheme), BucketManager.AuditListener {

    private lateinit var pbBinary: ProgressBar
    private lateinit var ivBinary: ImageView
    private lateinit var pbHead: ProgressBar
    private lateinit var ivHead: ImageView
    private lateinit var pbChain: ProgressBar
    private lateinit var ivChain: ImageView
    private lateinit var stepHead: View
    private lateinit var stepChain: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.dialog_preflight_audit)
        setCancelable(false)

        pbBinary = findViewById(R.id.pbBinary)
        ivBinary = findViewById(R.id.ivBinary)
        pbHead = findViewById(R.id.pbHeadNode)
        ivHead = findViewById(R.id.ivHeadNode)
        pbChain = findViewById(R.id.pbChain)
        ivChain = findViewById(R.id.ivChain)
        stepHead = findViewById(R.id.stepHeadNode)
        stepChain = findViewById(R.id.stepChain)
    }

    override fun onStepComplete(step: BucketManager.AuditStep, success: Boolean) {
        (context as? android.app.Activity)?.runOnUiThread {
            when (step) {
                BucketManager.AuditStep.BINARY_CHECK -> {
                    pbBinary.visibility = View.GONE
                    ivBinary.visibility = View.VISIBLE
                    ivBinary.setImageResource(if (success) android.R.drawable.ic_input_add else android.R.drawable.ic_delete)
                    
                    if (success) {
                        stepHead.alpha = 1.0f
                        pbHead.visibility = View.VISIBLE
                    }
                }
                BucketManager.AuditStep.HEAD_NODE_CHECK -> {
                    pbHead.visibility = View.GONE
                    ivHead.visibility = View.VISIBLE
                    ivHead.setImageResource(if (success) android.R.drawable.ic_input_add else android.R.drawable.ic_delete)
                    
                    if (success) {
                        stepChain.alpha = 1.0f
                        pbChain.visibility = View.VISIBLE
                    }
                }
                BucketManager.AuditStep.GENESIS_WALKBACK -> {
                    pbChain.visibility = View.GONE
                    ivChain.visibility = View.VISIBLE
                    ivChain.setImageResource(if (success) android.R.drawable.ic_input_add else android.R.drawable.ic_delete)
                }
            }
        }
    }
}
