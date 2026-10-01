package com.offlinewallet.ui

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.offlinewallet.R
import com.offlinewallet.crypto.QueueManager
import com.offlinewallet.models.Transaction
import java.text.SimpleDateFormat
import java.util.*

class TransactionAdapter(
    private var transactions: List<Transaction>,
    private var currentWalletId: String? = null,
    private val onVerifyClick: ((Transaction) -> Unit)? = null,
    private val onCancelClick: ((Transaction) -> Unit)? = null,
    private val onItemClick: ((Transaction) -> Unit)? = null
) : RecyclerView.Adapter<TransactionAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.txIcon)
        val iconContainer: View = view.findViewById(R.id.txIconContainer)
        val targetText: TextView = view.findViewById(R.id.txTarget)
        val dateText: TextView = view.findViewById(R.id.txDate)
        val amountText: TextView = view.findViewById(R.id.txAmount)
        val counterText: TextView = view.findViewById(R.id.txCounter)
        val verifyBtn: android.widget.Button = view.findViewById(R.id.btnVerifyPin)
        val cancelBtn: android.widget.Button = view.findViewById(R.id.btnCancelTx)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_transaction, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val tx = transactions[position]
        val context = holder.itemView.context
        
        val isIncoming = tx.payeeId == currentWalletId
        val isTopup = tx.method == "TOPUP"
        
        if (isTopup) {
            holder.targetText.text = "Top-up: Server → Vault"
            holder.amountText.text = String.format("+₹%.2f", tx.amount / 100.0)
            holder.amountText.setTextColor(ContextCompat.getColor(context, R.color.verified_green))
            holder.icon.setImageResource(android.R.drawable.ic_input_add)
            holder.iconContainer.backgroundTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#0F1A17"))
            holder.icon.imageTintList = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(context, R.color.verified_green))
        } else if (isIncoming) {
            holder.targetText.text = "From: ${tx.payerId}"
            holder.amountText.text = String.format("+₹%.2f", tx.amount / 100.0)
            holder.amountText.setTextColor(ContextCompat.getColor(context, R.color.verified_green))
            holder.icon.setImageResource(android.R.drawable.ic_menu_revert) // Incoming icon
            holder.iconContainer.backgroundTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#0F1A17"))
            holder.icon.imageTintList = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(context, R.color.verified_green))
        } else {
            holder.targetText.text = "To: ${tx.payeeId}"
            holder.amountText.text = String.format("-₹%.2f", tx.amount / 100.0)
            holder.amountText.setTextColor(ContextCompat.getColor(context, R.color.white))
            holder.icon.setImageResource(android.R.drawable.ic_menu_send) // Outgoing icon
            holder.iconContainer.backgroundTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#1F1416"))
            holder.icon.imageTintList = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(context, R.color.outgoing_red))
        }

        val sdf = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
        holder.dateText.text = sdf.format(Date(tx.timestamp * 1000))
        
        holder.counterText.text = "Block #${tx.counter}"

        // Special styling for PENDING status or Branches
        val isActive = tx.method == "OFFLINE_ACTIVE"
        val isSettled = tx.status == QueueManager.STATUS_SETTLED || tx.status == "PROCESSED" || tx.status == "ALREADY_SETTLED"
        
        if (isTopup || isSettled) {
            holder.counterText.text = if (isTopup) "Success · Ledger Reload" else "Success · Block #${tx.counter}"
            if (isIncoming || isTopup) {
                holder.amountText.setTextColor(ContextCompat.getColor(context, R.color.verified_green))
            }
        } else if (isActive || tx.status == QueueManager.STATUS_PENDING_MUTUAL_PIN || tx.status == QueueManager.STATUS_QUEUED || tx.status == QueueManager.STATUS_FAILED) {
            holder.amountText.setTextColor(ContextCompat.getColor(context, R.color.pending_orange))
            holder.iconContainer.backgroundTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#1A160F"))
            holder.icon.imageTintList = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(context, R.color.pending_orange))
            
            if (isActive) {
                holder.counterText.text = "⌛ ${tx.status.lowercase().replace("_", " ")}..."
            } else if (tx.status == QueueManager.STATUS_FAILED) {
                holder.counterText.text = "⚠️ Branch · Block #${tx.counter}"
            } else if (tx.status == QueueManager.STATUS_QUEUED) {
                holder.counterText.text = "Awaiting sync · Block #${tx.counter}"
            }
        }

        // PIN Verification Button: Show for both roles if pending mutual PIN or failed
        val isPending = tx.status == QueueManager.STATUS_PENDING_MUTUAL_PIN || tx.status == QueueManager.STATUS_FAILED
        
        if (isPending) {
            holder.verifyBtn.visibility = View.VISIBLE
            holder.verifyBtn.text = if (tx.status == QueueManager.STATUS_FAILED) "Retry" else "Verify"
            holder.verifyBtn.setOnClickListener { onVerifyClick?.invoke(tx) }
            
            // Cancel Button: Show for Alice's outgoing only
            if (!isIncoming) {
                holder.cancelBtn.visibility = View.VISIBLE
                holder.cancelBtn.setOnClickListener { onCancelClick?.invoke(tx) }
            } else {
                holder.cancelBtn.visibility = View.GONE
            }
        } else if (tx.status == QueueManager.STATUS_QUEUED && isIncoming) {
            // Bob's side: If we got Alice's signature but Bob hasn't "collected" it (offline sync logic)
            holder.verifyBtn.visibility = View.VISIBLE
            holder.verifyBtn.text = "Complete"
            holder.verifyBtn.setOnClickListener { onVerifyClick?.invoke(tx) }
            holder.cancelBtn.visibility = View.GONE
        } else {
            holder.verifyBtn.visibility = View.GONE
            holder.cancelBtn.visibility = View.GONE
        }
        holder.itemView.setOnClickListener {
            onItemClick?.invoke(tx) ?: run {
                val intent = android.content.Intent(context, com.offlinewallet.ui.payment.TransactionDetailActivity::class.java).apply {
                    putExtra("TX_ID", tx.localId)
                }
                context.startActivity(intent)
            }
        }
    }

    override fun getItemCount() = transactions.size

    fun updateData(newTransactions: List<Transaction>, walletId: String? = currentWalletId) {
        transactions = newTransactions
        currentWalletId = walletId
        notifyDataSetChanged()
    }
}
