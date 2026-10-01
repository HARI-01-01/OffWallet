package com.offlinewallet.ui.payment

import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.offlinewallet.R
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.HashChainManager
import com.offlinewallet.crypto.HexUtils
import com.offlinewallet.crypto.QueueManager
import com.offlinewallet.models.BlockchainNode
import com.offlinewallet.models.BlockchainNodeType
import com.offlinewallet.ui.views.BlockchainGraphView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class BlockchainExplorerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_blockchain_explorer)

        findViewById<android.view.View>(R.id.btnBack).setOnClickListener { finish() }

        val graphView = findViewById<BlockchainGraphView>(R.id.blockchainGraph)
        graphView.onNodeSelected = { node -> showNodeDetails(node) }

        lifecycleScope.launch {
            val walletId = SecureStorage.getWalletId() ?: return@launch
            val nodes = withContext(Dispatchers.IO) {
                fetchUnifiedNodes(walletId)
            }
            graphView.setNodes(nodes)
        }
    }

    private suspend fun fetchUnifiedNodes(walletId: String): List<BlockchainNode> {
        return withContext(Dispatchers.IO) {
            val nodes = mutableListOf<BlockchainNode>()
            val db = com.offlinewallet.crypto.SimpleDatabase.getInstance(this@BlockchainExplorerActivity).readableDatabase
            
            val currentPass = SecureStorage.getPass()?.pass
            val checkpointHash = currentPass?.lastSettledHead ?: ""

            val cursor = db.query("blockchain", null, "wallet_id = ?", arrayOf(walletId), null, null, "counter ASC")
            cursor.use {
                while (it.moveToNext()) {
                    val nodeTypeStr = it.getString(it.getColumnIndexOrThrow("node_type")) ?: "PAYMENT_SENT"
                    val type = try {
                        BlockchainNodeType.valueOf(nodeTypeStr)
                    } catch (_: Exception) {
                        BlockchainNodeType.PAYMENT_SENT
                    }
                    
                    val hash = it.getString(it.getColumnIndexOrThrow("block_hash"))
                    val isSynced = it.getInt(it.getColumnIndexOrThrow("synced")) == 1
                    
                    val status = if (type == BlockchainNodeType.GENESIS) "ROOT"
                                else if (hash == checkpointHash) "CHECKPOINT"
                                else if (isSynced) "SETTLED" 
                                else "LOCAL"

                    nodes.add(BlockchainNode(
                        id = hash,
                        type = type,
                        amountP = it.getLong(it.getColumnIndexOrThrow("amount")),
                        counter = it.getLong(it.getColumnIndexOrThrow("counter")),
                        timestamp = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                        prevHash = it.getString(it.getColumnIndexOrThrow("prev_block_hash")),
                        hash = hash,
                        peerId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                        status = status
                    ))
                }
            }
            
            // If no nodes found (first run before Genesis), add a fallback System node
            if (nodes.isEmpty()) {
                nodes.add(BlockchainNode(
                    id = "ROOT",
                    type = BlockchainNodeType.GENESIS,
                    amountP = 0,
                    counter = 0,
                    timestamp = System.currentTimeMillis() / 1000,
                    prevHash = "0".repeat(64),
                    hash = "0".repeat(64),
                    status = "SYSTEM"
                ))
            }
            
            nodes.sortedBy { it.counter }
        }
    }

    private fun showNodeDetails(node: BlockchainNode) {
        val msg = """
            Type: ${node.type}
            Counter: #${node.counter}
            Amount: ₹${node.amountP / 100.0}
            
            ${if (node.peerId != null) "Peer: ${node.peerId}" else ""}
            
            Hash:
            ${node.hash.take(32)}...
            
            Prev Hash:
            ${node.prevHash.take(32)}...
            
            Time: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date(node.timestamp * 1000))}
        """.trimIndent()

        AlertDialog.Builder(this)
            .setTitle("🔍 Node Details")
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }
}
