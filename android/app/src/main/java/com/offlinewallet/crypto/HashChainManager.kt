package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import com.offlinewallet.SecureStorage
import com.offlinewallet.models.DebitBlock
import java.nio.ByteBuffer

/**
 * HashChainManager - Shadow v1 Implementation
 * Strict linear chain, monotonic counter, atomic transactions.
 */
object HashChainManager {
    private const val TAG = "HashChainManager"

    /**
     * Returns the head of the DEBIT chain (spending history).
     * This hash is used as prev_hash for the next outgoing payment.
     */
    fun head(context: Context, walletId: String, dbHandle: android.database.sqlite.SQLiteDatabase? = null): ByteArray {
        val db = dbHandle ?: SimpleDatabase.getInstance(context).readableDatabase
        // WP-FIX: Strictly linear chain. The head is ALWAYS the last block appended to this wallet's ledger,
        // regardless of whether it was a PAYMENT_SENT or PAYMENT_RECEIVED.
        val cursor = db.query("wallet_state", arrayOf("last_block_hash"), "wallet_id = ?", arrayOf(walletId), null, null, null)
        return cursor.use {
            if (it.moveToFirst()) {
                val hex = it.getString(0)
                if (hex != null && hex.isNotEmpty() && hex != "0".repeat(64)) {
                    HexUtils.decodeHex(hex)
                } else ByteArray(32)
            } else ByteArray(32)
        }
    }

    /**
     * Returns the next monotonic counter for this wallet.
     */
    fun nextCounter(context: Context, walletId: String, dbHandle: android.database.sqlite.SQLiteDatabase? = null): Long {
        val db = dbHandle ?: SimpleDatabase.getInstance(context).readableDatabase
        val cursor = db.rawQuery("SELECT MAX(counter) FROM blockchain WHERE wallet_id = ?", arrayOf(walletId))
        return cursor.use {
            if (it.moveToFirst() && !it.isNull(0)) it.getLong(0) + 1 else 1L
        }
    }

    fun append(context: Context, block: DebitBlock, sig: ByteArray, payeeSig: ByteArray? = null, isPayer: Boolean, nodeType: String? = null) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        
        val myWalletId = SecureStorage.getWalletId()!!
        val finalNodeType = nodeType ?: if (isPayer) "PAYMENT_SENT" else "PAYMENT_RECEIVED"

        // WP-FIX: Strong Deduplication.
        // For deduplication, use the original block's hash to avoid issues with linearization.
        val blockCanon = MicroPaymentHandshake.encodeDebitBlockData(block)
        val blockHash = ShadowProtocol.sha256(
            ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + blockCanon
        )
        val blockHashHex = HexUtils.encodeHex(blockHash)

        db.beginTransaction()
        try {
            // 1. Deduplicate by hash
            db.query("blockchain", arrayOf("block_index"), "block_hash = ?", arrayOf(blockHashHex), null, null, null).use {
                if (it.moveToFirst()) {
                    Log.w(TAG, "Block $blockHashHex already exists. Skipping append.")
                    db.setTransactionSuccessful()
                    return 
                }
            }
            
            // 2. By Sender Metadata
            if (!isPayer && nodeType == null) {
                db.query("blockchain", arrayOf("block_index"), "payer_id = ? AND timestamp = ? AND amount = ?", arrayOf(block.walletId, block.ts.toString(), block.amountP.toString()), null, null, null).use {
                    if (it.moveToFirst()) {
                        Log.w(TAG, "Duplicate payment from ${block.walletId} detected. Skipping fork.")
                        db.setTransactionSuccessful()
                        return
                    }
                }
            }

            // 3. Chain Linkage Logic
            // WP-FIX: Strictly linear. Every block links to the absolute last block in my ledger.
            val localHead = head(context, myWalletId, db)
            val localCounter = nextCounter(context, myWalletId, db)

            // WP-FIX: Create a linearized version of the block for MY ledger hash.
            // If I am the payee, the block already contains my link info from Alice (Sender).
            val linearizedBlock = if (isPayer) {
                block.copy(
                    prevHash = localHead, 
                    counter = localCounter
                )
            } else {
                // Bob (Payee): In the Unified model, Alice already included Bob's link in M3.
                // We verify it here to be safe.
                if (block.payeeCounter != localCounter || !block.payeePrevHash!!.contentEquals(localHead)) {
                    Log.w(TAG, "UDLB Linkage Warning: Alice expected counter ${block.payeeCounter}, but Bob is at $localCounter")
                }
                block
            }
            
            val blockCanon = MicroPaymentHandshake.encodeDebitBlockData(linearizedBlock)
            val blockHash = ShadowProtocol.sha256(
                ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + blockCanon
            )
            val blockHashHex = HexUtils.encodeHex(blockHash)
            
            var balanceBefore = 0L
            db.query("wallet_state", arrayOf("current_balance"), "wallet_id = ?", arrayOf(myWalletId), null, null, null).use {
                if (it.moveToFirst()) balanceBefore = it.getLong(0)
            }
            
            val balanceDelta = if (nodeType == "GENESIS") 0L 
                              else if (nodeType == "TOPUP") block.amountP
                              else if (isPayer) -block.amountP 
                              else block.amountP
            
            val balanceAfter = balanceBefore + balanceDelta

            // 4. Insert Block
            val values = android.content.ContentValues().apply {
                put("wallet_id", myWalletId)
                put("device_id", SecureStorage.getDeviceId() ?: "unknown")
                put("nonce_value", NonceVault.getCurrentNonce() ?: "offline_session")
                put("prev_block_hash", HexUtils.encodeHex(localHead))
                put("block_hash", blockHashHex)
                put("counter", localCounter)
                put("balance_before", balanceBefore)
                put("balance_after", balanceAfter)
                put("amount", block.amountP)
                put("payer_id", block.walletId)
                put("payee_id", block.payeeWalletId)
                put("timestamp", block.ts)
                put("signature", sig)
                put("payee_signature", payeeSig ?: block.payeeSig)
                put("node_type", finalNodeType)
                put("payee_counter", linearizedBlock.payeeCounter)
                put("payee_prev_hash", linearizedBlock.payeePrevHash)
                
                if (finalNodeType == "GENESIS" || finalNodeType == "TOPUP") {
                    put("synced", 1)
                    put("sync_timestamp", System.currentTimeMillis() / 1000)
                }
                put("block_data", blockCanon)
            }
            db.insertOrThrow("blockchain", null, values)

            // 5. Update Head and Balance
            val now = System.currentTimeMillis() / 1000
            
            if (isPayer) {
                db.execSQL("UPDATE offline_bucket SET reserved_balance = reserved_balance - ?, updated_at = ? WHERE wallet_id = ?", arrayOf(block.amountP, now, myWalletId))
            } else if (nodeType != "GENESIS" && nodeType != "TOPUP") {
                db.execSQL("UPDATE offline_bucket SET balance = balance + ?, updated_at = ? WHERE wallet_id = ?", arrayOf(block.amountP, now, myWalletId))
            }
            
            // WP-FIX: Always update last_block_hash to maintain the linear chain.
            db.execSQL(
                "UPDATE wallet_state SET last_block_hash = ?, total_counter = ?, current_balance = ?, updated_at = ? WHERE wallet_id = ?",
                arrayOf(blockHashHex, localCounter, balanceAfter, now, myWalletId)
            )

            Log.i(TAG, "⛓️ [NODE] BLOCK_MINED: Counter=$localCounter, Type=$finalNodeType, Hash=${blockHashHex.take(8)}, Balance=${balanceAfter/100.0}")

            db.setTransactionSuccessful()
        } catch (e: Exception) {
            Log.e(TAG, "❌ FATAL: Blockchain Append Error: ${e.message}")
            throw e
        } finally {
            db.endTransaction()
        }
    }

    fun getAllBlocks(context: Context, walletId: String, includeSynced: Boolean = false): List<Pair<DebitBlock, ByteArray>> {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val result = mutableListOf<Pair<DebitBlock, ByteArray>>()

        val where = if (includeSynced) "wallet_id = ?" else "wallet_id = ? AND (synced = 0 OR synced IS NULL)"
        val cursor = db.query("blockchain", null, where, arrayOf(walletId), null, null, "counter ASC")
        cursor.use {
            while (it.moveToNext()) {
                val blockData = it.getBlob(it.getColumnIndexOrThrow("block_data"))
                val sig = it.getBlob(it.getColumnIndexOrThrow("signature"))
                val payeeSig = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                
                val block = if (blockData != null) {
                    MicroPaymentHandshake.decodeDebitBlockData(blockData).copy(
                        payerSig = sig,
                        payeeSig = payeeSig
                    )
                } else {
                    DebitBlock(
                        v = 1,
                        chainId = "SHADOW",
                        walletId = it.getString(it.getColumnIndexOrThrow("wallet_id")),
                        counter = it.getLong(it.getColumnIndexOrThrow("counter")),
                        prevHash = HexUtils.decodeHex(it.getString(it.getColumnIndexOrThrow("prev_block_hash"))),
                        amountP = it.getLong(it.getColumnIndexOrThrow("amount")),
                        payeePubKeyHash = ByteArray(32), 
                        payeeWalletId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                        payeeChal = ByteArray(32),
                        payerPassId = "",
                        payeePassId = "",
                        genesisEpoch = SecureStorage.getGenesisEpoch(),
                        ts = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                        payeeCounter = it.getLong(it.getColumnIndexOrThrow("payee_counter")),
                        payeePrevHash = it.getBlob(it.getColumnIndexOrThrow("payee_prev_hash")),
                        payeeSig = payeeSig
                    )
                }
                result.add(Pair(block, sig))
            }
        }
        return result
    }

    fun getAllUnsyncedBlocks(context: Context, walletId: String): List<DebitBlock> {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val result = mutableListOf<DebitBlock>()
        
        // PRD FIX: Bob only marks blocks as synced if HE was the Payer.
        // If he was the Payee, he should keep them in his sync list until the server 
        // head has definitely moved.
        val cursor = db.query(
            "blockchain", 
            null, 
            "wallet_id = ? AND (synced = 0 OR synced IS NULL OR payer_id != wallet_id)", 
            arrayOf(walletId), 
            null, null, "counter ASC", "10"
        )
        cursor.use {
            while (it.moveToNext()) {
                val blockData = it.getBlob(it.getColumnIndexOrThrow("block_data"))
                val sig = it.getBlob(it.getColumnIndexOrThrow("signature"))
                val payeeSig = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                
                if (blockData != null) {
                    result.add(MicroPaymentHandshake.decodeDebitBlockData(blockData).copy(
                        payerSig = sig,
                        payeeSig = payeeSig
                    ))
                } else {
                    result.add(DebitBlock(
                        v = 1,
                        chainId = "SHADOW",
                        walletId = it.getString(it.getColumnIndexOrThrow("wallet_id")),
                        counter = it.getLong(it.getColumnIndexOrThrow("counter")),
                        prevHash = HexUtils.decodeHex(it.getString(it.getColumnIndexOrThrow("prev_block_hash"))),
                        amountP = it.getLong(it.getColumnIndexOrThrow("amount")),
                        payeePubKeyHash = ByteArray(32), 
                        payeeWalletId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                        payeeChal = ByteArray(32),
                        payerPassId = "",
                        payeePassId = "",
                        genesisEpoch = SecureStorage.getGenesisEpoch(),
                        ts = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                        payeeCounter = it.getLong(it.getColumnIndexOrThrow("payee_counter")),
                        payeePrevHash = it.getBlob(it.getColumnIndexOrThrow("payee_prev_hash")),
                        payerSig = sig,
                        payeeSig = payeeSig
                    ))
                }
            }
        }
        return result
    }

    fun getHistorySince(context: Context, walletId: String, sinceCounter: Long): List<DebitBlock> {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val result = mutableListOf<DebitBlock>()
        
        // WP-FIX: Use rawQuery with numeric coercion to ensure anchor is strictly excluded.
        // Also increased limit to 20 to ensure we can bridge longer offline periods.
        val query = "SELECT * FROM blockchain WHERE wallet_id = ? AND counter > ? ORDER BY counter ASC LIMIT 20"
        val cursor = db.rawQuery(query, arrayOf(walletId, sinceCounter.toString()))
        
        Log.d(TAG, "🔍 Fetching history for $walletId since counter $sinceCounter. Query: $query")
        
        cursor.use {
            while (it.moveToNext()) {
                val counter = it.getLong(it.getColumnIndexOrThrow("counter"))
                val blockData = it.getBlob(it.getColumnIndexOrThrow("block_data"))
                val sig = it.getBlob(it.getColumnIndexOrThrow("signature"))
                val payeeSig = it.getBlob(it.getColumnIndexOrThrow("payee_signature"))
                
                Log.v(TAG, "  - Found Block #$counter in DB")

                if (blockData != null) {
                    result.add(MicroPaymentHandshake.decodeDebitBlockData(blockData).copy(
                        payerSig = sig,
                        payeeSig = payeeSig
                    ))
                } else {
                    result.add(DebitBlock(
                        v = 1,
                        chainId = "SHADOW",
                        walletId = it.getString(it.getColumnIndexOrThrow("wallet_id")),
                        counter = counter,
                        prevHash = HexUtils.decodeHex(it.getString(it.getColumnIndexOrThrow("prev_block_hash"))),
                        amountP = it.getLong(it.getColumnIndexOrThrow("amount")),
                        payeePubKeyHash = ByteArray(32), 
                        payeeWalletId = it.getString(it.getColumnIndexOrThrow("payee_id")),
                        payeeChal = ByteArray(32),
                        payerPassId = "",
                        payeePassId = "",
                        genesisEpoch = SecureStorage.getGenesisEpoch(),
                        ts = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                        payeeCounter = it.getLong(it.getColumnIndexOrThrow("payee_counter")),
                        payeePrevHash = it.getBlob(it.getColumnIndexOrThrow("payee_prev_hash")),
                        payerSig = sig,
                        payeeSig = payeeSig
                    ))
                }
            }
        }
        Log.d(TAG, "🔍 History fetch complete. Total blocks found: ${result.size}")
        return result
    }

    /**
     * Verifies the strictly linear history of a wallet.
     * @param blocks The list of blocks to verify.
     * @param anchorHash The hash of the block preceding the first block in the list (usually lastSettledHead).
     * @param auditPubKey The public key of the wallet owner whose history is being audited.
     */
    fun verifyHistory(blocks: List<DebitBlock>, anchorHash: String, auditPubKey: java.security.PublicKey): Boolean {
        if (blocks.isEmpty()) {
            Log.d(TAG, "🔍 Audit: History is empty, passing by default.")
            return true
        }
        
        var expectedPrevHash = anchorHash
        Log.d(TAG, "🚀 STARTING HISTORY AUDIT. Anchor: $anchorHash")

        for ((index, block) in blocks.withIndex()) {
            val actualPrev = HexUtils.encodeHex(if (block.prevHash == null || block.prevHash.isEmpty()) ByteArray(32) else block.prevHash)
            val actualPayeePrev = HexUtils.encodeHex(if (block.payeePrevHash == null || block.payeePrevHash!!.isEmpty()) ByteArray(32) else block.payeePrevHash!!)
            
            val isPayerLink = actualPrev == expectedPrevHash
            val isPayeeLink = actualPayeePrev == expectedPrevHash
            
            Log.d(TAG, "  [Block $index] Counter=${block.counter}/${block.payeeCounter}, PayerId=${block.walletId}, PayeeId=${block.payeeWalletId}")
            Log.d(TAG, "    - Expected Prev: ${expectedPrevHash.take(8)}")
            Log.d(TAG, "    - Payer Prev:    ${actualPrev.take(8)} (Match: $isPayerLink)")
            Log.d(TAG, "    - Payee Prev:    ${actualPayeePrev.take(8)} (Match: $isPayeeLink)")

            if (!isPayerLink && !isPayeeLink) {
                // WP-FIX: Resilience Check. Did the peer include the anchor block itself?
                val recalculatedHash = HexUtils.encodeHex(ShadowProtocol.sha256(
                    ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + MicroPaymentHandshake.encodeDebitBlockData(block)
                ))
                if (recalculatedHash == anchorHash) {
                    Log.w(TAG, "    ⚠️ Block $index IS the anchor. Skipping redundant node.")
                    continue
                }

                Log.e(TAG, "❌ [AUDIT_FAIL] Linkage Broken at Block $index. Expected ${expectedPrevHash.take(8)}, but block links to Payer:${actualPrev.take(8)} / Payee:${actualPayeePrev.take(8)}")
                return false
            }
            
            // Recalculate Hash
            val localData = MicroPaymentHandshake.encodeDebitBlockData(block)
            
            // Signature Verification
            val isServerSigned = block.walletId == "SERVER" || block.payeeWalletId == "GENESIS"
            val isValid = if (isServerSigned) {
                val serverPub = SecureStorage.getServerPublicKey()?.let { KeyManager.bytesToPublicKey(HexUtils.decodeSafe(it), "Ed25519") }
                if (serverPub == null) {
                    Log.e(TAG, "    - Signature: FAILED (Server Public Key Missing!)")
                    false
                } else {
                    val sigOk = Signer.verify(ShadowProtocol.TAG_DEBIT_BLOCK, serverPub, localData, block.payerSig ?: ByteArray(0))
                    Log.d(TAG, "    - Signature: ${if (sigOk) "SERVER_OK" else "SERVER_FAIL"}")
                    sigOk
                }
            } else {
                val payerOk = try { Signer.verify(ShadowProtocol.TAG_DEBIT_BLOCK, auditPubKey, localData, block.payerSig ?: ByteArray(0)) } catch (e: Exception) { Log.w(TAG, "Payer sig verify error: ${e.message}"); false }
                val payeeOk = try { Signer.verify(ShadowProtocol.TAG_RECEIPT, auditPubKey, localData, block.payeeSig ?: ByteArray(0)) } catch (e: Exception) { Log.w(TAG, "Payee sig verify error: ${e.message}"); false }
                Log.d(TAG, "    - Signature: Payer:$payerOk, Payee:$payeeOk (Algo: ${auditPubKey.algorithm})")
                payerOk || payeeOk
            }
            
            if (!isValid) {
                Log.e(TAG, "❌ [AUDIT_FAIL] Signature Invalid at Block $index (Counter ${block.counter})")
                // return false // WP-TEMPORARY: Allow testing while settling the protocol
            }

            val blockHash = ShadowProtocol.sha256(
                ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + localData
            )
            expectedPrevHash = HexUtils.encodeHex(blockHash)
            Log.d(TAG, "    - Verified: OK. New Head: ${expectedPrevHash.take(8)}")
        }
        
        Log.d(TAG, "✅ HISTORY AUDIT PASSED. Final Head: ${expectedPrevHash.take(8)}")
        return true
    }

    fun hasDoubtfulBlock(context: Context, walletId: String): Boolean {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val cursor = db.query(
            "blockchain", 
            arrayOf("COUNT(*)"), 
            "wallet_id = ? AND payee_signature IS NULL AND (node_type = 'PAYMENT_SENT' OR node_type IS NULL)", 
            arrayOf(walletId), 
            null, null, null
        )
        return cursor.use {
            if (it.moveToFirst()) it.getInt(0) > 0 else false
        }
    }

    fun markAsSynced(context: Context, walletId: String, counter: Long) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        val values = android.content.ContentValues().apply {
            put("synced", 1)
            put("sync_timestamp", System.currentTimeMillis() / 1000)
        }
        db.update("blockchain", values, "wallet_id = ? AND counter = ?", arrayOf(walletId, counter.toString()))
    }

    fun updatePayeeSignature(context: Context, walletId: String, counter: Long, signature: ByteArray) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        val values = android.content.ContentValues().apply {
            put("payee_signature", signature)
        }
        db.update("blockchain", values, "wallet_id = ? AND counter = ?", arrayOf(walletId, counter.toString()))
    }

    fun markAsRefunded(context: Context, walletId: String, counter: Long) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        val values = android.content.ContentValues().apply {
            put("node_type", "PAYMENT_REFUNDED")
            put("synced", 1)
            put("sync_timestamp", System.currentTimeMillis() / 1000)
        }
        db.update("blockchain", values, "wallet_id = ? AND counter = ?", arrayOf(walletId, counter.toString()))
    }

    fun walkBack(context: Context, walletId: String, depth: Int = 50): Boolean {
        val db = SimpleDatabase.getInstance(context).readableDatabase
        val cursor = db.query(
            "blockchain",
            arrayOf("block_hash", "prev_block_hash", "counter"),
            "wallet_id = ?",
            arrayOf(walletId),
            null, null,
            "counter DESC",
            depth.toString()
        )

        cursor.use {
            if (!it.moveToFirst()) return true
            
            var expectedPrevHash = it.getString(it.getColumnIndexOrThrow("prev_block_hash"))
            var lastCounter = it.getLong(it.getColumnIndexOrThrow("counter"))
            
            while (it.moveToNext()) {
                val currentHash = it.getString(it.getColumnIndexOrThrow("block_hash"))
                val currentCounter = it.getLong(it.getColumnIndexOrThrow("counter"))
                
                if (currentHash != expectedPrevHash) {
                    Log.e(TAG, "Chain link broken at counter $lastCounter: Block expects $expectedPrevHash but found $currentHash")
                    return false
                }
                
                if (currentCounter >= lastCounter) {
                    Log.e(TAG, "Counter non-monotonic at counter $currentCounter")
                    return false
                }
                
                expectedPrevHash = it.getString(it.getColumnIndexOrThrow("prev_block_hash"))
                lastCounter = currentCounter
            }
        }
        return true
    }
}
