package com.offlinewallet.crypto

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.util.Log
import com.offlinewallet.NetworkManager
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.HexUtils
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class BucketManager(private val context: Context) {
    private val db = SimpleDatabase.getInstance(context)
    private val queueManager = QueueManager(context)

    suspend fun createBucket(
        walletId: String,
        initialBalance: Long,
        counter: Long,
        aesKey: ByteArray,
        serverPublicKey: ByteArray,
        serverSignature: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        // ✅ Standardized format: wallet_id|balance|counter
        val bucketData = "$walletId|$initialBalance|$counter"
        val isValid = Signer.verifyWithBytes(ShadowProtocol.TAG_GENESIS, serverPublicKey, bucketData.toByteArray(Charsets.UTF_8), serverSignature)
        if (!isValid) {
            Log.e("BucketManager", "❌ Invalid initial bucket signature for $walletId. Data: $bucketData")
            return@withContext false
        }

        // Encrypt sensitive data
        val (encBal, ivBal, tagBal) = Encryptor.encrypt(aesKey, initialBalance.toString().toByteArray())
        val (encCtr, ivCtr, tagCtr) = Encryptor.encrypt(aesKey, counter.toString().toByteArray())

        // Persist IV + Ciphertext + Tag to ensure we can decrypt later
        val encryptedBalance = ivBal + encBal + tagBal
        val encryptedCounter = ivCtr + encCtr + tagCtr

        db.insertBucket(
            walletId = walletId,
            balance = initialBalance,
            counter = counter,
            encryptedBalance = encryptedBalance,
            encryptedCounter = encryptedCounter,
            serverSignature = serverSignature,
            expiresAt = System.currentTimeMillis() / 1000 + 86400
        )

        // Initialize Wallet State for Blockchain tracking
        val values = android.content.ContentValues().apply {
            put("wallet_id", walletId)
            put("current_balance", initialBalance)
            put("total_counter", counter)
            put("last_block_hash", "0".repeat(64)) // Root/Genesis hash
            put("status", "ACTIVE")
            put("updated_at", System.currentTimeMillis() / 1000)
        }
        db.writableDatabase.insertWithOnConflict("wallet_state", null, values, android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE)
        
        // Initialize Head Hash Protection Root
        HeadHashProtection.storeRootHash(context, "0".repeat(64))
        
        TelemetryManager.logEvent(context, "WALLET_INIT", mapOf("wallet_id" to walletId, "balance" to initialBalance))

        true
    }

    suspend fun getBucket(walletId: String): Cursor? = withContext(Dispatchers.IO) {
        db.getBucket(walletId)
    }

    suspend fun createBucketV1(
        walletId: String,
        genesis: com.offlinewallet.models.GenesisData,
        serverSignature: ByteArray,
        serverPublicKeyOverride: String? = null
    ): Boolean = withContext(Dispatchers.IO) {
        // 1. Verify Server Signature over Genesis (O4)
        val genesisCanon = "${genesis.v}|${genesis.walletId}|${genesis.devicePubKeyHash}|${genesis.balanceP}|${genesis.counter}|${genesis.genesisEpoch}|${genesis.issuedAt}|${genesis.serverSeq}"
        val spubHex = serverPublicKeyOverride ?: SecureStorage.getServerPublicKey()
        
        if (spubHex == null) {
            Log.e("BucketManager", "❌ Cannot verify Genesis: Server Public Key (Trust Anchor) is missing.")
            // Hackathon Fallback: If trust anchor is missing, we might need to trust the first one 
            // OR we must ensure it's saved during registration.
            return@withContext false
        }
        
        val spub = HexUtils.decodeSafe(spubHex)
        Log.d("BucketManager", "Verifying Genesis with Key: ${spubHex.take(20)}... (Size: ${spub.size})")
        
        // --- Verification Flow ---
        var isValid = false
        
        // WP-FIX: UDLB - Verification now uses the binary genesis block data
        val genesisBlock = com.offlinewallet.models.DebitBlock(
            v = genesis.v,
            chainId = "SHADOW",
            walletId = walletId,
            counter = genesis.counter,
            prevHash = ByteArray(32),
            amountP = genesis.balanceP,
            payeePubKeyHash = ByteArray(32),
            payeeWalletId = "GENESIS",
            payeeChal = ByteArray(32),
            payerPassId = "SYSTEM",
            payeePassId = "SYSTEM",
            genesisEpoch = genesis.genesisEpoch,
            ts = genesis.issuedAt,
            payeeCounter = 0L,
            payeePrevHash = ByteArray(32)
        )
        val blockData = MicroPaymentHandshake.encodeDebitBlockData(genesisBlock)

        try {
            // Case A: SPKI / Long Key (RSA/ECDSA/Ed25519 SPKI)
            if (spub.size > 32) {
                val pubKey = try { 
                    KeyManager.bytesToPublicKey(spub, "Ed25519") 
                } catch (_: Exception) { 
                    try { KeyManager.bytesToPublicKey(spub, "EC") } catch (_: Exception) { null }
                }
                
                if (pubKey != null) {
                    isValid = Signer.verify(ShadowProtocol.TAG_DEBIT_BLOCK, pubKey, blockData, serverSignature)
                }
            } 
            
            // Case B: Raw 32-byte Ed25519 Key OR if Case A failed
            if (!isValid) {
                val rawKey = if (spub.size > 32) spub.takeLast(32).toByteArray() else spub
                if (rawKey.size == 32) {
                    isValid = Signer.verifyWithBytes(ShadowProtocol.TAG_DEBIT_BLOCK, rawKey, blockData, serverSignature)
                }
            }
        } catch (e: Exception) {
            Log.e("BucketManager", "❌ Signature Verification Engine Error: ${e.message}")
        }

        if (!isValid) {
            Log.e("BucketManager", "❌ Invalid genesis binary signature.")
            return@withContext false
        }
        
        // 2. Persist to monotonic store
        SecureStorage.saveGenesisEpoch(genesis.genesisEpoch)
        
        // 3. Initialize Bucket Table
        val storedKeyHex = SecureStorage.getAesKey()
        val aesKey = if (storedKeyHex != null) {
            HexUtils.decodeHex(storedKeyHex)
        } else {
            val secretKey = Encryptor.generateKey() // DBK (Generated on device per v1 spec)
            val keyBytes = secretKey.encoded
            SecureStorage.saveAesKey(HexUtils.encodeHex(keyBytes))
            keyBytes
        }
        
        val (encBal, ivBal, tagBal) = Encryptor.encrypt(aesKey, genesis.balanceP.toString().toByteArray())
        val (encCtr, ivCtr, tagCtr) = Encryptor.encrypt(aesKey, genesis.counter.toString().toByteArray())

        db.insertBucket(
            walletId = walletId,
            balance = genesis.balanceP,
            counter = genesis.counter,
            encryptedBalance = ivBal + encBal + tagBal,
            encryptedCounter = ivCtr + encCtr + tagCtr,
            serverSignature = serverSignature,
            expiresAt = System.currentTimeMillis() / 1000 + 86400
        )

        // 4. Initialize Wallet State
        val values = android.content.ContentValues().apply {
            put("wallet_id", walletId)
            put("current_balance", genesis.balanceP)
            put("total_counter", genesis.counter)
            put("last_block_hash", "0".repeat(64))
            put("status", "ACTIVE")
            put("updated_at", System.currentTimeMillis() / 1000)
        }
        db.writableDatabase.insertWithOnConflict("wallet_state", null, values, android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE)
        
        // WP-History: Append Genesis Block to Blockchain
        Log.d("BucketManager", "⛓️ [GENESIS] Appending block: Counter=${genesisBlock.counter}, Prev=${HexUtils.encodeHex(genesisBlock.prevHash).take(8)}")
        HashChainManager.append(context, genesisBlock, serverSignature, isPayer = false, nodeType = "GENESIS")

        HeadHashProtection.storeRootHash(context, "0".repeat(64))
        true
    }

    companion object {
        const val MAX_OFFLINE_BALANCE = 200000 // Strictly ₹2,000 in paisa
        const val MAX_OFFLINE_TXS = 10         // Max 10 transactions between syncs
    }

    enum class AuditStep {
        BINARY_CHECK,
        HEAD_NODE_CHECK,
        GENESIS_WALKBACK
    }

    interface AuditListener {
        fun onStepComplete(step: AuditStep, success: Boolean)
    }

    suspend fun reserveFunds(walletId: String, amount: Long, listener: AuditListener? = null): ReservationResult = withContext(Dispatchers.IO) {
        // --- PHASE 0: HARDWARE AUDIT ---
        
        // 1. Binary Seal Check
        val binaryOk = IntegrityGuardian.checkIntegrity()
        listener?.onStepComplete(AuditStep.BINARY_CHECK, binaryOk)
        if (!binaryOk) {
            Log.e("BucketManager", "Binary integrity violation! Blocking reservation.")
            freezeBucket(walletId, "BINARY_TAMPERED")
            return@withContext ReservationResult.Error("Security violation detected", "1001")
        }

        // 3. Full Chain Walk-Back (WP-14 check 3)
        val chainOk = HashChainManager.walkBack(context, walletId)
        listener?.onStepComplete(AuditStep.GENESIS_WALKBACK, chainOk)
        if (!chainOk) {
            Log.e("BucketManager", "Chain history corrupted! Backtrack failed.")
            freezeBucket(walletId, "LEDGER_CHAIN_BROKEN")
            return@withContext ReservationResult.Error("Ledger integrity failure", "1003")
        }
        
        // 4. Doubtful Block Check
        if (HashChainManager.hasDoubtfulBlock(context, walletId)) {
            Log.w("BucketManager", "Blocking reservation: Unconfirmed transaction exists.")
            return@withContext ReservationResult.Error("Please sync previous transaction", "1004")
        }
        
        // 5. Balance Check
        val spendable = checkBalance(walletId) ?: 0
        if (spendable < amount) {
            Log.w("BucketManager", "Insufficient spendable balance.")
            return@withContext ReservationResult.Error("Insufficient balance", "3000")
        }

        // PRD FIX: Offline Spending Limit Check (2000 Cap)
        val pass = SecureStorage.getPass()?.pass ?: return@withContext ReservationResult.Error("Security Pass missing", "1002")
        val currentCounter = HashChainManager.nextCounter(context, walletId)
        val usedCount = currentCounter - pass.lastSettledCounter
        
        Log.d("BucketManager", "Audit: Counter=$currentCounter, Anchor=${pass.lastSettledCounter}, Used=$usedCount")
        
        if (usedCount > MAX_OFFLINE_TXS) {
            return@withContext ReservationResult.Error("Offline transaction limit reached ($usedCount/10). Please sync.", "1005")
        }

        val unsyncedBlocks = HashChainManager.getHistorySince(context, walletId, pass.lastSettledCounter)
        val totalSpentOffline = unsyncedBlocks.sumOf { it.amountP }
        val remainingOfflineCapacity = pass.aggregateCapP - totalSpentOffline
        
        if (amount > remainingOfflineCapacity) {
             return@withContext ReservationResult.Error("Remaining offline limit too low: ₹${remainingOfflineCapacity/100.0}. Please sync.", "1006")
        }
        
        val success = db.reserveFunds(walletId, amount)
        if (success) ReservationResult.Success else ReservationResult.Error("Deduction failed", "3001")
    }

    sealed class ReservationResult {
        object Success : ReservationResult()
        data class Error(val message: String, val code: String) : ReservationResult()
    }

    suspend fun commitReservedFunds(
        walletId: String, 
        amount: Long, 
        localId: String, 
        signature: ByteArray, 
        block: com.offlinewallet.models.DebitBlock
    ): Triple<Boolean, Long, Long> = withContext(Dispatchers.IO) {
        val cursor = db.getBucket(walletId) ?: return@withContext Triple(false, 0L, 0L)
        
        cursor.use {
            if (!it.moveToFirst()) return@withContext Triple(false, 0L, 0L)
            
            // Append to Blockchain (Invariant I4: one transaction)
            // This now also handles the balance commit/deduction from reserved
            HashChainManager.append(context, block, signature, isPayer = true)
            
            // Update encrypted balance record (optional/advisory for v1)
            val bucket = db.getBucket(walletId)
            var currentBalance = 0L
            bucket?.use { c -> if (c.moveToFirst()) currentBalance = c.getLong(c.getColumnIndexOrThrow("balance")) }
            
            val aesKeyHex = SecureStorage.getAesKey()
            if (aesKeyHex != null) {
                try {
                    val aesKey = HexUtils.decodeHex(aesKeyHex)
                    val (encBal, ivBal, tagBal) = Encryptor.encrypt(aesKey, currentBalance.toString().toByteArray())
                    val encryptedBalance = ivBal + encBal + tagBal
                    
                    val values = android.content.ContentValues().apply {
                        put("encrypted_balance", encryptedBalance)
                        put("updated_at", System.currentTimeMillis() / 1000)
                    }
                    db.writableDatabase.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
                } catch (_: Exception) {}
            }
            
            // Add to Queue
            queueManager.addTransaction(amount.toInt(), walletId, block.payeeWalletId, block.counter, signature, localId = localId, method = "OFFLINE")
            
            Triple(true, currentBalance, block.counter)
        }
    }

    suspend fun rollbackReservedFunds(walletId: String, amount: Long): Boolean = withContext(Dispatchers.IO) {
        db.rollbackReserved(walletId, amount)
    }

    suspend fun deductFunds(walletId: String, amount: Long): Triple<Boolean, Long, Long> = withContext(Dispatchers.IO) {
        // Legacy method, discouraged in v1
        Triple(false, 0L, 0L)
    }

    suspend fun addFundsDirectly(walletId: String, amount: Int, localId: String? = null): Pair<Boolean, Int> = withContext(Dispatchers.IO) {
        val cursor = db.getBucket(walletId) ?: return@withContext Pair(false, 0)
        
        // ✅ Idempotency Check: Don't credit if transaction ID was already processed
        if (localId != null) {
            val txCursor = db.getTransaction(localId)
            txCursor?.use {
                if (it.moveToFirst()) {
                    val status = it.getString(it.getColumnIndexOrThrow("status"))
                    if (status == "PROCESSED" || status == "QUEUED") {
                        Log.w("BucketManager", "Idempotency: Transaction $localId already processed. Skipping balance update.")
                        cursor.use { c ->
                            return@withContext if (c.moveToFirst()) Pair(true, c.getInt(c.getColumnIndexOrThrow("balance"))) else Pair(false, 0)
                        }
                    }
                }
            }
        }

        cursor.use {
            if (!it.moveToFirst()) return@withContext Pair(false, 0)
            val balance = it.getInt(it.getColumnIndexOrThrow("balance"))
            val counter = it.getInt(it.getColumnIndexOrThrow("counter"))
            val newBalance = balance + amount
            
            // Update encrypted balance if AES key is available
            val aesKeyHex = SecureStorage.getAesKey()
            if (aesKeyHex != null) {
                try {
                    val aesKey = HexUtils.decodeHex(aesKeyHex)
                    val (encBal, ivBal, tagBal) = Encryptor.encrypt(aesKey, newBalance.toString().toByteArray())
                    val encryptedBalance = ivBal + encBal + tagBal
                    
                    val values = android.content.ContentValues().apply {
                        put("balance", newBalance)
                        put("encrypted_balance", encryptedBalance)
                        put("updated_at", System.currentTimeMillis() / 1000)
                    }
                    val success = db.writableDatabase.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId)) > 0
                    return@withContext Pair(success, newBalance)
                } catch (_: Exception) {}
            }
            
            val success = db.updateBucket(walletId, newBalance.toLong(), counter.toLong())
            Pair(success, newBalance)
        }
    }

    suspend fun addFunds(
        walletId: String,
        amount: Int,
        newBalance: Long,
        counter: Long,
        expiresAt: Long,
        aesKey: ByteArray,
        serverPublicKey: ByteArray,
        serverSignature: ByteArray,
        issuedAt: Long? = null,
        prevHashOverride: String? = null
    ): Pair<Boolean, Long> = withContext(Dispatchers.IO) {
        val cursor = db.getBucket(walletId) ?: return@withContext Pair(false, 0L)

        cursor.use {
            if (!it.moveToFirst()) return@withContext Pair(false, 0L)
            
            val oldBalance = it.getLong(it.getColumnIndexOrThrow("balance"))
            val oldCounter = it.getLong(it.getColumnIndexOrThrow("counter"))

            // 1. Verification: Counter must be strictly monotonic
            if (counter <= oldCounter) {
                Log.e("BucketManager", "❌ Topup rejected: Counter not monotonic ($counter <= $oldCounter)")
                return@withContext Pair(false, 0L)
            }

            // 2. Verification: Balance must be monotonic (can't decrease during topup)
            if (newBalance < oldBalance) {
                Log.e("BucketManager", "❌ Topup rejected: Balance decreased ($newBalance < $oldBalance)")
                return@withContext Pair(false, 0L)
            }

            // 3. Signature Verification (UDLB Binary)
            val head = if (prevHashOverride != null) HexUtils.decodeHex(prevHashOverride) else HashChainManager.head(context, walletId)
            val topupBlock = com.offlinewallet.models.DebitBlock(
                v = 1,
                chainId = "SHADOW",
                walletId = "SERVER",
                counter = counter,
                prevHash = head,
                amountP = amount.toLong(),
                payeePubKeyHash = ByteArray(32),
                payeeWalletId = walletId,
                payeeChal = ByteArray(32),
                payerPassId = "SERVER",
                payeePassId = "SERVER",
                genesisEpoch = SecureStorage.getGenesisEpoch(),
                ts = issuedAt ?: (System.currentTimeMillis() / 1000),
                payeeCounter = 0L,
                payeePrevHash = ByteArray(32)
            )
            val blockData = MicroPaymentHandshake.encodeDebitBlockData(topupBlock)
            
            // Verifies: tag ("shadow/v1/block-hash") + 0x00 + message
            val isValid = Signer.verifyWithBytes(ShadowProtocol.TAG_DEBIT_BLOCK, serverPublicKey, blockData, serverSignature)

            if (!isValid) {
                Log.e("BucketManager", "❌ Invalid topup binary signature for $walletId. Counter: $counter, Amount: $amount, Prev: ${HexUtils.encodeHex(head).take(8)}")
                return@withContext Pair(false, 0L)
            }

            // Limit Check: Cannot exceed ₹2000 in offline bucket
            if (newBalance > MAX_OFFLINE_BALANCE) {
                Log.e("BucketManager", "Topup rejected: Offline balance cannot exceed ₹2000")
                return@withContext Pair(false, 0L)
            }

            // Update local storage with the new signed balance and counter
            try {
                // Re-encrypt both balance and counter
                val (encBal, ivBal, tagBal) = Encryptor.encrypt(aesKey, newBalance.toString().toByteArray())
                val (encCtr, ivCtr, tagCtr) = Encryptor.encrypt(aesKey, counter.toString().toByteArray())
                
                val encryptedBalance = ivBal + encBal + tagBal
                val encryptedCounter = ivCtr + encCtr + tagCtr
                
                val values = android.content.ContentValues().apply {
                    put("balance", newBalance)
                    put("counter", counter)
                    put("encrypted_balance", encryptedBalance)
                    put("encrypted_counter", encryptedCounter)
                    put("server_signature", serverSignature)
                    put("expires_at", expiresAt)
                    put("updated_at", System.currentTimeMillis() / 1000)
                }
                db.writableDatabase.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId))
                
                // Sync to wallet_state for Blockchain integrity
                val stateValues = android.content.ContentValues().apply {
                    put("current_balance", newBalance)
                    put("total_counter", counter)
                    put("updated_at", System.currentTimeMillis() / 1000)
                }
                db.writableDatabase.update("wallet_state", stateValues, "wallet_id = ?", arrayOf(walletId))
                
                // WP-History: Append Top-up Block to Blockchain
                val head = HashChainManager.head(context, walletId)
                val topupBlock = com.offlinewallet.models.DebitBlock(
                    v = 1,
                    chainId = "SHADOW",
                    walletId = "SERVER",
                    counter = counter,
                    prevHash = head,
                    amountP = newBalance - oldBalance,
                    payeePubKeyHash = ByteArray(32),
                    payeeWalletId = walletId,
                    payeeChal = ByteArray(32),
                    payerPassId = "SERVER",
                    payeePassId = "SERVER",
                    genesisEpoch = SecureStorage.getGenesisEpoch(),
                    ts = issuedAt ?: (System.currentTimeMillis() / 1000),
                    payeeCounter = 0L,
                    payeePrevHash = ByteArray(32)
                )
                Log.d("BucketManager", "⛓️ [TOPUP] Appending block: Counter=${topupBlock.counter}, Prev=${HexUtils.encodeHex(topupBlock.prevHash).take(8)}")
                HashChainManager.append(context, topupBlock, serverSignature, isPayer = false, nodeType = "TOPUP")

                Log.d("BucketManager", "✅ Bucket updated securely with server proof. New Balance: $newBalance")
                return@withContext Pair(true, newBalance)
            } catch (e: Exception) {
                Log.e("BucketManager", "Error updating secure bucket: ${e.message}")
                Pair(false, 0L)
            }
        }
    }

    suspend fun checkBalance(walletId: String): Int? = withContext(Dispatchers.IO) {
        val cursor = db.getBucket(walletId) ?: return@withContext null
        cursor.use {
            if (it.moveToFirst()) {
                it.getInt(it.getColumnIndexOrThrow("balance"))
            } else null
        }
    }

    suspend fun getCounter(walletId: String): Int? = withContext(Dispatchers.IO) {
        val cursor = db.getBucket(walletId) ?: return@withContext null
        cursor.use {
            if (it.moveToFirst()) {
                it.getInt(it.getColumnIndexOrThrow("counter"))
            } else null
        }
    }

    suspend fun freezeBucket(walletId: String, reason: String = "SECURITY_VIOLATION"): Boolean = withContext(Dispatchers.IO) {
        val db = SimpleDatabase.getInstance(context).writableDatabase
        val values = android.content.ContentValues().apply {
            put("status", "FROZEN")
            put("freeze_reason", reason)
            put("updated_at", System.currentTimeMillis() / 1000)
        }
        db.update("offline_bucket", values, "wallet_id = ?", arrayOf(walletId)) > 0
    }

    suspend fun activateBucket(walletId: String): Boolean = withContext(Dispatchers.IO) {
        val success = db.updateStatus(walletId, "ACTIVE") > 0
        if (success) {
            try {
                val networkManager = NetworkManager(context, com.offlinewallet.Config.BASE_URL)
                val res = networkManager.unfreezeWallet()
                return@withContext res.isSuccess
            } catch (e: Exception) {
                Log.e("BucketManager", "Failed to sync unfreeze to server", e)
            }
        }
        success
    }
}
