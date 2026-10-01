package com.offlinewallet.firebase

import android.content.Context
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

class FirebaseService(private val context: Context) {
    private val auth = FirebaseAuth.getInstance()
    private val db = FirebaseFirestore.getInstance()

    // Collection names
    companion object {
        const val COLLECTION_USERS = "users"
        const val COLLECTION_BUCKETS = "buckets"
        const val COLLECTION_TRANSACTIONS = "transactions"
        const val COLLECTION_SETTLEMENTS = "settlements"
        const val COLLECTION_QUEUE = "pending_queue"
    }

    // ---------- Authentication ----------

    suspend fun signInWithEmail(email: String, password: String): Result<String> {
        return try {
            val result = auth.signInWithEmailAndPassword(email, password).await()
            Result.success(result.user?.uid ?: "")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun signUpWithEmail(email: String, password: String): Result<String> {
        return try {
            val result = auth.createUserWithEmailAndPassword(email, password).await()
            Result.success(result.user?.uid ?: "")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun signInAnonymously(): Result<String> {
        return try {
            val result = auth.signInAnonymously().await()
            Result.success(result.user?.uid ?: "")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun getCurrentUserId(): String? {
        return auth.currentUser?.uid
    }

    fun signOut() {
        auth.signOut()
    }

    // ---------- User Management ----------

    suspend fun createUser(walletId: String, userData: Map<String, Any>): Result<Unit> {
        return try {
            db.collection(COLLECTION_USERS)
                .document(walletId)
                .set(userData)
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getUser(walletId: String): Result<Map<String, Any>?> {
        return try {
            val snapshot = db.collection(COLLECTION_USERS)
                .document(walletId)
                .get()
                .await()
            Result.success(snapshot.data)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ---------- Bucket Operations ----------

    suspend fun createBucket(walletId: String, bucketData: Map<String, Any>): Result<Unit> {
        return try {
            db.collection(COLLECTION_BUCKETS)
                .document(walletId)
                .set(bucketData)
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getBucket(walletId: String): Result<Map<String, Any>?> {
        return try {
            val snapshot = db.collection(COLLECTION_BUCKETS)
                .document(walletId)
                .get()
                .await()
            Result.success(snapshot.data)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun updateBucket(walletId: String, updates: Map<String, Any>): Result<Unit> {
        return try {
            db.collection(COLLECTION_BUCKETS)
                .document(walletId)
                .update(updates)
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ---------- Transaction Operations ----------

    suspend fun addTransaction(transactionData: Map<String, Any>): Result<String> {
        return try {
            val docRef = db.collection(COLLECTION_TRANSACTIONS).document()
            val data = transactionData.toMutableMap().apply {
                put("remote_id", docRef.id)
                put("timestamp", System.currentTimeMillis() / 1000)
                put("status", "QUEUED")
            }
            docRef.set(data).await()
            Result.success(docRef.id)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getPendingTransactions(walletId: String): Result<List<Map<String, Any>>> {
        return try {
            val snapshot = db.collection(COLLECTION_TRANSACTIONS)
                .whereEqualTo("payer_id", walletId)
                .whereIn("status", listOf("QUEUED", "FAILED_TO_PROCESS"))
                .get()
                .await()
            Result.success(snapshot.documents.map { it.data ?: emptyMap() })
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun updateTransactionStatus(remoteId: String, status: String): Result<Unit> {
        return try {
            db.collection(COLLECTION_TRANSACTIONS)
                .document(remoteId)
                .update("status", status)
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ---------- Real-time Listeners ----------

    fun listenToTransactions(
        walletId: String,
        onUpdate: (List<Map<String, Any>>) -> Unit
    ) {
        db.collection(COLLECTION_TRANSACTIONS)
            .whereEqualTo("payer_id", walletId)
            .addSnapshotListener { snapshot, error ->
                if (error != null) return@addSnapshotListener
                val transactions = snapshot?.documents?.map { it.data ?: emptyMap() } ?: emptyList()
                onUpdate(transactions)
            }
    }

    fun listenToBucket(
        walletId: String,
        onUpdate: (Map<String, Any>) -> Unit
    ) {
        db.collection(COLLECTION_BUCKETS)
            .document(walletId)
            .addSnapshotListener { snapshot, error ->
                if (error != null) return@addSnapshotListener
                val data = snapshot?.data ?: emptyMap()
                onUpdate(data)
            }
    }

    // ---------- Settlement Operations ----------

    suspend fun createSettlement(settlementId: String, settlementData: Map<String, Any>): Result<Unit> {
        return try {
            db.collection(COLLECTION_SETTLEMENTS)
                .document(settlementId)
                .set(settlementData)
                .await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ---------- Sync Manager ----------

    suspend fun syncLocalQueue(
        localTransactions: List<Map<String, Any>>
    ): Result<Int> {
        var synced = 0
        for (tx in localTransactions) {
            val result = addTransaction(tx)
            if (result.isSuccess) synced++
        }
        return Result.success(synced)
    }
}
