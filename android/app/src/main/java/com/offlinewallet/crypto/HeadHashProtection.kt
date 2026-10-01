package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import com.offlinewallet.SecureStorage

/**
 * HeadHashProtection - Implements hardware-backed protection for the chain head.
 * Prevents "Last Node Modification" and "Rollback" attacks.
 */
object HeadHashProtection {
    private const val TAG = "HeadHashProtection"
    private const val PREF_HEAD_HASH = "sealed_head_hash"
    private const val PREF_PREV_HASH = "sealed_prev_hash"
    private const val PREF_ROOT_HASH = "sealed_root_hash"

    /**
     * Store the current head hash in Keystore (Sealed)
     */
    fun storeHeadHash(context: Context, headHash: String) {
        val currentHead = getHeadHash(context)
        if (currentHead != null) {
            // Move current to previous for rollback detection
            val sealedPrev = SecureKeyStore.sealData(HexUtils.decodeHex(currentHead))
            if (sealedPrev != null) {
                saveToStorage(context, PREF_PREV_HASH, HexUtils.encodeHex(sealedPrev))
            }
        }

        val sealedHead = SecureKeyStore.sealData(HexUtils.decodeHex(headHash))
        if (sealedHead != null) {
            saveToStorage(context, PREF_HEAD_HASH, HexUtils.encodeHex(sealedHead))
            Log.d(TAG, "Head hash sealed and stored: ${headHash.take(8)}...")
        }
    }

    /**
     * Initialize the Root Hash (Genesis) in Keystore
     */
    fun storeRootHash(context: Context, rootHash: String) {
        val sealedRoot = SecureKeyStore.sealData(HexUtils.decodeHex(rootHash))
        if (sealedRoot != null) {
            saveToStorage(context, PREF_ROOT_HASH, HexUtils.encodeHex(sealedRoot))
            Log.d(TAG, "Root hash sealed and stored")
        }
    }

    fun getHeadHash(context: Context): String? {
        val hex = getFromStorage(context, PREF_HEAD_HASH) ?: return null
        val unsealed = SecureKeyStore.unsealData(HexUtils.decodeHex(hex))
        return unsealed?.let { HexUtils.encodeHex(it) }
    }

    fun getPrevHash(context: Context): String? {
        val hex = getFromStorage(context, PREF_PREV_HASH) ?: return null
        val unsealed = SecureKeyStore.unsealData(HexUtils.decodeHex(hex))
        return unsealed?.let { HexUtils.encodeHex(it) }
    }

    /**
     * Verify chain integrity using Keystore-stored head hash
     */
    fun verifyBeforeTransaction(context: Context, headHash: String?): VerificationResult {
        if (headHash == null) {
            return VerificationResult.Success("No transactions yet")
        }

        val storedHash = getHeadHash(context)
        if (storedHash == null) {
            // First run recovery or initialization
            storeHeadHash(context, headHash)
            return VerificationResult.Success("Protection initialized")
        }

        if (storedHash == headHash) {
            return VerificationResult.Success("Hardware integrity verified")
        }

        // MISMATCH! Check for rollback
        val prevHash = getPrevHash(context)
        if (prevHash != null && prevHash == headHash) {
            return VerificationResult.Failure("ROLLBACK ATTACK DETECTED! Chain head matches previous state.")
        }

        return VerificationResult.Failure("CHAIN HEAD TAMPERED! DB hash does not match hardware-sealed truth.")
    }

    private fun saveToStorage(context: Context, key: String, value: String) {
        val prefs = context.getSharedPreferences("head_protection", Context.MODE_PRIVATE)
        prefs.edit().putString(key, value).apply()
    }

    private fun getFromStorage(context: Context, key: String): String? {
        val prefs = context.getSharedPreferences("head_protection", Context.MODE_PRIVATE)
        return prefs.getString(key, null)
    }

    sealed class VerificationResult {
        data class Success(val message: String) : VerificationResult()
        data class Failure(val reason: String) : VerificationResult()
    }
}
