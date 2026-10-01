package com.offlinewallet.crypto

import android.util.Log
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Enhanced OTP Atomic Swap Protocol
 * Implementation of the 9-Phase LLD for zero-connectivity transfers.
 */
object OTPAtomicSwap {
    private const val TAG = "OTPAtomicSwap"
    private const val OTP_LENGTH = 6
    private const val OTP_EXPIRY_SECONDS = 300 // 5 minutes for user entry

    // Store active swap states
    private val activeSwaps = ConcurrentHashMap<String, SwapState>()
    private val usedOtps = ConcurrentHashMap<String, Long>()
    private val usedTransactions = ConcurrentHashMap<String, Long>()

    enum class SwapStatus {
        IDLE, CHALLENGE_EXCHANGED, VERIFIED, COMMITTED, CANCELLED
    }

    data class SwapState(
        val localId: String,
        val payerId: String,
        val payeeId: String,
        val amount: Int,
        val myOtp: String,
        val myOtpHash: ByteArray,
        var peerOtpHash: ByteArray? = null,
        var peerPublicKey: ByteArray? = null,
        var myPin: String? = null,
        var peerPin: String? = null,
        val timestamp: Long,
        var status: SwapStatus = SwapStatus.IDLE,
        val transactionId: String = "TXN_${System.currentTimeMillis()}_${java.util.UUID.randomUUID().toString().take(8)}"
    )

    data class SwapResult(
        val success: Boolean,
        val message: String = "",
        val state: SwapState? = null
    )

    /**
     * PHASE 0: Generate Challenge
     */
    fun startSwap(
        payerId: String,
        payeeId: String,
        amount: Int,
        localId: String = java.util.UUID.randomUUID().toString()
    ): SwapState {
        // ✅ PERSISTENT STATE PROTECTION: Check if this swap is already in progress
        val existing = activeSwaps[localId]
        if (existing != null) {
            Log.d(TAG, "♻️ Resuming active swap [$localId]. Current Status: ${existing.status}")
            return existing
        }

        // Check for duplicate transaction
        val txKey = "${payerId}_${payeeId}_${amount}_${localId}"
        if (usedTransactions.containsKey(txKey)) {
            Log.w(TAG, "Duplicate transaction detected in memory: $txKey")
        }

        val otp = generateSecureOtp()
        val hash = Hasher.hashOtp(otp)

        val state = SwapState(
            localId = localId,
            payerId = payerId,
            payeeId = payeeId,
            amount = amount,
            myOtp = otp,
            myOtpHash = hash,
            timestamp = System.currentTimeMillis()
        )

        activeSwaps[localId] = state
        usedTransactions[txKey] = System.currentTimeMillis()
        cleanupOldEntries()
        
        Log.d(TAG, "Phase 0: Swap started [$localId]. My OTP: $otp")
        return state
    }

    /**
     * RESUME Swap: Used when a previous session was interrupted but funds already deducted.
     */
    fun resumeSwap(
        localId: String,
        payerId: String,
        payeeId: String,
        amount: Int,
        myOtp: String? = null
    ): SwapState {
        val otp = myOtp ?: generateSecureOtp()
        val hash = Hasher.hashOtp(otp)

        val state = SwapState(
            localId = localId,
            payerId = payerId,
            payeeId = payeeId,
            amount = amount,
            myOtp = otp,
            myOtpHash = hash,
            timestamp = System.currentTimeMillis(),
            status = SwapStatus.IDLE // Restart handshake from beginning but keep ID
        )

        activeSwaps[localId] = state
        Log.d(TAG, "Phase 0 (Resume): Swap resumed [$localId]")
        return state
    }

    /**
     * PHASE 4: Exchange Challenges
     */
    fun onChallengeReceived(localId: String, peerOtpHash: ByteArray, peerPublicKey: ByteArray) {
        activeSwaps[localId]?.let {
            it.peerOtpHash = peerOtpHash
            it.peerPublicKey = peerPublicKey
            it.status = SwapStatus.CHALLENGE_EXCHANGED
            Log.d(TAG, "Phase 4: Challenge exchanged [$localId]")
        }
    }

    /**
     * PHASE 6: Mutual Verification (User enters code from peer's phone)
     */
    fun verifyPeerOtp(localId: String, enteredOtp: String): Boolean {
        val state = activeSwaps[localId] ?: return false
        val peerHash = state.peerOtpHash ?: return false
        
        val computedHash = Hasher.hashOtp(enteredOtp)
        val isValid = computedHash.contentEquals(peerHash)
        
        if (isValid) {
            state.status = SwapStatus.VERIFIED
            Log.d(TAG, "Phase 6: Peer OTP verified [$localId]")
        } else {
            Log.w(TAG, "Phase 6: Peer OTP INVALID [$localId]")
        }
        return isValid
    }

    /**
     * MUTUAL PIN VERIFICATION: Verify the 4-digit code shown on peer's screen.
     */
    fun verifyPin(localId: String, enteredPin: String): Boolean {
        val state = activeSwaps[localId] ?: return false
        val expected = state.myPin ?: return false
        
        val isValid = enteredPin == expected
        if (isValid) {
            state.status = SwapStatus.VERIFIED
            Log.d(TAG, "Mutual PIN Verified [$localId]")
        } else {
            Log.w(TAG, "Mutual PIN INVALID [$localId]. Entered: $enteredPin, Expected: $expected")
        }
        return isValid
    }

    /**
     * FORCE VERIFY: Set state to VERIFIED manually (e.g. from history recovery).
     */
    fun markAsVerified(localId: String) {
        activeSwaps[localId]?.let {
            it.status = SwapStatus.VERIFIED
            Log.d(TAG, "Status forced to VERIFIED for commit [$localId]")
        }
    }

    /**
     * PHASE 8: Commit
     */
    fun commitSwap(localId: String): SwapResult {
        val state = activeSwaps[localId] ?: run {
            Log.e(TAG, "❌ commitSwap failed: State not found for $localId")
            return SwapResult(false, "Swap not found in memory")
        }

        Log.d(TAG, "Attempting commit for $localId. Current Status: ${state.status}")

        if (state.status != SwapStatus.VERIFIED && state.status != SwapStatus.COMMITTED) {
            return SwapResult(false, "Cannot commit: Current status is ${state.status}")
        }

        if (state.status == SwapStatus.COMMITTED) {
            return SwapResult(true, "Already Committed", state)
        }

        if (System.currentTimeMillis() - state.timestamp > OTP_EXPIRY_SECONDS * 1000) {
            cancelSwap(localId)
            return SwapResult(false, "Swap expired")
        }

        // Enhanced double-spend check
        val txKey = "${state.payerId}_${state.payeeId}_${state.amount}_${localId}"
        
        synchronized(activeSwaps) {
            val currentState = activeSwaps[localId] ?: return SwapResult(false, "Swap disappeared")
            if (currentState.status == SwapStatus.COMMITTED) {
                return SwapResult(true, "Committed by other thread", currentState)
            }

            // Check if our OTP was already used (Double-spend protection) with transaction context
            val otpKey = "${state.payerId}_${state.myOtp}_${state.transactionId}"
            if (usedOtps.containsKey(otpKey)) {
                return SwapResult(false, "Security Error: OTP already used")
            }

            // Finalize
            currentState.status = SwapStatus.COMMITTED
            usedOtps[otpKey] = System.currentTimeMillis()
            usedTransactions[txKey] = System.currentTimeMillis()
            
            // DON'T remove yet, let cleanup task handle it so peer can still find it for a few seconds
        }
        
        cleanupOldEntries()
        Log.d(TAG, "Phase 8: Swap committed successfully [$localId]")
        return SwapResult(true, "Committed", state)
    }

    fun cancelSwap(localId: String) {
        activeSwaps[localId]?.status = SwapStatus.CANCELLED
        activeSwaps.remove(localId)
        Log.d(TAG, "Swap cancelled [$localId]")
    }

    /**
     * Generate a cryptographically secure OTP and its hash
     */
    fun generateChallenge(): Pair<String, ByteArray> {
        val otp = generateSecureOtp()
        val hash = Hasher.hashOtp(otp)
        return Pair(otp, hash)
    }

    private fun generateSecureOtp(): String {
        val random = SecureRandom()
        val otp = 100000 + random.nextInt(900000)
        return otp.toString()
    }

    private fun cleanupOldEntries() {
        val now = System.currentTimeMillis()
        val expiryTime = OTP_EXPIRY_SECONDS * 1000L
        usedOtps.entries.removeIf { now - it.value > expiryTime }
        usedTransactions.entries.removeIf { now - it.value > expiryTime }
    }

    private fun cleanupOldOtps() {
        // Deprecated in favor of cleanupOldEntries
        cleanupOldEntries()
    }

    fun getSwapState(localId: String) = activeSwaps[localId]
}
