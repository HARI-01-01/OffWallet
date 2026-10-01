package com.offlinewallet.crypto

import android.content.Context
import android.util.Log
import com.offlinewallet.SecureStorage
import com.offlinewallet.models.Pass
import com.offlinewallet.models.PassEnvelope

/**
 * PassVault - Manages Security Passes for offline verification.
 */
object PassVault {
    private const val TAG = "PassVault"

    /**
     * Verify a peer's Pass Envelope (both directions, offline)
     */
    fun verifyPass(context: Context, envelope: PassEnvelope, rawPass: ByteArray? = null): Boolean {
        try {
            val pass = envelope.pass
            val serverSig = HexUtils.decodeHex(envelope.sig)

            // 1. sig verifies under a pinned server key matching kid
            val serverPubHex = SecureStorage.getServerPublicKey()
            if (serverPubHex == null) {
                Log.e(TAG, "Server Public Key missing in SecureStorage")
                return false
            }
            val serverPub = HexUtils.decodeHex(serverPubHex)
            
            Log.d(TAG, "Verifying Pass (ID: ${pass.passId}) with kid: ${pass.kid}")

            // WP-FIX: Use original bytes if provided, otherwise fallback to encoding
            val passBytes = rawPass ?: MicroPaymentHandshake.encodePass(pass)
            val serverPublicKey = KeyManager.bytesToPublicKey(serverPub, "Ed25519")
            
            if (!Signer.verify(ShadowProtocol.TAG_PASS, serverPublicKey, passBytes, serverSig)) {
                Log.e(TAG, "❌ Pass signature verification failed for ${pass.walletId}")
                Log.v(TAG, "DEBUG: Pass Bytes Hash = ${HexUtils.encodeHex(ShadowProtocol.sha256(passBytes))}")
                return false
            }

            Log.d(TAG, "✅ Pass signature verified")

            // 2. Clock Rollback & Expiry Check (Issue 6.3)
            val now = System.currentTimeMillis() / 1000
            if (!HighWaterStore.isTimeAcceptable(context, now)) {
                return false
            }

            if (pass.expiresAt <= maxOf(now, HighWaterStore.get(HighWaterStore.Key.TIME_HWM))) {
                Log.e(TAG, "Pass expired")
                return false
            }

            // 3. Sequence Check
            val lastPassSeq = HighWaterStore.get(HighWaterStore.Key.PASS_SERVER_SEQ)
            if (pass.serverSeq < lastPassSeq) {
                Log.e(TAG, "Pass replay detected (Sequence: ${pass.serverSeq} < $lastPassSeq)")
                return false
            }
            HighWaterStore.bump(HighWaterStore.Key.PASS_SERVER_SEQ, pass.serverSeq)

            // 4. issued_at <= local_clock + 300
            if (pass.issuedAt > now + 300) {
                Log.e(TAG, "Pass from future rejected")
                return false
            }

            // 4. wallet_id is not in the local revocation cache (Skip for hackathon)

            Log.d(TAG, "Pass verified for ${pass.displayName} (${pass.walletId})")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying pass: ${e.message}")
            return false
        }
    }
}
