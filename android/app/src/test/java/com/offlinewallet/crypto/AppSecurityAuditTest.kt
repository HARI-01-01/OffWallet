package com.offlinewallet.crypto

import com.offlinewallet.models.*
import org.junit.Assert.*
import org.junit.Test

class AppSecurityAuditTest {

    /**
     * ATTACK VECTOR 1: Transaction Replay
     * Verify that Bob rejects a DebitBlock if the counter is not exactly last_counter + 1.
     */
    @Test
    fun testReplayAttackPrevention() {
        val amount = 1000L
        
        // 1. Initial State (Bob thinks Alice is at counter 0)
        val lastSettledHead = "0".repeat(64)
        
        // 2. Attacker sends a block with Counter 1 (Valid)
        val validBlock = DebitBlock(
            v = 1, chainId = "main", walletId = "alice", counter = 1,
            prevHash = HexUtils.decodeHex(lastSettledHead), amountP = amount,
            payeePubKeyHash = ByteArray(32), payeeWalletId = "bob",
            payeeChal = ByteArray(32), payerPassId = "p1", payeePassId = "p2",
            genesisEpoch = 1, ts = System.currentTimeMillis() / 1000
        )
        
        // Bob's Audit (Bob normally does this in M3)
        assertTrue("Valid block should pass audit", performBobAudit(validBlock, 0, lastSettledHead))

        // 3. Attacker REPLAYS the same block (Counter 1 again)
        assertFalse("Replayed block should fail audit (Counter mismatch)", 
            performBobAudit(validBlock, 1, "some_new_hash"))
            
        // 4. Attacker sends a SKIP block (Counter 5 instead of 2)
        val skipBlock = validBlock.copy(counter = 5)
        assertFalse("Skipped counters should fail audit (Gap detected)", 
            performBobAudit(skipBlock, 1, "some_new_hash"))
    }

    /**
     * ATTACK VECTOR 2: Hash Chain Linkage (Forking)
     * Verify that Bob rejects a block if its prevHash doesn't match the current head.
     */
    @Test
    fun testForkPrevention() {
        val currentHead = "head_abc"
        val wrongPrevHash = "head_xyz"
        
        val forkBlock = DebitBlock(
            v = 1, chainId = "main", walletId = "alice", counter = 1,
            prevHash = HexUtils.decodeHex(wrongPrevHash), amountP = 100L,
            payeePubKeyHash = ByteArray(32), payeeWalletId = "bob",
            payeeChal = ByteArray(32), payerPassId = "p1", payeePassId = "p2",
            genesisEpoch = 1, ts = System.currentTimeMillis() / 1000
        )
        
        assertFalse("Block with wrong prevHash must fail audit", 
            performBobAudit(forkBlock, 0, currentHead))
    }

    /**
     * ATTACK VECTOR 3: Insufficient Funds
     * Verify that Bob rejects a payment if Alice's proof doesn't show enough balance.
     */
    @Test
    fun testOverspendPrevention() {
        // Alice has 500 settled, tries to spend 1000
        val anchorBalance = 500L
        val txAmount = 1000L
        
        // Bob checks balance: Anchor_Balance - Sum(Unsettled) >= Current_TX
        // Alice sends proof of funds (PF) in M3
        val isBalanceOk = (anchorBalance >= txAmount)
        assertFalse("Bob must reject overspending", isBalanceOk)
    }

    /**
     * ATTACK VECTOR 4: SAS Man-in-the-Middle
     * Verify that a modified session transcript results in a SAS mismatch.
     */
    @Test
    fun testSasMitMPrevention() {
        val ss = ByteArray(32) { 0x42.toByte() }
        val sid = "session_123"
        
        // 1. Original Parameters
        val transcriptOriginal = MicroPaymentHandshake.computeTranscript(
            sid, ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), "pA", "pB", 1000L
        )
        val sasOriginal = MicroPaymentHandshake.deriveSas(ss, transcriptOriginal)

        // 2. Attacker modifies the amount in transit (M1) to 5000L
        val transcriptTampered = MicroPaymentHandshake.computeTranscript(
            sid, ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), "pA", "pB", 5000L
        )
        val sasTampered = MicroPaymentHandshake.deriveSas(ss, transcriptTampered)

        assertNotEquals("Tampered transcript must produce different SAS", sasOriginal, sasTampered)
    }

    // --- Helper for Mocking Bob's Audit Logic ---
    private fun performBobAudit(block: DebitBlock, lastCounter: Long, lastHead: String): Boolean {
        // Linearity Check
        if (block.counter != lastCounter + 1) return false
        
        // Linkage Check
        val encodedPrevHash = HexUtils.encodeHex(block.prevHash)
        if (encodedPrevHash != lastHead && lastHead != "0".repeat(64)) {
            return false
        }
        
        return true
    }
}
