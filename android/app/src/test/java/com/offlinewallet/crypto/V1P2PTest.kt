package com.offlinewallet.crypto

import com.offlinewallet.models.*
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class V1P2PTest {

    @Test
    fun testV1HandshakeM1toM5() {
        val sid = UUID.randomUUID().toString()
        val amount = 1000L
        
        // Setup Alice (Payer)
        val aliceKeys = KeyManager.generateKeyPair()
        val alicePubKey = KeyManager.publicKeyToBytes(aliceKeys.public)
        val alicePass = Pass(
            v = 1, kid = "k1", walletId = "alice", displayName = "Alice",
            devicePubKeyHash = HexUtils.encodeHex(alicePubKey), 
            attestTier = "TEE", perTxCapP = 5000, aggregateCapP = 20000,
            txnCountCap = 10, recvUnsettledCapP = 5000, recvPerPeerCapP = 1000,
            passId = "p_alice", serverSeq = 1, issuedAt = 100, expiresAt = 200,
            genesisEpoch = 1, lastSettledCounter = 0, lastSettledHead = "0".repeat(64)
        )
        val alicePassEnv = PassEnvelope(alicePass, "sig_alice")
        val chalA = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
        val epkA = KeyManager.generateKeyPair().public.encoded // simplified

        // Setup Bob (Payee)
        val bobKeys = KeyManager.generateKeyPair()
        val bobPubKey = KeyManager.publicKeyToBytes(bobKeys.public)
        val bobPass = Pass(
            v = 1, kid = "k1", walletId = "bob", displayName = "Bob",
            devicePubKeyHash = HexUtils.encodeHex(bobPubKey),
            attestTier = "TEE", perTxCapP = 5000, aggregateCapP = 20000,
            txnCountCap = 10, recvUnsettledCapP = 5000, recvPerPeerCapP = 1000,
            passId = "p_bob", serverSeq = 2, issuedAt = 100, expiresAt = 200,
            genesisEpoch = 1, lastSettledCounter = 0, lastSettledHead = "0".repeat(64)
        )
        val bobPassEnv = PassEnvelope(bobPass, "sig_bob")
        val chalB = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
        val epkB = KeyManager.generateKeyPair().public.encoded

        // --- M1: Init (Alice -> Bob) ---
        val m1 = MicroPaymentHandshake.SessionInit(sid, epkA, chalA, alicePassEnv, amount)
        val m1Encoded = MicroPaymentHandshake.encodeSessionInit(m1)
        val m1Decoded = MicroPaymentHandshake.decodeSessionInit(m1Encoded)
        
        assertEquals(sid, m1Decoded.sid)
        assertEquals(amount, m1Decoded.amount_p)
        assertArrayEquals(chalA, m1Decoded.chal_A)

        // --- M2: Auth (Bob -> Alice) ---
        val sigB = ByteArray(64) // mock
        val m2 = MicroPaymentHandshake.SessionAuth(epkB, chalB, sigB, bobPassEnv)
        val m2Encoded = MicroPaymentHandshake.encodeSessionAuth(m2)
        val m2Decoded = MicroPaymentHandshake.decodeSessionAuth(m2Encoded)
        
        assertArrayEquals(chalB, m2Decoded.chal_B)
        assertEquals(bobPass.walletId, m2Decoded.pass_B.pass.walletId)

        // --- M3: Commit (Alice -> Bob) ---
        val block = DebitBlock(
            v = 1, chainId = "main", walletId = "alice", counter = 1,
            prevHash = ByteArray(32), amountP = amount,
            payeePubKeyHash = bobPubKey, payeeWalletId = "bob",
            payeeChal = chalB, payerPassId = "p_alice", payeePassId = "p_bob",
            genesisEpoch = 1, ts = 150
        )
        val sigA = ByteArray(64) // mock
        val m3Encoded = MicroPaymentHandshake.encodeM3(block, sigA)
        val (blockDecoded, sigADecoded) = MicroPaymentHandshake.decodeM3(m3Encoded)
        
        assertEquals(amount, blockDecoded.amountP)
        assertArrayEquals(sigA, sigADecoded)

        // --- M4: Receipt (Bob -> Alice) ---
        val receipt = Receipt(
            v = 1, blockHash = ByteArray(32), payeeWalletId = "bob",
            payeeCounter = 1, payeePrevHash = ByteArray(32),
            payerChal = chalA, ts = 160
        )
        val sigB_Receipt = ByteArray(64)
        val m4Encoded = MicroPaymentHandshake.encodeM4(receipt, sigB_Receipt)
        val (receiptDecoded, sigBDecoded) = MicroPaymentHandshake.decodeM4(m4Encoded)
        
        assertEquals("bob", receiptDecoded.payeeWalletId)
        assertArrayEquals(chalA, receiptDecoded.payerChal)

        // --- SAS Derivation ---
        val ss = ByteArray(32) // mock shared secret
        val transcriptAlice = MicroPaymentHandshake.computeTranscript(
            sid, epkA, epkB, chalA, chalB, alicePass.passId, bobPass.passId, amount
        )
        val transcriptBob = MicroPaymentHandshake.computeTranscript(
            sid, epkA, epkB, chalA, chalB, alicePass.passId, bobPass.passId, amount
        )
        
        assertArrayEquals(transcriptAlice, transcriptBob)
        
        val sasAlice = MicroPaymentHandshake.deriveSas(ss, transcriptAlice)
        val sasBob = MicroPaymentHandshake.deriveSas(ss, transcriptBob)
        
        assertEquals(sasAlice, sasBob)
        assertEquals(6, sasAlice.length)
    }
}
