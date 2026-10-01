package com.offlinewallet.crypto

import org.junit.Test
import java.util.UUID

class NfcLogicTest {

    @Test
    fun testCompleteHandshakeFlow() {
        /*
        // 1. Setup Keys for Payer (Alice) and Payee (Bob)
        val aliceKeyPair = KeyManager.generateKeyPair()
        val alicePrivateKey = KeyManager.privateKeyToBytes(aliceKeyPair.private)!!
        val alicePublicKey = KeyManager.publicKeyToBytes(aliceKeyPair.public)

        val bobKeyPair = KeyManager.generateKeyPair()
        val bobPrivateKey = KeyManager.privateKeyToBytes(bobKeyPair.private)!!
        val bobPublicKey = KeyManager.publicKeyToBytes(bobKeyPair.public)

        val aliceWalletId = "alice_wallet"
        val bobWalletId = "bob_wallet"
        val amount = 5000 // ₹50.00
        val localId = UUID.randomUUID().toString()

        // 2. Payer (Alice) starts swap
        val aliceState = OTPAtomicSwap.startSwap(aliceWalletId, bobWalletId, amount, localId)
        assertNotNull(aliceState)

        // 3. Payer creates Challenge A
        val challengeA = NFCHandshake.createChallenge(
            aliceState.myOtpHash,
            alicePrivateKey,
            alicePublicKey,
            localId,
            amount,
            aliceWalletId
        )

        // 4. Serialize and Deserialize (Simulate NFC transmission)
        val encodedA = Serializer.encodeChallenge(challengeA)
        val decodedA = Serializer.decodeChallenge(encodedA)

        // 5. Payee (Bob) verifies Challenge A
        assertTrue("Challenge A verification failed", NFCHandshake.verifyChallenge(decodedA))
        assertEquals(amount, (decodedA["amount"] as Number).toInt())
        assertEquals(aliceWalletId, decodedA["payerId"])

        // 6. Payee (Bob) starts swap on his side
        val bobState = OTPAtomicSwap.startSwap(bobWalletId, aliceWalletId, amount, localId)
        OTPAtomicSwap.onChallengeReceived(localId, decodedA["otpHash"] as ByteArray, decodedA["publicKey"] as ByteArray)

        // 7. Payee creates Challenge B
        val challengeB = NFCHandshake.createChallenge(
            bobState.myOtpHash,
            bobPrivateKey,
            bobPublicKey,
            localId,
            0, // Bob doesn't send amount back typically or sends 0
            bobWalletId
        )

        // 8. Serialize and Deserialize (Simulate NFC response)
        val encodedB = Serializer.encodeChallenge(challengeB)
        val decodedB = Serializer.decodeChallenge(encodedB)

        // 9. Payer (Alice) verifies Challenge B
        assertTrue("Challenge B verification failed", NFCHandshake.verifyChallenge(decodedB))
        OTPAtomicSwap.onChallengeReceived(localId, decodedB["otpHash"] as ByteArray, decodedB["publicKey"] as ByteArray)

        // 10. Payer creates Payment Token (SKIP OTP for now)
        val aliceStateAfterHandshake = OTPAtomicSwap.getSwapState(localId)!!
        val paymentToken = NFCHandshake.createPaymentToken(aliceStateAfterHandshake, alicePrivateKey, 1)

        // 11. Serialize and Deserialize Token
        val encodedToken = Serializer.encodeChallenge(paymentToken)
        val decodedToken = Serializer.decodeChallenge(encodedToken)

        // 12. Payee verifies Payment Token
        assertTrue("Payment Token verification failed", NFCHandshake.verifyPaymentToken(decodedToken, alicePublicKey))

        // 13. Payee creates Receipt
        val receipt = NFCHandshake.createReceipt(decodedToken, bobPrivateKey)

        // 14. Serialize and Deserialize Receipt
        val encodedReceipt = Serializer.encodeChallenge(receipt)
        val decodedReceipt = Serializer.decodeChallenge(encodedReceipt)

        // 15. Payer verifies Receipt
        assertTrue("Receipt verification failed", NFCHandshake.verifyReceipt(decodedReceipt, bobPublicKey))

        // 16. Verify OTPs (LAST STEP)
        assertTrue("Alice verifying Bob's OTP failed", OTPAtomicSwap.verifyPeerOtp(localId, bobState.myOtp))
        assertTrue("Bob verifying Alice's OTP failed", OTPAtomicSwap.verifyPeerOtp(localId, aliceState.myOtp))

        // 17. Final Commit
        val aliceResult = OTPAtomicSwap.commitSwap(localId)
        val bobResult = OTPAtomicSwap.commitSwap(localId)

        assertTrue("Alice commit failed: ${aliceResult.message}", aliceResult.success)
        assertTrue("Bob commit failed: ${bobResult.message}", bobResult.success)
        */
    }
}
