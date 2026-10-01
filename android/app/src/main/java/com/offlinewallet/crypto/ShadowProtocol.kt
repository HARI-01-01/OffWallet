package com.offlinewallet.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest

/**
 * Shadow Protocol v1 - Core Utilities
 */
object ShadowProtocol {

    // Domain Separation Tags
    const val TAG_ATTEST_CHALLENGE = "shadow/v1/attest-challenge"
    const val TAG_GENESIS = "shadow/v1/genesis"
    const val TAG_PASS = "shadow/v1/pass"
    const val TAG_SESSION_AUTH = "shadow/v1/session-auth"
    const val TAG_DEBIT_BLOCK = "shadow/v1/debit-block"
    const val TAG_RECEIPT = "shadow/v1/receipt"
    const val TAG_ACK = "shadow/v1/ack"
    const val TAG_BLOCK_HASH = "shadow/v1/block-hash"
    const val TAG_SAS = "shadow/v1/sas"
    const val TAG_TOPUP = "shadow/v1/topup"
    const val TAG_KEY_A2B = "shadow/v1/key/a2b"
    const val TAG_KEY_B2A = "shadow/v1/key/b2a"

    /**
     * SHA-256 Hash
     */
    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * HKDF-SHA256 Implementation using BouncyCastle
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, len: Int): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info.toByteArray(Charsets.UTF_8)))
        val okm = ByteArray(len)
        generator.generateBytes(okm, 0, len)
        return okm
    }

    /**
     * sign_input(tag, payload_bytes) = tag || 0x00 || payload_bytes
     */
    fun prepareSignInput(tag: String, payload: ByteArray): ByteArray {
        return tag.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) + payload
    }

    /**
     * ChaCha20-Poly1305 Authenticated Encryption
     */
    fun encrypt(key: ByteArray, nonce: Long, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val aead = ChaCha20Poly1305()
        val nonceBytes = ByteArray(12)
        java.nio.ByteBuffer.wrap(nonceBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(nonce)
        
        aead.init(true, AEADParameters(KeyParameter(key), 128, nonceBytes, aad))
        val ciphertext = ByteArray(aead.getOutputSize(plaintext.size))
        val len = aead.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        aead.doFinal(ciphertext, len)
        return ciphertext
    }

    fun decrypt(key: ByteArray, nonce: Long, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val aead = ChaCha20Poly1305()
        val nonceBytes = ByteArray(12)
        java.nio.ByteBuffer.wrap(nonceBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(nonce)
        
        aead.init(false, AEADParameters(KeyParameter(key), 128, nonceBytes, aad))
        val plaintext = ByteArray(aead.getOutputSize(ciphertext.size))
        val len = aead.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
        aead.doFinal(plaintext, len)
        return plaintext
    }

    /**
     * Base45 Encoding (Simplified as Base64 for density)
     */
    fun base45Encode(data: ByteArray): String {
        return "SHV1:" + android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP)
    }

    fun base45Decode(input: String): ByteArray {
        if (!input.startsWith("SHV1:")) throw Exception("Invalid Shadow v1 payload")
        return android.util.Base64.decode(input.substring(5), android.util.Base64.NO_WRAP)
    }
}
