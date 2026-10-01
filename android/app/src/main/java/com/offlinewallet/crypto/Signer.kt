package com.offlinewallet.crypto

import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

object Signer {
    const val SIGNATURE_SIZE = 64
    
    // P-256 Curve Order N and N/2 for Low-S normalization
    private val CURVE_N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val N_HALF = CURVE_N.shiftRight(1)

    fun sign(tag: String, privateKey: PrivateKey, message: ByteArray): ByteArray? {
        val taggedMessage = tag.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) + message
        
        // Case 1: Hardware Keystore key (encoded is null)
        if (privateKey.encoded == null) {
            try {
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update(taggedMessage)
                val der = signature.sign()
                return normalize(der)
            } catch (e: UserNotAuthenticatedException) {
                // Rethrow to allow fallback logic to catch it
                throw e
            } catch (e: Exception) {
                Log.e("Signer", "Keystore sign failed", e)
                return null
            }
        }

        // Case 2: Software EC key (e.g. from server/SecureStorage)
        if (privateKey.algorithm == "EC") {
            return try {
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update(taggedMessage)
                val der = signature.sign()
                normalize(der)
            } catch (e: Exception) {
                Log.e("Signer", "Software EC sign failed", e)
                null
            }
        }

        // Case 3: Ed25519 software key
        return try {
            val privateKeyBytes = KeyManager.privateKeyToBytes(privateKey) ?: return null
            signWithBytes(taggedMessage, privateKeyBytes)
        } catch (e: Exception) {
            Log.e("Signer", "Ed25519 sign failed", e)
            null
        }
    }

    fun verify(tag: String, publicKey: PublicKey, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != SIGNATURE_SIZE) return false
        val taggedMessage = tag.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) + message
        
        Log.d("Signer", "Verifying Tagged Message: ${HexUtils.encodeHex(taggedMessage).take(32)}...")

        // If EC key
        if (publicKey.algorithm == "EC") {
            // Reject high-S
            val s = BigInteger(1, signature.sliceArray(32 until 64))
            if (s > N_HALF) return false

            return try {
                val der = denormalize(signature)
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(publicKey)
                verifier.update(taggedMessage)
                verifier.verify(der)
            } catch (e: Exception) {
                false
            }
        }

        // Fallback to Ed25519
        return try {
            val publicKeyBytes = KeyManager.publicKeyToBytes(publicKey)
            verifyWithBytes(taggedMessage, publicKeyBytes, signature)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Converts DER signature to raw 64-byte r||s with low-S.
     */
    fun normalize(der: ByteArray): ByteArray {
        val seq = ASN1Sequence.getInstance(der)
        val r = ASN1Integer.getInstance(seq.getObjectAt(0)).value
        var s = ASN1Integer.getInstance(seq.getObjectAt(1)).value

        // Enforce Low-S
        if (s > N_HALF) {
            s = CURVE_N.subtract(s)
        }

        val res = ByteArray(64)
        val rBytes = r.toByteArray().unpadded()
        val sBytes = s.toByteArray().unpadded()
        
        System.arraycopy(rBytes, 0, res, 32 - rBytes.size, rBytes.size)
        System.arraycopy(sBytes, 0, res, 64 - sBytes.size, sBytes.size)
        return res
    }

    /**
     * Converts raw 64-byte r||s to DER.
     */
    private fun denormalize(sig64: ByteArray): ByteArray {
        val r = BigInteger(1, sig64.sliceArray(0 until 32))
        val s = BigInteger(1, sig64.sliceArray(32 until 64))
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(r))
        v.add(ASN1Integer(s))
        return DERSequence(v).encoded
    }

    private fun ByteArray.unpadded(): ByteArray {
        return if (this.size > 32 && this[0] == 0.toByte()) {
            this.sliceArray(1 until this.size)
        } else {
            this
        }
    }

    fun signWithBytes(message: ByteArray, privateKeyBytes: ByteArray): ByteArray {
        require(privateKeyBytes.size == KeyManager.PRIVATE_KEY_SIZE) { 
            "Private key must be ${KeyManager.PRIVATE_KEY_SIZE} bytes" 
        }
        val privParams = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verifyWithBytes(tag: String, publicKeyBytes: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKeyBytes.size != KeyManager.PUBLIC_KEY_SIZE || signature.size != SIGNATURE_SIZE) {
            return false
        }
        val taggedMessage = tag.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) + message
        return try {
            val pubParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubParams)
            verifier.update(taggedMessage, 0, taggedMessage.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    fun verifyWithBytes(message: ByteArray, publicKeyBytes: ByteArray, signature: ByteArray): Boolean {
        // Legacy method
        if (publicKeyBytes.size != KeyManager.PUBLIC_KEY_SIZE || signature.size != SIGNATURE_SIZE) {
            return false
        }
        return try {
            val pubParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubParams)
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }
}
