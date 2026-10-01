package com.offlinewallet.crypto

import java.security.MessageDigest
import java.security.SecureRandom

object Hasher {
    private const val ALGORITHM = "SHA-256"
    const val DIGEST_SIZE = 32

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance(ALGORITHM).digest(data)
    }

    fun hashOtp(otp: String): ByteArray {
        return sha256(otp.toByteArray(Charsets.UTF_8))
    }

    fun generateChallenge(): ByteArray {
        val nonce = ByteArray(32)
        SecureRandom().nextBytes(nonce)
        return nonce
    }
}
