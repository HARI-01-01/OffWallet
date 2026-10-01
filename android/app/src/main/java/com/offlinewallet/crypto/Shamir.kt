package com.offlinewallet.crypto

import java.security.SecureRandom

/**
 * Shamir's Secret Sharing (2-of-3) implementation over GF(256).
 * Used for wallet key recovery as per PRD §13.
 */
object Shamir {
    private val random = SecureRandom()

    /**
     * Splits a secret into 3 shards, where any 2 can reconstruct it.
     */
    fun split(secret: ByteArray): List<ByteArray> {
        val shard1 = ByteArray(secret.size)
        val shard2 = ByteArray(secret.size)
        val shard3 = ByteArray(secret.size)

        // Generate random polynomial f(x) = secret + a*x over GF(256)
        // a is a random coefficient for each byte of the secret
        val a = ByteArray(secret.size)
        random.nextBytes(a)

        for (i in secret.indices) {
            val s = secret[i].toInt() and 0xFF
            val coeff = a[i].toInt() and 0xFF

            // f(1) = secret ^ (coeff * 1)
            shard1[i] = (s xor gfMul(coeff, 1)).toByte()
            // f(2) = secret ^ (coeff * 2)
            shard2[i] = (s xor gfMul(coeff, 2)).toByte()
            // f(3) = secret ^ (coeff * 3)
            shard3[i] = (s xor gfMul(coeff, 3)).toByte()
        }

        return listOf(shard1, shard2, shard3)
    }

    /**
     * Reconstructs the secret from 2 shards.
     * x1, x2 are the indices (1, 2, or 3).
     */
    fun combine(x1: Int, shard1: ByteArray, x2: Int, shard2: ByteArray): ByteArray {
        val secret = ByteArray(shard1.size)
        
        // Lagrange interpolation at x=0:
        // f(0) = (f(x1) * x2 / (x2 - x1)) ^ (f(x2) * x1 / (x1 - x2))
        
        val l1 = gfDiv(x2, x2 xor x1)
        val l2 = gfDiv(x1, x1 xor x2)

        for (i in shard1.indices) {
            val y1 = shard1[i].toInt() and 0xFF
            val y2 = shard2[i].toInt() and 0xFF
            
            secret[i] = (gfMul(y1, l1) xor gfMul(y2, l2)).toByte()
        }

        return secret
    }

    // --- GF(256) Math ---

    private val gfExp = IntArray(512)
    private val gfLog = IntArray(256)

    init {
        var x = 1
        for (i in 0 until 255) {
            gfExp[i] = x
            gfExp[i + 255] = x
            gfLog[x] = i
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D // AES polynomial: x^8 + x^4 + x^3 + x + 1
        }
    }

    private fun gfMul(a: Int, b: Int): Int {
        if (a == 0 || b == 0) return 0
        return gfExp[gfLog[a] + gfLog[b]]
    }

    private fun gfDiv(a: Int, b: Int): Int {
        if (a == 0) return 0
        if (b == 0) throw ArithmeticException("Division by zero in GF(256)")
        return gfExp[gfLog[a] + 255 - gfLog[b]]
    }
}
