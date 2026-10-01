package com.offlinewallet.crypto

import android.util.Base64

object HexUtils {
    /**
     * Decodes a string that could be Hex or Base64.
     */
    fun decodeSafe(input: String?): ByteArray {
        if (input.isNullOrBlank()) return ByteArray(0)
        val clean = input.filter { !it.isWhitespace() }.removePrefix("0x")
        
        // Detection: If it contains non-hex chars or starts with common Base64 prefixes like 'MF' (DER)
        val isHex = clean.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
        
        return if (isHex && clean.length % 2 == 0) {
            decodeHex(clean)
        } else {
            try {
                Base64.decode(clean, Base64.NO_WRAP)
            } catch (e: Exception) {
                // Fallback to hex if base64 fails
                decodeHex(clean)
            }
        }
    }

    fun decodeHex(hex: String): ByteArray {
        val cleanHex = hex.removePrefix("0x").filter { !it.isWhitespace() }
        check(cleanHex.length % 2 == 0) { "Must have an even length" }
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    fun encodeHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
