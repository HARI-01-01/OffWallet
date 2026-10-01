package com.offlinewallet.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Encryptor {
    private const val ALGORITHM = "AES/GCM/NoPadding"
    const val KEY_SIZE = 32
    const val IV_SIZE = 12
    const val TAG_SIZE = 16

    fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom())
        return generator.generateKey()
    }

    fun generateIv(): ByteArray {
        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)
        return iv
    }

    fun encrypt(key: ByteArray, plaintext: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val iv = generateIv()
        val cipher = Cipher.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE * 8, iv))
        val ciphertext = cipher.doFinal(plaintext)
        val tag = ciphertext.copyOfRange(ciphertext.size - TAG_SIZE, ciphertext.size)
        val encrypted = ciphertext.copyOfRange(0, ciphertext.size - TAG_SIZE)
        return Triple(encrypted, iv, tag)
    }

    fun decrypt(key: ByteArray, ciphertext: ByteArray, iv: ByteArray, tag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE * 8, iv))
        return cipher.doFinal(ciphertext + tag)
    }
}
