package com.offlinewallet.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SecureKeyStore - Handles secure storage of cryptographic keys
 * using Android Keystore system (hardware-backed when available)
 */
object SecureKeyStore {
    private const val TAG = "SecureKeyStore"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "offlinepay_"
    private const val NONCE_KEY_ALIAS = "offlinepay_nonce_key"
    private const val MASTER_KEY_ALIAS = "offlinepay_master_secret"
    private const val DB_WRAPPING_KEY_ALIAS = "offlinepay_db_wrap"
    private const val PREFS_DBK = "sealed_db_key"

    private lateinit var keyStore: KeyStore

    fun init() {
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            if (!keyStore.containsAlias(NONCE_KEY_ALIAS)) generateNonceKey()
            if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) generateMasterKey()
            if (!keyStore.containsAlias(DB_WRAPPING_KEY_ALIAS)) generateDbWrappingKey()
        } catch (e: Exception) { Log.e(TAG, "KeyStore Init Fail", e) }
    }

    private fun generateMasterKey() {
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(false).build()
            keyGenerator.init(spec); keyGenerator.generateKey()
        } catch (e: Exception) { Log.e(TAG, "Master Keygen Fail", e) }
    }

    private fun generateDbWrappingKey() {
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(DB_WRAPPING_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build()
            keyGenerator.init(spec); keyGenerator.generateKey()
        } catch (e: Exception) { Log.e(TAG, "DB Wrap Keygen Fail", e) }
    }

    fun getDatabaseKey(context: Context): String {
        val prefs = context.getSharedPreferences("secure_vault", Context.MODE_PRIVATE)
        val sealedHex = prefs.getString(PREFS_DBK, null)
        if (sealedHex != null) {
            val unsealed = unsealWithAlias(HexUtils.decodeHex(sealedHex), DB_WRAPPING_KEY_ALIAS)
            if (unsealed != null) return HexUtils.encodeHex(unsealed)
        }
        val dbk = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        val sealed = sealWithAlias(dbk, DB_WRAPPING_KEY_ALIAS)
        if (sealed != null) prefs.edit().putString(PREFS_DBK, HexUtils.encodeHex(sealed)).apply()
        return HexUtils.encodeHex(dbk)
    }

    private fun sealWithAlias(data: ByteArray, alias: String): ByteArray? {
        return try {
            val key = keyStore.getKey(alias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.iv + cipher.doFinal(data)
        } catch (e: Exception) { null }
    }

    private fun unsealWithAlias(sealedData: ByteArray, alias: String): ByteArray? {
        return try {
            if (sealedData.size <= 12) return null
            val iv = sealedData.sliceArray(0 until 12); val encrypted = sealedData.sliceArray(12 until sealedData.size)
            val key = keyStore.getKey(alias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(encrypted)
        } catch (e: Exception) { null }
    }

    fun sealData(data: ByteArray): ByteArray? = sealWithAlias(data, MASTER_KEY_ALIAS)
    fun unsealData(data: ByteArray): ByteArray? = unsealWithAlias(data, MASTER_KEY_ALIAS)

    private fun generateNonceKey() {
        try {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            kg.init(KeyGenParameterSpec.Builder(NONCE_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
            kg.generateKey()
        } catch (e: Exception) { }
    }

    fun generateAndStoreKeyPair(context: Context, walletId: String, useBiometrics: Boolean = false, challenge: ByteArray? = null): KeyPair? {
        val alias = "$KEY_ALIAS_PREFIX$walletId"
        if (keyStore.containsAlias(alias)) return getKeyPair(walletId)
        return try {
            try { generateKeyPairWithSpec(alias, useBiometrics, challenge, true) }
            catch (e: Exception) { generateKeyPairWithSpec(alias, useBiometrics, challenge, false) }
        } catch (e: Exception) { null }
    }

    private fun generateKeyPairWithSpec(alias: String, auth: Boolean, challenge: ByteArray?, strongBox: Boolean): KeyPair? {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(auth)
            .setInvalidatedByBiometricEnrollment(true)
        
        if (auth && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(60, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else if (auth) {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(60)
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(strongBox)
            // Use reflection to set rollback resistant to avoid compile errors on older SDKs
            try {
                val method = builder.javaClass.getMethod("setRollbackResistant", Boolean::class.java)
                method.invoke(builder, true)
            } catch (e: Exception) {
                Log.d(TAG, "setRollbackResistant not available")
            }
        }
        
        challenge?.let { builder.setAttestationChallenge(it) }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        generator.initialize(builder.build())
        return generator.generateKeyPair()
    }

    fun sign(walletId: String, tag: String, data: ByteArray): ByteArray? {
        val privateKey = getPrivateKey(walletId) ?: run {
            Log.e(TAG, "Sign failed: No private key found for wallet $walletId")
            return null
        }
        return try {
            Signer.sign(tag, privateKey, data)
        } catch (e: UserNotAuthenticatedException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Sign operation failed", e)
            null
        }
    }

    fun getKeyPair(walletId: String): KeyPair? {
        val alias = "$KEY_ALIAS_PREFIX$walletId"
        if (!keyStore.containsAlias(alias)) return null
        val pk = keyStore.getKey(alias, null) as? PrivateKey; val pub = keyStore.getCertificate(alias)?.publicKey
        return if (pk != null && pub != null) KeyPair(pub, pk) else null
    }

    fun keyExists(walletId: String): Boolean = keyStore.containsAlias("$KEY_ALIAS_PREFIX$walletId")

    fun isKeyValid(walletId: String): Boolean {
        val alias = "$KEY_ALIAS_PREFIX$walletId"
        if (!::keyStore.isInitialized || !keyStore.containsAlias(alias)) return false
        return try {
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return false
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            true
        } catch (e: UserNotAuthenticatedException) {
            true // Key is valid, just needs auth
        } catch (e: Exception) {
            // KeyPermanentlyInvalidatedException or other fatal errors
            Log.e(TAG, "Key $alias is invalid: ${e.message}")
            false
        }
    }

    fun deleteKey(walletId: String): Boolean { try { val alias = "$KEY_ALIAS_PREFIX$walletId"; if (keyStore.containsAlias(alias)) { keyStore.deleteEntry(alias); return true } } catch (e: Exception) { }; return false }
    fun getAttestationChain(walletId: String): List<String>? = keyStore.getCertificateChain("$KEY_ALIAS_PREFIX$walletId")?.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
    fun getPrivateKey(walletId: String): PrivateKey? {
        // 1. Try Hardware Keystore (Preferred)
        val alias = "$KEY_ALIAS_PREFIX$walletId"
        if (keyStore.containsAlias(alias)) {
            val key = keyStore.getKey(alias, null) as? PrivateKey
            if (key != null) return key
        }
        
        // 2. Try SecureStorage (Custodial/Software Fallback)
        val softKeyHex = com.offlinewallet.SecureStorage.getPrivateKey()
        if (softKeyHex != null) {
            return try {
                KeyManager.bytesToPrivateKey(HexUtils.decodeSafe(softKeyHex), "EC")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decode software key", e)
                null
            }
        }
        return null
    }

    fun getPublicKey(walletId: String): PublicKey? {
        // 1. Try Hardware Keystore
        val alias = "$KEY_ALIAS_PREFIX$walletId"
        if (keyStore.containsAlias(alias)) {
            val cert = keyStore.getCertificate(alias)
            if (cert != null) return cert.publicKey
        }
        
        // 2. Try SecureStorage
        val softKeyHex = com.offlinewallet.SecureStorage.getPublicKey()
        if (softKeyHex != null) {
            return try {
                KeyManager.bytesToPublicKey(HexUtils.decodeSafe(softKeyHex), "EC")
            } catch (e: Exception) {
                null
            }
        }
        return null
    }

    fun generateEphemeralKeyPair(): KeyPair? {
        return try {
            val bc = org.bouncycastle.jce.provider.BouncyCastleProvider()
            KeyPairGenerator.getInstance("X25519", bc).generateKeyPair()
        } catch (e: Exception) {
            Log.e(TAG, "X25519 KeyGen Failed: ${e.message}")
            try {
                val bc = org.bouncycastle.jce.provider.BouncyCastleProvider()
                KeyPairGenerator.getInstance("XDH", bc).generateKeyPair()
            } catch (e2: Exception) {
                Log.e(TAG, "XDH KeyGen Failed: ${e2.message}")
                null
            }
        }
    }

    fun computeSharedSecret(pk: PrivateKey, pub: PublicKey): ByteArray? {
        return try {
            val bc = org.bouncycastle.jce.provider.BouncyCastleProvider()
            val ka = try {
                KeyAgreement.getInstance("X25519", bc)
            } catch (e: Exception) {
                KeyAgreement.getInstance("XDH", bc)
            }
            ka.init(pk)
            ka.doPhase(pub, true)
            ka.generateSecret()
        } catch (e: Exception) {
            Log.e(TAG, "Shared secret computation failed: ${e.message}")
            null
        }
    }
}
