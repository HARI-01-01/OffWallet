package com.offlinewallet.crypto

import android.content.Context
import java.security.KeyPair

data class CreateWalletResult(
    val success: Boolean,
    val privateKey: ByteArray? = null,
    val publicKey: ByteArray? = null,
    val aesKey: ByteArray? = null,
    val error: String? = null
)

/**
 * Main orchestrator for offline wallet with Keystore integration
 */
class WalletCore(private val context: Context) {
    private val bucketManager = BucketManager(context)
    private val queueManager = QueueManager(context)

    /**
     * Create wallet with keys stored in Android Keystore
     */
    suspend fun createWalletWithKeystore(
        walletId: String,
        initialBalance: Long,
        counter: Int,
        serverPublicKey: ByteArray,
        serverSignature: ByteArray,
        useBiometrics: Boolean = false
    ): CreateWalletResult {
        return try {
            // 1. Initialize SecureKeyStore
            SecureKeyStore.init()

            // 2. Generate and store key pair in Keystore
            val keyPair = SecureKeyStore.generateAndStoreKeyPair(
                context = context,
                walletId = walletId,
                useBiometrics = useBiometrics
            )

            if (keyPair == null) {
                return CreateWalletResult(
                    success = false,
                    error = "Failed to generate secure keys"
                )
            }

            // 3. Get key bytes
            // Note: For Keystore keys, encoded is null. We don't export private key.
            val privateKeyBytes = KeyManager.privateKeyToBytes(keyPair.private)
            val publicKeyBytes = KeyManager.publicKeyToBytes(keyPair.public)

            // 4. Generate AES key for encryption
            val aesKeyObj = Encryptor.generateKey()
            val aesKey = aesKeyObj.encoded
            com.offlinewallet.SecureStorage.saveAesKey(HexUtils.encodeHex(aesKey))

            // 5. Create bucket
            val success = bucketManager.createBucket(
                walletId = walletId,
                initialBalance = initialBalance,
                counter = counter.toLong(),
                aesKey = aesKey,
                serverPublicKey = serverPublicKey,
                serverSignature = serverSignature
            )

            if (!success) {
                return CreateWalletResult(
                    success = false,
                    error = "Failed to create bucket"
                )
            }

            CreateWalletResult(
                success = true,
                privateKey = privateKeyBytes,
                publicKey = publicKeyBytes,
                aesKey = aesKey
            )
        } catch (e: Exception) {
            CreateWalletResult(
                success = false,
                error = e.message ?: "Unknown error"
            )
        }
    }

    /**
     * Get secure private key from Keystore
     */
    suspend fun getSecurePrivateKey(walletId: String): ByteArray? {
        val privateKey = SecureKeyStore.getPrivateKey(walletId) ?: return null
        return KeyManager.privateKeyToBytes(privateKey)
    }

    /**
     * Get secure public key from Keystore
     */
    suspend fun getSecurePublicKey(walletId: String): ByteArray? {
        val publicKey = SecureKeyStore.getPublicKey(walletId) ?: return null
        return KeyManager.publicKeyToBytes(publicKey)
    }

    /**
     * Delete wallet and secure keys
     */
    suspend fun deleteWallet(walletId: String): Boolean {
        return try {
            // Delete from Keystore
            SecureKeyStore.deleteKey(walletId)
            // Delete from database logic could be added here
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if wallet has secure keys
     */
    suspend fun hasSecureKeys(walletId: String): Boolean {
        return SecureKeyStore.keyExists(walletId)
    }
}
