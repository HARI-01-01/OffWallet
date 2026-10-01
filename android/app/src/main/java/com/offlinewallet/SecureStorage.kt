package com.offlinewallet

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecureStorage {
    private const val PREFS_NAME = "secure_prefs"
    private const val KEY_API_KEY = "api_key"
    private const val KEY_DEVICE_ID = "device_id"
    private const val KEY_DEVICE_PRIVATE_KEY = "device_private_key"
    private const val KEY_WALLET_ID = "wallet_id"
    private const val KEY_SERVER_SIGNATURE = "server_signature"
    private const val KEY_PUBLIC_KEY = "public_key"
    private const val KEY_PRIVATE_KEY = "private_key"
    private const val KEY_AES_KEY = "aes_key"
    private const val KEY_SERVER_PUBLIC_KEY = "server_public_key"
    private const val KEY_SERVER_SSL_PIN = "server_ssl_pin"
    private const val KEY_EXPIRES_AT = "expires_at"
    
    private const val KEY_EMAIL = "user_email"
    private const val KEY_WALLET_NAME = "wallet_name"
    private const val KEY_BALANCE = "current_balance"
    private const val KEY_IS_AUTHENTICATED = "is_authenticated"
    private const val KEY_LAST_SYNC_TIME = "last_sync_time"
    private const val KEY_GENESIS_EPOCH = "genesis_epoch"
    private const val KEY_PASS_ENVELOPE = "security_pass"
    private const val KEY_MNEMONIC = "mnemonic_phrase"
    private const val KEY_RECOVERY_SHARD = "recovery_shard"

    private lateinit var sharedPreferences: SharedPreferences

    fun init(context: Context) {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        sharedPreferences = EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveApiKey(apiKey: String) {
        sharedPreferences.edit().putString(KEY_API_KEY, apiKey).apply()
    }

    fun getApiKey(): String? {
        return sharedPreferences.getString(KEY_API_KEY, null)
    }

    // 1. Store Token Helper
    fun getAuthToken(): String? {
        val storedToken = sharedPreferences.getString(KEY_API_KEY, null)
        if (!storedToken.isNullOrEmpty()) return storedToken
        
        return null
    }

    fun saveDeviceId(deviceId: String) {
        sharedPreferences.edit().putString(KEY_DEVICE_ID, deviceId).apply()
    }

    fun getDeviceId(): String? {
        val id = sharedPreferences.getString(KEY_DEVICE_ID, null)
        if (id != null) return id
        
        // Generate and save a persistent device ID if it doesn't exist
        val newId = "dev_" + java.util.UUID.randomUUID().toString().replace("-", "").take(12)
        saveDeviceId(newId)
        return newId
    }

    fun saveDevicePrivateKey(privateKey: ByteArray) {
        sharedPreferences.edit().putString(KEY_DEVICE_PRIVATE_KEY, android.util.Base64.encodeToString(privateKey, android.util.Base64.DEFAULT)).apply()
    }

    fun getDevicePrivateKey(): ByteArray? {
        val keyString = sharedPreferences.getString(KEY_DEVICE_PRIVATE_KEY, null)
        return keyString?.let { android.util.Base64.decode(it, android.util.Base64.DEFAULT) }
    }

    fun saveWalletId(walletId: String) {
        sharedPreferences.edit().putString(KEY_WALLET_ID, walletId).apply()
    }

    fun getWalletId(): String? {
        return sharedPreferences.getString(KEY_WALLET_ID, null)
    }

    fun saveServerSignature(signature: String) {
        sharedPreferences.edit().putString(KEY_SERVER_SIGNATURE, signature).apply()
    }

    fun getServerSignature(): String? {
        return sharedPreferences.getString(KEY_SERVER_SIGNATURE, null)
    }

    fun savePublicKey(publicKey: String) {
        sharedPreferences.edit().putString(KEY_PUBLIC_KEY, publicKey).apply()
    }

    fun getPublicKey(): String? {
        return sharedPreferences.getString(KEY_PUBLIC_KEY, null)
    }

    fun savePrivateKey(privateKey: String) {
        sharedPreferences.edit().putString(KEY_PRIVATE_KEY, privateKey).apply()
    }

    fun getPrivateKey(): String? {
        return sharedPreferences.getString(KEY_PRIVATE_KEY, null)
    }

    fun saveAesKey(aesKey: String) {
        sharedPreferences.edit().putString(KEY_AES_KEY, aesKey).apply()
    }

    fun getAesKey(): String? {
        return sharedPreferences.getString(KEY_AES_KEY, null)
    }

    fun saveServerPublicKey(key: String) {
        sharedPreferences.edit().putString(KEY_SERVER_PUBLIC_KEY, key).apply()
    }

    fun getServerPublicKey(): String? {
        return sharedPreferences.getString(KEY_SERVER_PUBLIC_KEY, null)
    }

    fun saveServerSslPin(pin: String) {
        sharedPreferences.edit().putString(KEY_SERVER_SSL_PIN, pin).apply()
    }

    fun getServerSslPin(): String? {
        return sharedPreferences.getString(KEY_SERVER_SSL_PIN, null)
    }

    fun saveExpiresAt(expiresAt: Long) {
        sharedPreferences.edit().putLong(KEY_EXPIRES_AT, expiresAt).apply()
    }

    fun getExpiresAt(): Long {
        return sharedPreferences.getLong(KEY_EXPIRES_AT, 0L)
    }

    fun saveEmail(email: String) {
        sharedPreferences.edit().putString(KEY_EMAIL, email).apply()
    }

    fun getEmail(): String? {
        return sharedPreferences.getString(KEY_EMAIL, null)
    }

    fun saveWalletName(name: String) {
        sharedPreferences.edit().putString(KEY_WALLET_NAME, name).apply()
    }

    fun getWalletName(): String? {
        return sharedPreferences.getString(KEY_WALLET_NAME, null)
    }

    fun saveBalance(balance: Long) {
        sharedPreferences.edit().putLong(KEY_BALANCE, balance).apply()
    }

    fun getBalance(): Long {
        return sharedPreferences.getLong(KEY_BALANCE, 0L)
    }

    fun setAuthenticated(isAuthenticated: Boolean) {
        sharedPreferences.edit().putBoolean(KEY_IS_AUTHENTICATED, isAuthenticated).apply()
    }

    fun isAuthenticated(): Boolean {
        return sharedPreferences.getBoolean(KEY_IS_AUTHENTICATED, false)
    }

    fun saveLastSyncTime(time: Long) {
        sharedPreferences.edit().putLong(KEY_LAST_SYNC_TIME, time).apply()
    }

    fun getLastSyncTime(): Long {
        return sharedPreferences.getLong(KEY_LAST_SYNC_TIME, System.currentTimeMillis())
    }

    fun saveGenesisEpoch(epoch: Long) {
        if (epoch > getGenesisEpoch()) {
            sharedPreferences.edit().putLong(KEY_GENESIS_EPOCH, epoch).apply()
        }
    }

    fun getGenesisEpoch(): Long {
        val stored = sharedPreferences.getLong(KEY_GENESIS_EPOCH, 0L)
        val pass = getPass()?.pass?.genesisEpoch ?: 0L
        return maxOf(stored, pass)
    }

    fun savePass(pass: com.offlinewallet.models.PassEnvelope) {
        val json = com.google.gson.Gson().toJson(pass)
        sharedPreferences.edit().putString(KEY_PASS_ENVELOPE, json).apply()
        saveGenesisEpoch(pass.pass.genesisEpoch) // Automatically update epoch
    }

    fun getPass(): com.offlinewallet.models.PassEnvelope? {
        val json = sharedPreferences.getString(KEY_PASS_ENVELOPE, null) ?: return null
        return try {
            com.google.gson.Gson().fromJson(json, com.offlinewallet.models.PassEnvelope::class.java)
        } catch (e: Exception) {
            null
        }
    }

    fun saveMnemonic(mnemonic: String) {
        sharedPreferences.edit().putString(KEY_MNEMONIC, mnemonic).apply()
    }

    fun getMnemonic(): String? {
        return sharedPreferences.getString(KEY_MNEMONIC, null)
    }

    fun saveRecoveryShard(shard: String) {
        sharedPreferences.edit().putString(KEY_RECOVERY_SHARD, shard).apply()
    }

    fun getRecoveryShard(): String? {
        return sharedPreferences.getString(KEY_RECOVERY_SHARD, null)
    }

    fun clear() {
        sharedPreferences.edit().clear().apply()
    }

    fun isRegistered(): Boolean {
        return isAuthenticated() && getWalletId() != null
    }

    fun isBucketValid(): Boolean {
        val signature = getServerSignature()
        val expiresAt = getExpiresAt()
        return signature != null && expiresAt > (System.currentTimeMillis() / 1000)
    }

    fun getCredentialSummary(): String {
        return "Wallet: ${getWalletId() ?: "None"}, Device: ${getDeviceId() ?: "None"}"
    }
}
