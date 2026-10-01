package com.offlinewallet.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.offlinewallet.BuildConfig
import com.offlinewallet.NetworkManager
import com.offlinewallet.SecureStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * IntegrityGuardian - Ensures the app has not been tampered with
 * by verifying the APK hash and Signing Certificate against hardware-backed references.
 */
object IntegrityGuardian {
    private const val TAG = "IntegrityGuardian"
    private const val KEY_APK_HASH = "sealed_apk_hash"
    private const val KEY_CERT_HASH = "sealed_cert_hash"
    
    private var isVerified = false
    private var cachedApkHash: String? = null
    
    private val scope = CoroutineScope(Dispatchers.IO + Job())

    /**
     * Initialize integrity check on app startup
     */
    fun init(context: Context) {
        val currentApkHash = calculateApkHash(context) ?: return
        val currentCertHash = getSigningCertificateHash(context) ?: return
        cachedApkHash = currentApkHash

        val storedApkHash = getSealedHash(context, KEY_APK_HASH)
        val storedCertHash = getSealedHash(context, KEY_CERT_HASH)

        if (storedApkHash == null || storedCertHash == null) {
            Log.d(TAG, "First run or update detected. Establishing new integrity baseline.")
            sealAndStore(context, KEY_APK_HASH, currentApkHash)
            sealAndStore(context, KEY_CERT_HASH, currentCertHash)
            isVerified = true
            return
        }

        // Verify BOTH Factors
        if (storedApkHash == currentApkHash && storedCertHash == currentCertHash) {
            isVerified = true
            Log.d(TAG, "Hardware-bound binary integrity verified ✓")
            return
        }

        // If certificate changed => DEFINITELY tampered
        if (storedCertHash != currentCertHash) {
            Log.e(TAG, "🚨 CRITICAL: SIGNING CERTIFICATE MISMATCH!")
            freezeWallet(context, "CERTIFICATE_MISMATCH")
            return
        }

        val installer = try {
            context.packageManager.getInstallerPackageName(context.packageName)
        } catch (e: Exception) {
            null
        }

        val isFromTrustedSource = BuildConfig.DEBUG || 
                                installer == "com.android.vending" || 
                                installer == "com.google.android.feedback" ||
                                installer == "com.android.shell" || 
                                installer == "com.google.android.packageinstaller" ||
                                installer.isNullOrEmpty()
        
        if (isFromTrustedSource) {
            if (isDeviceRooted()) {
                Log.e(TAG, "🚨 CRITICAL: ROOT DETECTED!")
                freezeWallet(context, "DEVICE_ROOTED")
                return
            }
            Log.i(TAG, "Trusted source detected ($installer). Re-sealing baseline.")
            sealAndStore(context, KEY_APK_HASH, currentApkHash)
            isVerified = true
        } else {
            Log.e(TAG, "🚨 APK mismatch detected! Source: $installer")
            freezeWallet(context, "SIDELOADED_APK_TAMPER")
        }
    }

    private fun freezeWallet(context: Context, reason: String) {
        isVerified = false
        val walletId = SecureStorage.getWalletId() ?: "unknown"
        NonceVault.invalidateCurrentNonce(context)
        scope.launch {
            val bucketManager = BucketManager(context)
            bucketManager.freezeBucket(walletId, reason)
            val networkManager = NetworkManager(context, com.offlinewallet.Config.BASE_URL)
            networkManager.reportTamperEvent(walletId, reason, cachedApkHash ?: "unknown", SecureStorage.getDeviceId() ?: "unknown")
        }
        Log.e(TAG, "Wallet FROZEN due to: $reason")
    }

    private fun sealAndStore(context: Context, key: String, value: String) {
        val data = "$value|${BuildConfig.VERSION_CODE}".toByteArray()
        val sealed = SecureKeyStore.sealData(data)
        if (sealed != null) {
            val prefs = context.getSharedPreferences("integrity_prefs", Context.MODE_PRIVATE)
            prefs.edit().putString(key, HexUtils.encodeHex(sealed)).apply()
        }
    }

    private fun getSealedHash(context: Context, key: String): String? {
        val prefs = context.getSharedPreferences("integrity_prefs", Context.MODE_PRIVATE)
        val hex = prefs.getString(key, null) ?: return null
        val unsealed = SecureKeyStore.unsealData(HexUtils.decodeHex(hex)) ?: return null
        val parts = String(unsealed).split("|")
        val hash = parts[0]
        val version = parts.getOrNull(1)?.toIntOrNull()
        if (version != null && version != BuildConfig.VERSION_CODE) return null
        return hash
    }

    fun checkIntegrity(): Boolean = isVerified

    private fun getSigningCertificateHash(context: Context): String? {
        return try {
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            }
            val signatures = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                packageInfo.signatures
            }
            val signature = signatures?.get(0)?.toByteArray() ?: return null
            val digest = MessageDigest.getInstance("SHA-256")
            HexUtils.encodeHex(digest.digest(signature))
        } catch (e: Exception) { null }
    }

    private fun calculateApkHash(context: Context): String? {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val apkPath = packageInfo.applicationInfo?.sourceDir ?: return null
            val file = File(apkPath)
            val digest = MessageDigest.getInstance("SHA-256")
            val fis = FileInputStream(file)
            val buffer = ByteArray(8192)
            var n: Int
            while (fis.read(buffer).also { n = it } != -1) {
                digest.update(buffer, 0, n)
            }
            fis.close()
            HexUtils.encodeHex(digest.digest())
        } catch (e: Exception) { null }
    }

    fun isDeviceRooted(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"
        )
        for (path in paths) {
            if (File(path).exists()) return true
        }
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val inReader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
            inReader.readLine() != null
        } catch (t: Throwable) { false } finally { process?.destroy() }
    }
}
