package com.offlinewallet

import android.app.Application
import com.google.firebase.FirebaseApp
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.FirebaseFirestoreSettings
import android.util.Log
import com.offlinewallet.crypto.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        // Initialize BouncyCastle for Advanced Crypto (X25519)
        // We add it as a new provider instead of replacing the restricted system "BC"
        // to avoid breaking system SSL/TLS components.
        Security.addProvider(BouncyCastleProvider())

        // Initialize Firebase
        FirebaseApp.initializeApp(this)

        // Configure Firestore for offline persistence
        try {
            val settings = FirebaseFirestoreSettings.Builder()
                .setPersistenceEnabled(true)
                .setCacheSizeBytes(FirebaseFirestoreSettings.CACHE_SIZE_UNLIMITED)
                .build()
            FirebaseFirestore.getInstance().firestoreSettings = settings
        } catch (e: Exception) {
            // Log or handle error
        }
        
        // Initialize Core Security Components
        try { SecureStorage.init(applicationContext) } catch (e: Exception) { Log.e("App", "SecureStorage Init Fail", e) }
        try { SecureKeyStore.init() } catch (e: Exception) { Log.e("App", "SecureKeyStore Init Fail", e) }
        try { IntegrityGuardian.init(applicationContext) } catch (e: Exception) { Log.e("App", "IntegrityGuardian Init Fail", e) }
        try { NonceVault.init(applicationContext) } catch (e: Exception) { Log.e("App", "NonceVault Init Fail", e) }
        try { HighWaterStore.init(applicationContext) } catch (e: Exception) { Log.e("App", "HighWaterStore Init Fail", e) }

        // WP-Purge: Invalid blocks are now handled by file-level wipe during Hard Reset.
    }
}
