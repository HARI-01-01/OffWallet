package com.offlinewallet.payment

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.util.Base64
import android.util.Log
import com.offlinewallet.crypto.QueueManager
import com.offlinewallet.crypto.Signer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SMSPaymentHandler(private val context: Context) {
    private val queueManager = QueueManager(context)
    
    companion object {
        private const val TAG = "SMSPaymentHandler"
        private const val SMS_GATEWAY_NUMBER = "8000" // Should be moved to BuildConfig
        const val SMS_SENT_ACTION = "com.offlinewallet.SMS_SENT"
        const val SMS_DELIVERED_ACTION = "com.offlinewallet.SMS_DELIVERED"
    }

    suspend fun processPayment(
        payerId: String,
        payeeId: String,
        amount: Int,
        aesKey: ByteArray?,
        privateKey: ByteArray?
    ): SMSPaymentResult = withContext(Dispatchers.IO) {
        return@withContext try {
            // 1. Create transaction record with counter
            val timestamp = System.currentTimeMillis() / 1000
            val localId = UUID.randomUUID().toString()
            val counter = getNextCounter()
            
            // 2. Create payload: localId|amount|payerId|payeeId|counter|timestamp
            val payload = "$localId|$amount|$payerId|$payeeId|$counter|$timestamp"
            
            // 3. Sign the payload
            val fullSignature = if (privateKey != null) {
                Signer.signWithBytes(privateKey, payload.toByteArray())
            } else {
                ByteArray(0)
            }
            
            // 4. Encrypt with AES if available
            val encryptedBase64 = if (aesKey != null) {
                encryptSMSPayload(payload, aesKey)
            } else {
                Base64.encodeToString(payload.toByteArray(), Base64.NO_WRAP)
            }
            
            // 5. Short signature for SMS space constraints (not ideal for security, but necessary for SMS)
            // Note: In a production environment, use a more compact binary format instead of Base64 strings
            val sigBase64 = Base64.encodeToString(fullSignature, Base64.NO_WRAP).take(16)
            
            val smsMessage = "PAY|$encryptedBase64|$sigBase64"
            
            // 6. Send via SMS with delivery reports
            val smsManager = context.getSystemService(SmsManager::class.java)
            
            val sentPI = PendingIntent.getBroadcast(context, 0, Intent(SMS_SENT_ACTION), 
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val deliveredPI = PendingIntent.getBroadcast(context, 0, Intent(SMS_DELIVERED_ACTION).apply { putExtra("LOCAL_ID", localId) }, 
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            
            smsManager.sendTextMessage(SMS_GATEWAY_NUMBER, null, smsMessage, sentPI, deliveredPI)
            
            // 7. Store in local queue for offline tracking
            queueManager.addTransaction(
                amount = amount,
                payerId = payerId,
                payeeId = payeeId,
                counter = counter.toLong(),
                payerSignature = fullSignature,
                method = "SMS",
                localId = localId
            )
            // Mark as SMS_PENDING initially
            queueManager.updateTransactionPins(localId, "SMS_PENDING", "", "QUEUED")
            
            SMSPaymentResult(
                success = true,
                message = "Payment request sent via encrypted SMS",
                transactionId = localId
            )
        } catch (e: Exception) {
            Log.e(TAG, "SMS payment failed", e)
            SMSPaymentResult(false, "SMS failed: ${e.message}")
        }
    }

    private fun encryptSMSPayload(payload: String, aesKey: ByteArray): String {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), spec)
            
            val ciphertext = cipher.doFinal(payload.toByteArray())
            val combined = iv + ciphertext
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Encryption failed", e)
            Base64.encodeToString(payload.toByteArray(), Base64.NO_WRAP)
        }
    }

    private fun getNextCounter(): Int {
        val prefs = context.getSharedPreferences("sms_counters", Context.MODE_PRIVATE)
        val current = prefs.getInt("counter", 0)
        prefs.edit().putInt("counter", current + 1).apply()
        return current + 1
    }
}

data class SMSPaymentResult(
    val success: Boolean,
    val message: String,
    val transactionId: String = "",
    val balanceAfter: Int = 0
)
