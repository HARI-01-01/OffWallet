package com.offlinewallet.crypto

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.Signature
import java.util.concurrent.Executor
import kotlin.coroutines.resume

class BiometricHelper(private val context: Context) {
    private val executor: Executor = ContextCompat.getMainExecutor(context)

    sealed class SignatureResult {
        data class Success(val signature: ByteArray, val authType: Int) : SignatureResult()
        data class Failure(val reason: String) : SignatureResult()
        object Cancelled : SignatureResult()
    }

    fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(context)
        return when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> true
            else -> false
        }
    }

    suspend fun authenticateForTransaction(
        amount: Long,
        payeeId: String,
        privateKey: java.security.PrivateKey,
        dataToSign: ByteArray
    ): SignatureResult = suspendCancellableCoroutine { continuation ->
        try {
            // 1. Create a Signature object bound to the private key
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)

            // 2. Create CryptoObject
            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            // 3. Display transaction details (WYSIWYS)
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authorize Payment")
                .setSubtitle("₹${String.format("%.2f", amount / 100.0)} to $payeeId")
                .setDescription("Sign transaction hash: ${HexUtils.encodeHex(dataToSign).take(16)}...")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .setConfirmationRequired(false)
                .build()

            val biometricPrompt = BiometricPrompt(
                context as FragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val sig = result.cryptoObject?.signature
                            sig?.update(dataToSign)
                            val signedData = sig?.sign()
                            if (signedData != null) {
                                continuation.resume(SignatureResult.Success(Signer.normalize(signedData), result.authenticationType))
                            } else {
                                continuation.resume(SignatureResult.Failure("Signing failed"))
                            }
                        } catch (e: Exception) {
                            continuation.resume(SignatureResult.Failure(e.message ?: "Unknown error"))
                        }
                    }

                    override fun onAuthenticationFailed() {
                        // Keep open for retries until error or cancel
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        when (errorCode) {
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_USER_CANCELED -> {
                                continuation.resume(SignatureResult.Cancelled)
                            }
                            else -> {
                                continuation.resume(SignatureResult.Failure(errString.toString()))
                            }
                        }
                    }
                }
            )

            biometricPrompt.authenticate(promptInfo, cryptoObject)
        } catch (e: Exception) {
            continuation.resume(SignatureResult.Failure(e.message ?: "Initialization error"))
        }
    }

    fun authenticate(
        activity: FragmentActivity,
        title: String = "Authenticate Payment",
        subtitle: String = "Confirm your identity",
        description: String = "Use fingerprint or device lock",
        onSuccess: () -> Unit,
        onFailure: (String) -> Unit
    ) {
        if (!isBiometricAvailable()) {
            onFailure("Biometrics not available")
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationFailed() {
                    onFailure("Authentication failed")
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailure(errString.toString())
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }
}
