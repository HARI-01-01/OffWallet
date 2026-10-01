package com.offlinewallet.auth

import android.app.Activity
import android.util.Log
import com.google.firebase.FirebaseException
import com.google.firebase.auth.*
import java.util.concurrent.TimeUnit

class PhoneAuthHelper(private val activity: Activity) {
    private val auth: FirebaseAuth = FirebaseAuth.getInstance()
    private var verificationId: String? = null
    private var resendToken: PhoneAuthProvider.ForceResendingToken? = null

    interface PhoneAuthCallback {
        fun onCodeSent(verificationId: String, token: PhoneAuthProvider.ForceResendingToken)
        fun onVerificationCompleted(credential: PhoneAuthCredential)
        fun onVerificationFailed(e: FirebaseException)
        fun onSignInSuccess(user: FirebaseUser?, idToken: String?)
        fun onSignInFailure(e: Exception)
    }

    private var callback: PhoneAuthCallback? = null

    fun sendVerificationCode(phoneNumber: String, callback: PhoneAuthCallback) {
        this.callback = callback
        val options = PhoneAuthOptions.newBuilder(auth)
            .setPhoneNumber(phoneNumber)
            .setTimeout(60L, TimeUnit.SECONDS)
            .setActivity(activity)
            .setCallbacks(object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                override fun onVerificationCompleted(credential: PhoneAuthCredential) {
                    Log.d("PhoneAuthHelper", "onVerificationCompleted: $credential")
                    callback.onVerificationCompleted(credential)
                    // Auto-signIn if possible
                    signInWithCredential(credential)
                }

                override fun onVerificationFailed(e: FirebaseException) {
                    Log.w("PhoneAuthHelper", "onVerificationFailed", e)
                    callback.onVerificationFailed(e)
                }

                override fun onCodeSent(id: String, token: PhoneAuthProvider.ForceResendingToken) {
                    Log.d("PhoneAuthHelper", "onCodeSent: $id")
                    verificationId = id
                    resendToken = token
                    callback.onCodeSent(id, token)
                }
            })
            .build()
        PhoneAuthProvider.verifyPhoneNumber(options)
    }

    fun verifyCode(code: String) {
        val id = verificationId ?: return
        val credential = PhoneAuthProvider.getCredential(id, code)
        signInWithCredential(credential)
    }

    private fun signInWithCredential(credential: PhoneAuthCredential) {
        auth.signInWithCredential(credential)
            .addOnCompleteListener(activity) { task ->
                if (task.isSuccessful) {
                    Log.d("PhoneAuthHelper", "signInWithCredential:success")
                    val user = task.result?.user
                    user?.getIdToken(true)?.addOnCompleteListener { tokenTask ->
                        if (tokenTask.isSuccessful) {
                            val token = tokenTask.result?.token
                            callback?.onSignInSuccess(user, token)
                        } else {
                            callback?.onSignInSuccess(user, null)
                        }
                    }
                } else {
                    Log.w("PhoneAuthHelper", "signInWithCredential:failure", task.exception)
                    callback?.onSignInFailure(task.exception ?: Exception("Sign-in failed"))
                }
            }
    }
}
