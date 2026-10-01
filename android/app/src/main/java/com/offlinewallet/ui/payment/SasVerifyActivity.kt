package com.offlinewallet.ui.payment

import android.app.Activity
import android.os.Bundle
import android.speech.tts.TextToSpeech
import android.os.Vibrator
import android.os.VibrationEffect
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.offlinewallet.R
import java.util.Locale

/**
 * SAS Verification Screen (WP-32)
 * Mandatory manual comparison of 6-digit session transcript hash.
 */
class SasVerifyActivity : AppCompatActivity(), TextToSpeech.OnInitListener {

    private var tts: TextToSpeech? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sas_verify)

        val sasDigits = intent.getStringExtra("SAS_DIGITS") ?: "000000"
        
        // Format as 000 000 for easier reading
        val formatted = sasDigits.take(3) + " " + sasDigits.drop(3)
        findViewById<TextView>(R.id.tvSasDigits).text = formatted

        // WP-32: SAS Accessibility (Audio Readout)
        tts = TextToSpeech(this, this)

        // WP-32: SAS Accessibility (Haptic Patterns)
        provideHapticFeedback(sasDigits)

        findViewById<Button>(R.id.btnConfirmSas).setOnClickListener {
            setResult(Activity.RESULT_OK)
            finish()
        }

        findViewById<Button>(R.id.btnAbortSas).setOnClickListener {
            setResult(Activity.RESULT_CANCELED)
            finish()
        }
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            tts?.language = Locale.US
            val sasDigits = intent.getStringExtra("SAS_DIGITS") ?: ""
            if (sasDigits.isNotEmpty()) {
                val readout = sasDigits.map { it.toString() }.joinToString(", ")
                tts?.speak("Security code is $readout", TextToSpeech.QUEUE_FLUSH, null, "SAS_READOUT")
            }
        }
    }

    private fun provideHapticFeedback(sas: String) {
        val vibrator = getSystemService(Vibrator::class.java)
        if (vibrator != null && vibrator.hasVibrator()) {
            val pattern = LongArray(sas.length * 2) { i ->
                if (i % 2 == 0) 100 else 200 // 100ms pause, 200ms buzz
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createWaveform(pattern, -1))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(pattern, -1)
            }
        }
    }

    override fun onDestroy() {
        tts?.stop()
        tts?.shutdown()
        super.onDestroy()
    }
}
