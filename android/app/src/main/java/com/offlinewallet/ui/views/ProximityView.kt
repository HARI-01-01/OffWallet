package com.offlinewallet.ui.views

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.core.content.ContextCompat
import com.offlinewallet.R

class ProximityView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null, defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    enum class State {
        IDLE, GOOD, WEAK, PERFECT, NFC_CONNECTING, TRANSFERRING, DIAGNOSTIC
    }

    private var state = State.IDLE
    private var rippleRadius = 0f
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 5f
    }
    
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        repeatCount = ValueAnimator.INFINITE
        interpolator = AccelerateDecelerateInterpolator()
        addUpdateListener {
            rippleRadius = it.animatedValue as Float
            invalidate()
        }
    }

    fun setState(newState: State) {
        if (state == newState) return
        state = newState
        
        animator.duration = if (state == State.TRANSFERRING) 600 else 1500

        val colorRes = when (state) {
            State.IDLE -> R.color.gray_300
            State.GOOD -> R.color.success
            State.WEAK -> R.color.warning
            State.PERFECT -> R.color.accent
            State.NFC_CONNECTING -> R.color.info
            State.TRANSFERRING -> R.color.primary
            State.DIAGNOSTIC -> R.color.primary
        }
        paint.color = ContextCompat.getColor(context, colorRes)
        
        if (state != State.IDLE && !animator.isRunning) {
            animator.start()
        } else if (state == State.IDLE) {
            animator.cancel()
        }
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val centerX = width / 2f
        val centerY = height / 2f
        val maxRadius = minOf(width, height) / 2f

        // Draw center circle
        paint.style = Paint.Style.FILL
        canvas.drawCircle(centerX, centerY, 20f, paint)

        // Draw ripples
        if (state != State.IDLE) {
            paint.style = Paint.Style.STROKE
            paint.alpha = (255 * (1 - rippleRadius)).toInt()
            canvas.drawCircle(centerX, centerY, maxRadius * rippleRadius, paint)
            
            // Second ripple
            val secondRipple = (rippleRadius + 0.5f) % 1f
            paint.alpha = (255 * (1 - secondRipple)).toInt()
            canvas.drawCircle(centerX, centerY, maxRadius * secondRipple, paint)
        }
    }
}
