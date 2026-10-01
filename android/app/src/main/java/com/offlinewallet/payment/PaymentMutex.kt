package com.offlinewallet.payment

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Payment Mutex (WP-15)
 * Prevents the device from forking its own chain by ensuring only one 
 * payment session is active at a time.
 */
object PaymentMutex {
    private val isLocked = AtomicBoolean(false)

    /**
     * Attempts to acquire the payment lock.
     * Returns true if successful, false if another session is already active.
     */
    fun acquire(): Boolean {
        return isLocked.compareAndSet(false, true)
    }

    /**
     * Releases the payment lock.
     */
    fun release() {
        isLocked.set(false)
    }
}
