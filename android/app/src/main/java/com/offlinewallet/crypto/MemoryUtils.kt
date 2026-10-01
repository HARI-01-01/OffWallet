package com.offlinewallet.crypto

import java.util.Arrays

object MemoryUtils {
    /**
     * Overwrites the content of a byte array with zeros to erase sensitive data from RAM.
     */
    fun erase(data: ByteArray?) {
        if (data != null) {
            Arrays.fill(data, 0.toByte())
        }
    }
}
