package com.offlinewallet.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Shadow v1 Canonical Encoding
 * Length-prefixed, fixed-order concatenation.
 */
object Canon {
    
    sealed class Field {
        data class U8(val v: Int) : Field()
        data class U64(val v: Long) : Field()
        data class Bytes(val v: ByteArray) : Field()
        data class Str(val v: String) : Field()
    }

    fun enc(vararg fields: Field): ByteArray {
        val bos = java.io.ByteArrayOutputStream()
        for (field in fields) {
            when (field) {
                is Field.U8 -> {
                    bos.write(field.v and 0xFF)
                }
                is Field.U64 -> {
                    val buf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                    buf.putLong(field.v)
                    bos.write(buf.array())
                }
                is Field.Bytes -> {
                    require(field.v.size <= 65535) { "Bytes field too large: ${field.v.size}" }
                    val lenBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
                    lenBuf.putShort(field.v.size.toShort())
                    bos.write(lenBuf.array())
                    bos.write(field.v)
                }
                is Field.Str -> {
                    val bytes = field.v.toByteArray(Charsets.UTF_8)
                    require(bytes.size <= 65535) { "String field too large: ${bytes.size}" }
                    require(!field.v.contains("\u0000")) { "String contains null byte" }
                    val lenBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
                    lenBuf.putShort(bytes.size.toShort())
                    bos.write(lenBuf.array())
                    bos.write(bytes)
                }
            }
        }
        return bos.toByteArray()
    }

    class Decoder(val data: ByteArray) {
        private val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

        fun u8(): Int {
            if (!buf.hasRemaining()) throw IllegalStateException("EOS")
            return buf.get().toInt() and 0xFF
        }

        fun u64(): Long {
            if (buf.remaining() < 8) throw IllegalStateException("EOS")
            return buf.long
        }

        fun bytes(): ByteArray {
            if (buf.remaining() < 2) throw IllegalStateException("EOS")
            val len = buf.short.toInt() and 0xFFFF
            if (buf.remaining() < len) throw IllegalStateException("Buffer underflow: expected $len, remaining ${buf.remaining()}")
            val res = ByteArray(len)
            buf.get(res)
            return res
        }

        fun str(): String = String(bytes(), Charsets.UTF_8)
        fun hasRemaining(): Boolean = buf.hasRemaining()

        fun assertVersion(expected: Int) {
            val v = u8()
            if (v != expected) throw IllegalStateException("Version mismatch: expected $expected, got $v")
        }

        fun assertDone() {
            if (buf.hasRemaining()) throw IllegalStateException("Trailing bytes: ${buf.remaining()}")
        }
    }
}
