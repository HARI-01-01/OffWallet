package com.offlinewallet.ui.utils

import android.graphics.Bitmap
import android.graphics.Color
import com.google.gson.Gson
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import com.offlinewallet.models.QRCodeData
import com.offlinewallet.models.V1QR
import com.offlinewallet.crypto.ShadowProtocol
import java.util.zip.Deflater
import java.util.zip.Inflater

object QRCodeHelper {
    private val gson = Gson()

    fun generatePaymentQR(data: QRCodeData, size: Int = 512): Bitmap? {
        return try {
            val jsonString = gson.toJson(data)
            val bitMatrix: BitMatrix = MultiFormatWriter().encode(
                jsonString,
                BarcodeFormat.QR_CODE,
                size,
                size
            )
            val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
            for (x in 0 until size) {
                for (y in 0 until size) {
                    bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
                }
            }
            bitmap
        } catch (e: Exception) {
            null
        }
    }

    fun parseQRData(jsonString: String): QRCodeData? {
        return try {
            gson.fromJson(jsonString, QRCodeData::class.java)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Shadow v1: base45(deflate(canon(V1QR)))
     */
    fun generateV1QR(data: V1QR, size: Int = 512): Bitmap? {
        return try {
            val canonBytes = com.offlinewallet.crypto.MicroPaymentHandshake.encodeV1QR(data)
            android.util.Log.d("QRCodeHelper", "Canon bytes size: ${canonBytes.size}")
            
            // Deflate using ByteArrayOutputStream for dynamic sizing
            val bos = java.io.ByteArrayOutputStream()
            val deflater = java.util.zip.Deflater(java.util.zip.Deflater.BEST_COMPRESSION)
            deflater.setInput(canonBytes)
            deflater.finish()
            val buf = ByteArray(1024)
            while (!deflater.finished()) {
                val count = deflater.deflate(buf)
                bos.write(buf, 0, count)
            }
            val compressedBytes = bos.toByteArray()
            android.util.Log.d("QRCodeHelper", "Compressed size: ${compressedBytes.size}")
            
            // Base45 (Simulated as Base64 for density for now)
            val qrString = ShadowProtocol.base45Encode(compressedBytes)
            android.util.Log.d("QRCodeHelper", "QR String length: ${qrString.length}")
            
            val bitMatrix: com.google.zxing.common.BitMatrix = com.google.zxing.MultiFormatWriter().encode(
                qrString,
                com.google.zxing.BarcodeFormat.QR_CODE,
                size,
                size
            )
            val bitmap = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.RGB_565)
            for (x in 0 until size) {
                for (y in 0 until size) {
                    bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                }
            }
            bitmap
        } catch (e: Exception) {
            android.util.Log.e("QRCodeHelper", "QR Generation Error", e)
            null
        }
    }

    fun parseV1QR(qrString: String): V1QR? {
        return try {
            val compressedBytes = ShadowProtocol.base45Decode(qrString)
            
            // Inflate correctly using a loop
            val inflater = java.util.zip.Inflater()
            inflater.setInput(compressedBytes)
            val bos = java.io.ByteArrayOutputStream()
            val buf = ByteArray(1024)
            while (!inflater.finished()) {
                val count = inflater.inflate(buf)
                if (count == 0) break
                bos.write(buf, 0, count)
            }
            val canonBytes = bos.toByteArray()
            
            com.offlinewallet.crypto.MicroPaymentHandshake.decodeV1QR(canonBytes)
        } catch (e: Exception) {
            android.util.Log.e("QRCodeHelper", "QR Parse Error: ${e.message}", e)
            null
        }
    }
}
