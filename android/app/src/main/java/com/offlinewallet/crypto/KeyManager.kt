package com.offlinewallet.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object KeyManager {
    private const val ALGORITHM = "Ed25519"
    const val PRIVATE_KEY_SIZE = 32
    const val PUBLIC_KEY_SIZE = 32

    fun generateKeyPair(): KeyPair {
        val bc = BouncyCastleProvider()
        val kpg = KeyPairGenerator.getInstance(ALGORITHM, bc)
        return kpg.generateKeyPair()
    }

    fun generateEphemeralKeyPair(): KeyPair {
        return try {
            KeyPairGenerator.getInstance("X25519", BouncyCastleProvider()).generateKeyPair()
        } catch (e: Exception) {
            KeyPairGenerator.getInstance("XDH", BouncyCastleProvider()).generateKeyPair()
        }
    }

    fun privateKeyToBytes(privateKey: PrivateKey): ByteArray? {
        val encoded = privateKey.encoded ?: return null
        return try {
            val params = PrivateKeyFactory.createKey(encoded)
            if (params is Ed25519PrivateKeyParameters) params.encoded
            else if (params is X25519PrivateKeyParameters) params.encoded
            else encoded
        } catch (e: Exception) {
            encoded
        }
    }

    fun publicKeyToBytes(publicKey: PublicKey): ByteArray {
        val encoded = publicKey.encoded ?: throw IllegalArgumentException("Public key encoding failed")
        return try {
            val params = PublicKeyFactory.createKey(encoded)
            if (params is Ed25519PublicKeyParameters) params.encoded
            else if (params is X25519PublicKeyParameters) params.encoded
            else encoded
        } catch (e: Exception) {
            encoded
        }
    }

    fun encryptAesKeyWithServerEphemeral(aesKey: ByteArray, serverEphemeralPub: ByteArray): ByteArray {
        // 1. Generate client ephemeral key pair
        val clientEph = generateEphemeralKeyPair()
        val clientPub = publicKeyToBytes(clientEph.public)
        
        // 2. Compute shared secret (ECDH)
        val serverPub = bytesToPublicKey(serverEphemeralPub, "X25519")
        val ka = try {
            KeyAgreement.getInstance("X25519", BouncyCastleProvider())
        } catch (e: Exception) {
            KeyAgreement.getInstance("XDH", BouncyCastleProvider())
        }
        ka.init(clientEph.private)
        ka.doPhase(serverPub, true)
        val sharedSecret = ka.generateSecret()
        
        // 3. Derive wrap key (HKDF)
        val derivedKey = ShadowProtocol.hkdf(sharedSecret, ByteArray(0), "shadow/v1/aes-key-wrap", 32)
        
        // 4. Encrypt AES key (AES-GCM)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(aesKey)
        val tag = ciphertext.takeLast(16).toByteArray() // AESGCM in Java appends tag to ciphertext
        val encryptedData = ciphertext.dropLast(16).toByteArray()

        // Return: clientPub (32) + iv (12) + encryptedData + tag (16)
        return clientPub + iv + encryptedData + tag
    }

    fun bytesToPrivateKey(data: ByteArray): PrivateKey {
        return bytesToPrivateKey(data, ALGORITHM)
    }

    fun bytesToPrivateKey(data: ByteArray, algorithm: String): PrivateKey {
        // Simple case: data is already PKCS#8
        if (data.size > 32) return KeyFactory.getInstance(algorithm, BouncyCastleProvider()).generatePrivate(PKCS8EncodedKeySpec(data))
        
        // Manual header construction for raw bytes (Ed25519/X25519)
        val header = when (algorithm) {
            "Ed25519" -> byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20)
            "X25519", "XDH" -> byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20)
            else -> throw IllegalArgumentException("Raw bytes conversion not supported for algorithm: $algorithm")
        }
        val factory = try {
            KeyFactory.getInstance(algorithm, BouncyCastleProvider())
        } catch (e: Exception) {
            if (algorithm == "X25519") KeyFactory.getInstance("XDH", BouncyCastleProvider())
            else throw e
        }
        val keySpec = PKCS8EncodedKeySpec(header + data)
        return factory.generatePrivate(keySpec)
    }

    fun bytesToPublicKey(data: ByteArray): PublicKey {
        return bytesToPublicKey(data, ALGORITHM)
    }

    fun bytesToPublicKey(data: ByteArray, algorithm: String): PublicKey {
        if (data.size > 32) {
            // Already encoded (SPKI) - Try multiple algorithms to avoid OID mismatch crashes
            val algorithms = mutableListOf<String>()
            // Always try generic algorithms first for SPKI
            algorithms.addAll(listOf("EC", "ECDSA", "Ed25519", "EdDSA", "RSA"))
            
            // Add the requested algorithm if not already present
            if (!algorithms.contains(algorithm)) {
                algorithms.add(0, algorithm)
            }
            
            for (alg in algorithms) {
                try {
                    // Try BouncyCastle first
                    return KeyFactory.getInstance(alg, BouncyCastleProvider()).generatePublic(X509EncodedKeySpec(data))
                } catch (_: Throwable) {
                    try {
                        // Fallback to default provider (e.g. Conscrypt)
                        return KeyFactory.getInstance(alg).generatePublic(X509EncodedKeySpec(data))
                    } catch (_: Throwable) {}
                }
            }
            throw InvalidKeySpecException("Could not parse SPKI public key with any supported algorithm (size: ${data.size})")
        }
        
        // Manual header construction for raw bytes (Ed25519/X25519)
        val header = when (algorithm) {
            "Ed25519" -> byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            "X25519", "XDH" -> byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00)
            else -> throw IllegalArgumentException("Raw bytes conversion not supported for algorithm: $algorithm")
        }
        val factory = try {
            KeyFactory.getInstance(algorithm, BouncyCastleProvider())
        } catch (e: Exception) {
            if (algorithm == "X25519") KeyFactory.getInstance("XDH", BouncyCastleProvider())
            else throw e
        }
        val keySpec = X509EncodedKeySpec(header + data)
        return factory.generatePublic(keySpec)
    }
}
