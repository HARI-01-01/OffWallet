package com.offlinewallet.crypto

/**
 * Shadow Protocol v1 - Encrypted Session Channel
 * Implements frame sealing/opening with per-direction keys and sequence numbers.
 */
class SessionChannel(
    private val sid: String,
    private val kOwnToPeer: ByteArray,
    private val kPeerToOwn: ByteArray
) {
    private var sendSeq = 0L
    private var recvSeq = 0L
    private var lastSealedMessage: ByteArray? = null
    private var lastSealedType: Byte? = null

    /**
     * Seals a payload into an encrypted frame.
     * aad = sid || msgType (1 byte)
     */
    fun seal(msgType: Byte, payload: ByteArray): ByteArray {
        val aad = sid.toByteArray(Charsets.UTF_8) + byteArrayOf(msgType)
        val ciphertext = ShadowProtocol.encrypt(kOwnToPeer, sendSeq, aad, payload)
        lastSealedMessage = ciphertext
        lastSealedType = msgType
        sendSeq++
        return ciphertext
    }

    /**
     * Re-send the EXACT same ciphertext without incrementing sendSeq
     */
    fun retryLastMessage(): Pair<Byte, ByteArray>? {
        val type = lastSealedType ?: return null
        val msg = lastSealedMessage ?: return null
        return Pair(type, msg)
    }

    /**
     * Opens an encrypted frame.
     */
    fun open(msgType: Byte, ciphertext: ByteArray): ByteArray {
        val aad = sid.toByteArray(Charsets.UTF_8) + byteArrayOf(msgType)
        try {
            val plaintext = ShadowProtocol.decrypt(kPeerToOwn, recvSeq, aad, ciphertext)
            recvSeq++
            return plaintext
        } catch (e: Exception) {
            // Sequence mismatch or integrity failure. 
            // In a more complex implementation, we'd check if this is a duplicate of the last processed.
            throw e
        }
    }

    /**
     * Securely erases session keys from memory.
     */
    fun erase() {
        MemoryUtils.erase(kOwnToPeer)
        MemoryUtils.erase(kPeerToOwn)
        MemoryUtils.erase(lastSealedMessage)
        lastSealedMessage = null
        lastSealedType = null
    }

    companion object {
        fun derive(ss: ByteArray, transcriptHash: ByteArray, sid: String, isPayer: Boolean): SessionChannel {
            val prk = ShadowProtocol.hkdf(ss, transcriptHash, "shadow/v1/session-prk", 32)
            val k_a2b = ShadowProtocol.hkdf(prk, ByteArray(0), ShadowProtocol.TAG_KEY_A2B, 32)
            val k_b2a = ShadowProtocol.hkdf(prk, ByteArray(0), ShadowProtocol.TAG_KEY_B2A, 32)
            
            return if (isPayer) {
                SessionChannel(sid, k_a2b, k_b2a)
            } else {
                SessionChannel(sid, k_b2a, k_a2b)
            }
        }
    }
}
