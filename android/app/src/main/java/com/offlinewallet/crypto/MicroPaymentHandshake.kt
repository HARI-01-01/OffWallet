package com.offlinewallet.crypto

import com.offlinewallet.SecureStorage
import com.offlinewallet.models.*
import java.nio.ByteBuffer

/**
 * Shadow Protocol v1 Handshake
 * Implements M1-M5 session logic using Encrypted SessionChannel.
 */
object MicroPaymentHandshake {

    // Frame Message Types (WP-18)
    const val MSG_M1_INIT = 0x01.toByte()
    const val MSG_M2_AUTH = 0x02.toByte()
    const val MSG_M3_COMMIT = 0x03.toByte()
    const val MSG_M4_RECEIPT = 0x04.toByte()
    const val MSG_M5_ACK = 0x05.toByte()
    const val MSG_M2_PASS = 0x06.toByte()
    const val MSG_M2_READY = 0x07.toByte()
    const val MSG_PROTOCOL_ERROR = 0x08.toByte()

    data class SessionInit(
        val sid: String,
        val epk_A: ByteArray,
        val chal_A: ByteArray,
        val pass_A: PassEnvelope,
        val amount_p: Long,
        val history_A: List<DebitBlock>,
        val rawPassA: ByteArray? = null // WP-FIX: Preserve original bytes for verification
    )

    data class SessionAuth(
        val epk_B: ByteArray,
        val chal_B: ByteArray,
        val sig_B: ByteArray,
        val pass_B: PassEnvelope,
        val payeeHead: ByteArray? = null,
        val payeeCounter: Long? = null
    )

    data class ProtocolError(
        val code: Int,
        val message: String
    )

    data class HistoryExchange(
        val pass: PassEnvelope,
        val history: List<DebitBlock>
    )

    fun encodeHistoryExchange(ex: HistoryExchange): ByteArray {
        val historyCanon = Canon.enc(
            *ex.history.map { Canon.Field.Bytes(encodeDebitBlock(it)) }.toTypedArray()
        )
        return Canon.enc(
            Canon.Field.Bytes(encodePassEnvelope(ex.pass)),
            Canon.Field.Bytes(historyCanon)
        )
    }

    fun decodeHistoryExchange(data: ByteArray): HistoryExchange {
        val dec = Canon.Decoder(data)
        val pass = decodePassEnvelope(dec.bytes())
        val historyBytes = dec.bytes()
        dec.assertDone()
        
        val hdec = Canon.Decoder(historyBytes)
        val history = mutableListOf<DebitBlock>()
        while (hdec.hasRemaining()) {
            history.add(decodeDebitBlock(hdec.bytes()))
        }
        return HistoryExchange(pass, history)
    }

    fun encodeSessionInit(m1: SessionInit): ByteArray {
        val passEnvCanon = encodePassEnvelope(m1.pass_A)
        val historyCanon = Canon.enc(
            *m1.history_A.map { Canon.Field.Bytes(encodeDebitBlock(it)) }.toTypedArray()
        )
        return Canon.enc(
            Canon.Field.Str(m1.sid),
            Canon.Field.Bytes(m1.epk_A),
            Canon.Field.Bytes(m1.chal_A),
            Canon.Field.Bytes(passEnvCanon),
            Canon.Field.U64(m1.amount_p),
            Canon.Field.Bytes(historyCanon)
        )
    }

    fun decodePass(data: ByteArray): Pass {
        val dec = Canon.Decoder(data)
        val pass = Pass(
            v = dec.u8(),
            kid = dec.str(),
            walletId = dec.str(),
            displayName = dec.str(),
            devicePubKeyHash = HexUtils.encodeHex(dec.bytes()),
            devicePubKey = HexUtils.encodeHex(dec.bytes()),
            attestTier = dec.str(),
            perTxCapP = dec.u64(),
            aggregateCapP = dec.u64(),
            txnCountCap = dec.u64(),
            recvUnsettledCapP = dec.u64(),
            recvPerPeerCapP = dec.u64(),
            passId = dec.str(),
            serverSeq = dec.u64(),
            issuedAt = dec.u64(),
            expiresAt = dec.u64(),
            genesisEpoch = dec.u64(),
            lastSettledCounter = dec.u64(),
            lastSettledHead = HexUtils.encodeHex(dec.bytes())
        )
        dec.assertDone()
        return pass
    }

    fun decodePassEnvelope(data: ByteArray): PassEnvelope {
        val dec = Canon.Decoder(data)
        val passBytes = dec.bytes()
        val sig = dec.bytes()
        dec.assertDone()
        return PassEnvelope(decodePass(passBytes), HexUtils.encodeHex(sig))
    }

    fun encodePassEnvelope(env: PassEnvelope): ByteArray {
        return Canon.enc(
            Canon.Field.Bytes(encodePass(env.pass)),
            Canon.Field.Bytes(HexUtils.decodeSafe(env.sig))
        )
    }

    fun decodeSessionInit(payload: ByteArray): SessionInit {
        val dec = Canon.Decoder(payload)
        val sid = dec.str()
        val epk_A = dec.bytes()
        val chal_A = dec.bytes()
        
        // WP-FIX: Peek into the envelope to get raw bytes
        val envelopeBytes = dec.bytes()
        val edec = Canon.Decoder(envelopeBytes)
        val rawPass = edec.bytes() // This is what the server signed
        val sig = edec.bytes()
        val pass = decodePass(rawPass)
        val pass_A = PassEnvelope(pass, HexUtils.encodeHex(sig))

        val amount_p = dec.u64()
        val historyBytes = dec.bytes()
        dec.assertDone()

        val hdec = Canon.Decoder(historyBytes)
        val history = mutableListOf<DebitBlock>()
        while (hdec.hasRemaining()) {
            history.add(decodeDebitBlock(hdec.bytes()))
        }
        
        return SessionInit(sid, epk_A, chal_A, pass_A, amount_p, history, rawPass)
    }

    fun encodeSessionAuth(m2: SessionAuth): ByteArray {
        val passEnvCanon = Canon.enc(
            Canon.Field.Bytes(encodePass(m2.pass_B.pass)),
            Canon.Field.Bytes(HexUtils.decodeSafe(m2.pass_B.sig))
        )
        return Canon.enc(
            Canon.Field.Bytes(m2.epk_B),
            Canon.Field.Bytes(m2.chal_B),
            Canon.Field.Bytes(m2.sig_B),
            Canon.Field.Bytes(passEnvCanon),
            Canon.Field.Bytes(m2.payeeHead ?: ByteArray(0)),
            Canon.Field.U64(m2.payeeCounter ?: 0L)
        )
    }

    fun encodePass(pass: Pass): ByteArray {
        // WP-FIX: Use ONLY the data inside the pass object. 
        // Do NOT fall back to local SecureStorage, which belongs to the current device, 
        // not necessarily the owner of the pass we are encoding.
        val pubKeyHex = pass.devicePubKey ?: ""
        return Canon.enc(
            Canon.Field.U8(pass.v),
            Canon.Field.Str(pass.kid),
            Canon.Field.Str(pass.walletId),
            Canon.Field.Str(pass.displayName),
            Canon.Field.Bytes(HexUtils.decodeSafe(pass.devicePubKeyHash)),
            Canon.Field.Bytes(HexUtils.decodeSafe(pubKeyHex)),
            Canon.Field.Str(pass.attestTier),
            Canon.Field.U64(pass.perTxCapP),
            Canon.Field.U64(pass.aggregateCapP),
            Canon.Field.U64(pass.txnCountCap),
            Canon.Field.U64(pass.recvUnsettledCapP),
            Canon.Field.U64(pass.recvPerPeerCapP),
            Canon.Field.Str(pass.passId),
            Canon.Field.U64(pass.serverSeq),
            Canon.Field.U64(pass.issuedAt),
            Canon.Field.U64(pass.expiresAt),
            Canon.Field.U64(pass.genesisEpoch),
            Canon.Field.U64(pass.lastSettledCounter),
            Canon.Field.Bytes(HexUtils.decodeSafe(pass.lastSettledHead))
        )
    }

    fun decodeSessionAuth(payload: ByteArray): SessionAuth {
        val dec = Canon.Decoder(payload)
        val res = SessionAuth(
            epk_B = dec.bytes(),
            chal_B = dec.bytes(),
            sig_B = dec.bytes(),
            pass_B = decodePassEnvelope(dec.bytes()),
            payeeHead = if (dec.hasRemaining()) dec.bytes() else null,
            payeeCounter = if (dec.hasRemaining()) dec.u64() else null
        )
        dec.assertDone()
        return res
    }

    fun decodeDebitBlockData(data: ByteArray): DebitBlock {
        val dec = Canon.Decoder(data)
        val block = DebitBlock(
            v = dec.u8(),
            chainId = dec.str(),
            walletId = dec.str(),
            counter = dec.u64(),
            prevHash = dec.bytes(),
            amountP = dec.u64(),
            payeePubKeyHash = dec.bytes(),
            payeeWalletId = dec.str(),
            payeeChal = dec.bytes(),
            payerPassId = dec.str(),
            payeePassId = dec.str(),
            genesisEpoch = dec.u64(),
            ts = dec.u64(),
            payeeCounter = if (dec.hasRemaining()) dec.u64() else null,
            payeePrevHash = if (dec.hasRemaining()) dec.bytes() else null
        )
        dec.assertDone()
        return block
    }

    fun encodeDebitBlockData(block: DebitBlock): ByteArray {
        val zero32 = ByteArray(32)
        val pHash = if (block.prevHash == null || block.prevHash.isEmpty()) zero32 else block.prevHash
        val ppHash = if (block.payeePrevHash == null || block.payeePrevHash.isEmpty()) zero32 else block.payeePrevHash
        val pubHash = if (block.payeePubKeyHash == null || block.payeePubKeyHash.isEmpty()) zero32 else block.payeePubKeyHash
        val chal = if (block.payeeChal == null || block.payeeChal.isEmpty()) zero32 else block.payeeChal

        val res = Canon.enc(
            Canon.Field.U8(block.v),
            Canon.Field.Str(block.chainId),
            Canon.Field.Str(block.walletId),
            Canon.Field.U64(block.counter),
            Canon.Field.Bytes(pHash),
            Canon.Field.U64(block.amountP),
            Canon.Field.Bytes(pubHash),
            Canon.Field.Str(block.payeeWalletId),
            Canon.Field.Bytes(chal),
            Canon.Field.Str(block.payerPassId),
            Canon.Field.Str(block.payeePassId),
            Canon.Field.U64(block.genesisEpoch),
            Canon.Field.U64(block.ts),
            Canon.Field.U64(block.payeeCounter ?: 0L),
            Canon.Field.Bytes(ppHash)
        )

        android.util.Log.v("Handshake", "Encoded Block #${block.counter}/${block.payeeCounter ?: 0}: Hash=${HexUtils.encodeHex(ShadowProtocol.sha256(ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + res)).take(8)}")
        return res
    }

    fun encodeDebitBlock(block: DebitBlock): ByteArray {
        val data = encodeDebitBlockData(block)
        return Canon.enc(
            Canon.Field.Bytes(data),
            Canon.Field.Bytes(block.payerSig ?: ByteArray(0)),
            Canon.Field.Bytes(block.payeeSig ?: ByteArray(0))
        )
    }

    fun decodeDebitBlock(data: ByteArray): DebitBlock {
        val dec = Canon.Decoder(data)
        val blockBytes = dec.bytes()
        val ps = dec.bytes()
        val ss = dec.bytes()
        dec.assertDone()

        val bdec = Canon.Decoder(blockBytes)
        val block = DebitBlock(
            v = bdec.u8(),
            chainId = bdec.str(),
            walletId = bdec.str(),
            counter = bdec.u64(),
            prevHash = bdec.bytes(),
            amountP = bdec.u64(),
            payeePubKeyHash = bdec.bytes(),
            payeeWalletId = bdec.str(),
            payeeChal = bdec.bytes(),
            payerPassId = bdec.str(),
            payeePassId = bdec.str(),
            genesisEpoch = bdec.u64(),
            ts = bdec.u64(),
            payeeCounter = if (bdec.hasRemaining()) bdec.u64() else null,
            payeePrevHash = if (bdec.hasRemaining()) bdec.bytes() else null
        )
        bdec.assertDone()

        return block.copy(
            payerSig = if (ps.isNotEmpty()) ps else null,
            payeeSig = if (ss.isNotEmpty()) ss else null
        )
    }

    fun encodeHandoverM3(pass: PassEnvelope, block: DebitBlock, sigA: ByteArray): ByteArray {
        val passEnvCanon = encodePassEnvelope(pass)
        val blockWithSigs = block.copy(payerSig = sigA)
        return Canon.enc(
            Canon.Field.Bytes(passEnvCanon),
            Canon.Field.Bytes(encodeDebitBlock(blockWithSigs))
        )
    }

    fun decodeHandoverM3(data: ByteArray): Triple<PassEnvelope, DebitBlock, ByteArray> {
        val dec = Canon.Decoder(data)
        val passEnv = decodePassEnvelope(dec.bytes())
        val blockWithSigsBytes = dec.bytes()
        dec.assertDone()
        
        val blockWithSigs = decodeDebitBlock(blockWithSigsBytes)
        return Triple(passEnv, blockWithSigs, blockWithSigs.payerSig ?: ByteArray(0))
    }

    fun encodeM3(block: DebitBlock, sigA: ByteArray): ByteArray {
        // M3 signature proof is usually blockData + sigA separately packed or bundled
        return Canon.enc(Canon.Field.Bytes(encodeDebitBlockData(block)), Canon.Field.Bytes(sigA))
    }

    fun encodeM4(receipt: Receipt, sigB: ByteArray): ByteArray {
        val receiptCanon = Canon.enc(
            Canon.Field.U8(receipt.v),
            Canon.Field.Bytes(receipt.blockHash),
            Canon.Field.Str(receipt.payeeWalletId),
            Canon.Field.U64(receipt.payeeCounter),
            Canon.Field.Bytes(receipt.payeePrevHash),
            Canon.Field.Bytes(receipt.payerChal),
            Canon.Field.U64(receipt.ts)
        )
        return Canon.enc(Canon.Field.Bytes(receiptCanon), Canon.Field.Bytes(sigB))
    }

    fun encodeM5(ack: Ack): ByteArray {
        return Canon.enc(
            Canon.Field.U8(ack.v),
            Canon.Field.Bytes(ack.receiptHash)
        )
    }

    fun encodeError(err: ProtocolError): ByteArray {
        return Canon.enc(
            Canon.Field.U64(err.code.toLong()),
            Canon.Field.Str(err.message)
        )
    }

    fun decodeError(data: ByteArray): ProtocolError {
        val dec = Canon.Decoder(data)
        val res = ProtocolError(
            code = dec.u64().toInt(),
            message = dec.str()
        )
        dec.assertDone()
        return res
    }

    /**
     * Compute transcript hash for M2/SAS
     */
    fun computeTranscript(
        sid: String, 
        epk_A: ByteArray, 
        epk_B: ByteArray, 
        chal_A: ByteArray, 
        chal_B: ByteArray, 
        pass_id_A: String, 
        pass_id_B: String, 
        amount_p: Long
    ): ByteArray {
        val transcriptCanon = Canon.enc(
            Canon.Field.Str(sid),
            Canon.Field.Bytes(epk_A),
            Canon.Field.Bytes(epk_B),
            Canon.Field.Bytes(chal_A),
            Canon.Field.Bytes(chal_B),
            Canon.Field.Str(pass_id_A),
            Canon.Field.Str(pass_id_B),
            Canon.Field.U64(amount_p)
        )
        return ShadowProtocol.sha256(
            ShadowProtocol.TAG_SESSION_AUTH.toByteArray() + byteArrayOf(0x00) + transcriptCanon
        )
    }

    fun decodeM3(payload: ByteArray): Pair<DebitBlock, ByteArray> {
        val dec = Canon.Decoder(payload)
        val blockBytes = dec.bytes()
        val sigA = dec.bytes()
        dec.assertDone()
        
        val block = decodeDebitBlock(blockBytes)
        return Pair(block, sigA)
    }

    fun decodeM4(payload: ByteArray): Pair<Receipt, ByteArray> {
        val dec = Canon.Decoder(payload)
        val receiptCanon = dec.bytes()
        val sigB = dec.bytes()
        dec.assertDone()
        
        val rdec = Canon.Decoder(receiptCanon)
        val receipt = Receipt(
            v = rdec.u8(),
            blockHash = rdec.bytes(),
            payeeWalletId = rdec.str(),
            payeeCounter = rdec.u64(),
            payeePrevHash = rdec.bytes(),
            payerChal = rdec.bytes(),
            ts = rdec.u64()
        )
        rdec.assertDone()
        return Pair(receipt, sigB)
    }

    fun encodeV1QR(v1: V1QR): ByteArray {
        val passEnvCanon = encodePassEnvelope(v1.pass)
        val historyCanon = Canon.enc(
            *v1.history.map { Canon.Field.Bytes(encodeDebitBlock(it)) }.toTypedArray()
        )
        return Canon.enc(
            Canon.Field.U8(v1.v),
            Canon.Field.Bytes(passEnvCanon),
            Canon.Field.Str(v1.sid),
            Canon.Field.Bytes(HexUtils.decodeSafe(v1.epk_B)),
            Canon.Field.Bytes(HexUtils.decodeSafe(v1.chal_B)),
            Canon.Field.Str(v1.bleUuid),
            Canon.Field.U64(v1.amountP ?: 0L),
            Canon.Field.Bytes(historyCanon)
        )
    }

    fun decodeV1QR(payload: ByteArray): V1QR {
        try {
            val dec = Canon.Decoder(payload)
            val v = dec.u8()
            val passEnv = decodePassEnvelope(dec.bytes())
            val sid = dec.str()
            val epk_B = dec.bytes()
            val chal_B = dec.bytes()
            val bleUuid = dec.str()
            val amountP = dec.u64()
            val historyBytes = dec.bytes()
            dec.assertDone()
            
            val hdec = Canon.Decoder(historyBytes)
            val history = mutableListOf<DebitBlock>()
            while (hdec.hasRemaining()) {
                history.add(decodeDebitBlock(hdec.bytes()))
            }
            
            return V1QR(
                v = v,
                pass = passEnv,
                sid = sid,
                epk_B = HexUtils.encodeHex(epk_B),
                chal_B = HexUtils.encodeHex(chal_B),
                bleUuid = bleUuid,
                amountP = if (amountP > 0) amountP else null,
                history = history
            )
        } catch (e: Exception) {
            android.util.Log.e("Handshake", "decodeV1QR failed: ${e.message}")
            throw e
        }
    }

    /**
     * Derive 6-digit SAS (Short Authentication String)
     */
    fun deriveSas(ss: ByteArray, transcript: ByteArray): String {
        val sasBytes = ShadowProtocol.hkdf(ss, transcript, "shadow/v1/sas", 4)
        val bb = java.nio.ByteBuffer.wrap(sasBytes)
        val sasInt = bb.int and 0x7FFFFFFF
        return String.format(java.util.Locale.US, "%06d", sasInt % 1_000_000)
    }
}
