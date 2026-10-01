package com.offlinewallet.payment.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import com.offlinewallet.SecureStorage
import com.offlinewallet.crypto.*
import com.offlinewallet.models.*
import kotlinx.coroutines.*
import java.security.SecureRandom
import java.util.*

/**
 * BLEManager - Pro Inverted Handshake Implementation
 * Alice (Payer) = Server, Bob (Payee) = Client
 * Flow: Tap -> Connect -> M2_Auth (Bob ID) -> M2_Pass (Alice ID) -> M2_Ready (Bob OK) -> M3 (Alice Money) -> M4 (Bob Receipt)
 */
@SuppressLint("MissingPermission")
class BLEManager(private val context: Context) {
    private val TAG = "BLEManager"
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter = bluetoothManager.adapter
    private val mainHandler = Handler(Looper.getMainLooper())
    private val scope = CoroutineScope(Dispatchers.Main + Job())

    companion object {
        private val WALLET_SERVICE_UUID = UUID.fromString("f044464c-5701-4000-8000-00805f9b34fb")
        private var sharedGattServer: BluetoothGattServer? = null
    }

    private var SERVICE_UUID = WALLET_SERVICE_UUID
    private val CHAR_UUID = UUID.fromString("f044464d-5701-4000-8000-00805f9b34fb")
    private val CLIENT_CHARACTERISTIC_CONFIG = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    private var currentMtu = 23 // Default BLE MTU

    fun setServiceUuid(uuid: UUID) { this.SERVICE_UUID = uuid }
    fun setSessionChannel(channel: SessionChannel) { this.sessionChannel = channel }

    // Callbacks
    var onDataReceived: ((ByteArray) -> Unit)? = null
    var onPhaseChanged: ((PaymentSessionProgress) -> Unit)? = null
    var onError: ((String) -> Unit)? = null
    var onDeviceFound: ((String) -> Unit)? = null

    // State
    private var gatt: BluetoothGatt? = null
    private var payerTargetChar: BluetoothGattCharacteristic? = null
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = adapter?.bluetoothLeAdvertiser
    private var connectedDevice: BluetoothDevice? = null
    private var pendingWriteQueue = mutableListOf<ByteArray>()
    private val chunkMap = mutableMapOf<Int, ByteArray>()
    private var isWriting = false
    private var expectedChunks = 0
    private var m3Sent = false
    private var m3Received = false
    private var finalized = false
    private var isPayerRole = true
    private var m4TimeoutJob: Job? = null
    private var targetBleId: String? = null
    private var scanTimeoutRunnable: Runnable? = null
    private var descriptorTimeoutRunnable: Runnable? = null
    private var lastScanTime = 0L
    private var isScanning = false
    private var responseDeferred: CompletableDeferred<Unit>? = null
    private val subscriptionMap = mutableMapOf<BluetoothDevice, Boolean>()
    private var currentAdvertisingSid: String? = null

    private var mtuReady = false
    private var descriptorWriteAttempts = 0
    private val MAX_DESCRIPTOR_ATTEMPTS = 3
    private var discoveryRetryAttempts = 0
    private val MAX_DISCOVERY_ATTEMPTS = 15 // Increased from 6 for slower devices
    private var reconnectAttempts = 0
    private val MAX_RECONNECT_ATTEMPTS = 2
    private var isFirstConnection = true
    private var pendingReconnectDevice: BluetoothDevice? = null

    internal var sessionChannel: SessionChannel? = null
    var currentPaymentContext: PaymentContext? = null
    var paymentCallbacks: PaymentCallbacks? = null
    private var paymentTimeoutRunnable: Runnable? = null

    data class PaymentContext(
        var payerId: String, var payeeId: String, var amount: Int,
        val ephPriv: ByteArray, val ephPub: ByteArray,
        var chal: ByteArray, var chalA: ByteArray? = null,
        val sid: String? = null,
        var myPass: PassEnvelope? = null, var peerPass: PassEnvelope? = null,
        val aliceBleUuid: UUID? = null,
        var committedBlock: DebitBlock? = null,
        var committedSigA: ByteArray? = null,
        var payeeHead: ByteArray? = null,
        var payeeCounter: Long? = null
    ) {
        fun erase() { MemoryUtils.erase(ephPriv); MemoryUtils.erase(ephPub); MemoryUtils.erase(chal); chalA?.let { MemoryUtils.erase(it) } }
    }

    interface PaymentCallbacks {
        fun onPaymentInitiated(); fun onChallengeReceived(challenge: ByteArray)
        fun onPaymentAccepted(receipt: com.offlinewallet.models.Receipt); fun onPaymentError(error: String); fun onPaymentComplete(newBalance: Int)
    }

    private fun logUuid(phase: String) {
        val target = currentPaymentContext?.aliceBleUuid ?: SERVICE_UUID
        Log.d(TAG, "[$phase] SERVICE: $target, CHAR: $CHAR_UUID")
    }

    // ==================== FULL BLE BOOTSTRAP FLOW ====================

    fun startPayerFlow(payerId: String, amount: Int, sid: String, bobPass: PassEnvelope, bobEpk: ByteArray, bobChal: ByteArray, callbacks: PaymentCallbacks) {
        stop()
        Log.d(TAG, "🚀 [STEP 0] Starting Full BLE PAYER Flow. SID: $sid, Amount: $amount")
        this.paymentCallbacks = callbacks; this.m3Sent = false; this.m3Received = false; this.finalized = false
        this.isPayerRole = true
        
        // WP-FIX: Use Static Service UUID for discovery
        this.SERVICE_UUID = WALLET_SERVICE_UUID
        
        startPaymentTimeout()
        scope.launch {
            Log.d(TAG, "🚀 [STEP 2] Launching Payer Setup Coroutine")
            
            // WP-FIX: Initialize context early for UI visibility
            currentPaymentContext = PaymentContext(
                payerId = payerId,
                payeeId = bobPass.pass.walletId,
                amount = amount,
                ephPriv = ByteArray(0), // Placeholder
                ephPub = ByteArray(0),  // Placeholder
                chal = bobChal,
                sid = sid,
                peerPass = bobPass,
                aliceBleUuid = WALLET_SERVICE_UUID
            )
            notifyProgress(PaymentPhase.DISCOVERY, "Searching for recipient...")
            
            data class PayerSetupResult(
                val ephA: java.security.KeyPair,
                val myPass: PassEnvelope,
                val ss: ByteArray,
                val transcript: ByteArray,
                val chalA: ByteArray
            )

            val result = withContext(Dispatchers.Default) {
                val eph = SecureKeyStore.generateEphemeralKeyPair() ?: return@withContext null
                val pass = SecureStorage.getPass() ?: return@withContext null
                val cA = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
                
                val sharedSecret = SecureKeyStore.computeSharedSecret(eph.private, KeyManager.bytesToPublicKey(bobEpk, "X25519"))
                    ?: return@withContext null
                
                // WP-FIX: Ensure raw 32-byte public keys are used in the transcript
                val ts = MicroPaymentHandshake.computeTranscript(sid, KeyManager.publicKeyToBytes(eph.public), bobEpk, cA, bobChal, pass.pass.passId, bobPass.pass.passId, amount.toLong())
                
                PayerSetupResult(eph, pass, sharedSecret, ts, cA)
            }

            if (result == null) {
                Log.e(TAG, "❌ [FAIL] Hardware security initialization failed")
                return@launch callbacks.onPaymentError("Security init failed")
            }

            Log.d(TAG, "🚀 [STEP 3-6] Security Parameters Computed")
            sessionChannel = SessionChannel.derive(result.ss, result.transcript, sid, true)
            
            // WP-FIX: Use standardized 32-byte keys in PaymentContext
            currentPaymentContext = PaymentContext(
                payerId = payerId, 
                payeeId = bobPass.pass.walletId, 
                amount = amount, 
                ephPriv = KeyManager.privateKeyToBytes(result.ephA.private)!!, 
                ephPub = KeyManager.publicKeyToBytes(result.ephA.public), 
                chal = bobChal, 
                chalA = result.transcript, // Transcript preservation
                sid = sid, 
                myPass = result.myPass, 
                peerPass = bobPass, 
                aliceBleUuid = WALLET_SERVICE_UUID
            )
            
            // Actually, keep chalA as the random challenge
            currentPaymentContext = currentPaymentContext?.copy(chalA = result.chalA)
            
            onDeviceFound = { address -> 
                Log.d(TAG, "🚀 [STEP 7] Target Device Found: $address. Attempting connect...")
                adapter?.getRemoteDevice(address)?.let { connectToDevice(it) }
                onDeviceFound = null 
            }
            
            Log.d(TAG, "🚀 [STEP 8] Starting BLE Scan for Static Service...")
            startScanning()
            notifyProgress(PaymentPhase.DISCOVERY, "Searching for Bob...")
        }
    }

    fun startPayeeFlow(sid: String, callbacks: PaymentCallbacks, existingEphKey: java.security.KeyPair? = null, bobChallenge: ByteArray? = null) {
        stop()
        Log.d(TAG, "🔍 [STEP 0] Starting Full BLE PAYEE Flow. SID: $sid")
        this.paymentCallbacks = callbacks
        this.isPayerRole = false
        
        // WP-FIX: Use Static Service UUID for discovery
        this.SERVICE_UUID = WALLET_SERVICE_UUID
        this.m3Sent = false; this.m3Received = false; this.finalized = false
        
        startPaymentTimeout()
        scope.launch {
            Log.d(TAG, "🔍 [STEP 2] Launching Payee Setup Coroutine")
            
            // WP-FIX: Initialize context early with what we know
            currentPaymentContext = PaymentContext(
                payerId = "awaiting",
                payeeId = SecureStorage.getWalletId() ?: "unknown",
                amount = 0,
                ephPriv = ByteArray(0),
                ephPub = ByteArray(0),
                chal = ByteArray(0),
                sid = sid
            )
            notifyProgress(PaymentPhase.DISCOVERY, "Initializing hardware security...")
            
            val (ephB, passB) = withContext(Dispatchers.Default) {
                val eph = existingEphKey ?: SecureKeyStore.generateEphemeralKeyPair() ?: return@withContext null
                val pass = SecureStorage.getPass() ?: return@withContext null
                Pair(eph, pass)
            } ?: run {
                Log.e(TAG, "❌ [FAIL] Payee Hardware security initialization failed")
                return@launch callbacks.onPaymentError("Security init failed")
            }

            Log.d(TAG, "🔍 [STEP 3-4] Ephemeral Keys and Pass Loaded")
            
            val myChal = bobChallenge ?: ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }

            // WP-FIX: Use standardized 32-byte keys in PaymentContext
            currentPaymentContext = PaymentContext(
                payerId = "awaiting",
                payeeId = SecureStorage.getWalletId()!!,
                amount = 0,
                ephPriv = KeyManager.privateKeyToBytes(ephB.private)!!,
                ephPub = KeyManager.publicKeyToBytes(ephB.public),
                chal = myChal, // Bob's challenge from QR
                sid = sid,
                myPass = passB
            )
            
            Log.d(TAG, "🔍 [STEP 5] Setting up GATT Server...")
            setupGattServer()
        }
    }

    private suspend fun sendM1Handshake() {
        val ctx = currentPaymentContext ?: return
        Log.d(TAG, "[PROT] > M1: Initiating Handshake with ${ctx.amount} paise...")
        notifyProgress(PaymentPhase.IDENTITY, "Sending security pass...")
        
        try {
            val encoded = withContext(Dispatchers.Default) {
                // WP-FIX: Use Full History since the Anchor to avoid gaps
                val history = HashChainManager.getHistorySince(context, ctx.payerId, ctx.myPass!!.pass.lastSettledCounter)
                
                Log.d(TAG, "[PROT] Packing Alice history: ${history.size} blocks for M1 (Starting from lastSettledCounter=${ctx.myPass!!.pass.lastSettledCounter})")

                val m1 = MicroPaymentHandshake.SessionInit(
                    sid = ctx.sid!!,
                    epk_A = ctx.ephPub,
                    chal_A = ctx.chalA!!,
                    pass_A = ctx.myPass!!,
                    amount_p = ctx.amount.toLong(),
                    history_A = history
                )
                MicroPaymentHandshake.encodeSessionInit(m1)
            }
            sendWithRetry(MicroPaymentHandshake.MSG_M1_INIT, encoded, MicroPaymentHandshake.MSG_M2_AUTH)
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M1 Initiation Error: ${e.message}")
            sendError(1000, "ERR-1000: M1 Initiation Fail - ${e.message}")
        }
    }

    private suspend fun handleM1(payload: ByteArray) {
        val m1 = try {
            MicroPaymentHandshake.decodeSessionInit(payload)
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M1 Decode Fail: ${e.message}")
            return sendError(1001, "ERR-1001: M1 Decode Fail - ${e.message}")
        }
        
        val ctx = currentPaymentContext ?: return
        Log.d(TAG, "[PROT] < M1: Received from ${m1.pass_A.pass.walletId}. Amount=${m1.amount_p}")
        
        // Update context with newly received information
        ctx.amount = m1.amount_p.toInt()
        ctx.peerPass = m1.pass_A
        ctx.payerId = m1.pass_A.pass.walletId
        
        // WP-18: Audit Alice's History
        notifyProgress(PaymentPhase.AUDIT, "Payer identified. Auditing ledger...")
        if (!PassVault.verifyPass(context, m1.pass_A, m1.rawPassA)) {
            Log.e(TAG, "[PROT] Alice Pass Verification Failed (Invalid server signature)")
            return sendError(1002, "ERR-1002: Alice Pass Signature Invalid")
        }

        // PRD FIX: Strict History Chain Audit
        val alicePub = KeyManager.bytesToPublicKey(HexUtils.decodeSafe(m1.pass_A.pass.devicePubKey ?: ""))
        Log.d(TAG, "[AUDIT] Bob auditing Alice: ${m1.history_A.size} blocks received. Anchor: ${m1.pass_A.pass.lastSettledHead.take(8)}")
        if (alicePub == null || !HashChainManager.verifyHistory(m1.history_A, m1.pass_A.pass.lastSettledHead, alicePub)) {
            Log.e(TAG, "[PROT] Alice Chain Audit Failed (Divergent history)")
            return sendError(1003, "ERR-1003: Alice Ledger Divergent")
        }
        
        // PRD FIX: Check for Gaps between provided history and server head
        if (m1.history_A.isNotEmpty()) {
            val firstBlock = m1.history_A.first()
            if (firstBlock.counter > m1.pass_A.pass.lastSettledCounter + 1) {
                Log.e(TAG, "[PROT] Alice Gap Audit Failed: Missing blocks since sync")
                return sendError(1006, "ERR-1006: Ledger Gap Detected")
            }
        }
        Log.d(TAG, "[PROT] Alice History Verified ✓")

        // Update context with Alice's info
        try {
            val ss = SecureKeyStore.computeSharedSecret(KeyManager.bytesToPrivateKey(ctx.ephPriv, "X25519"), KeyManager.bytesToPublicKey(m1.epk_A, "X25519")) 
                ?: return sendError(1004, "ERR-1004: Shared secret computation failed")
            
            // WP-FIX: Use Bob's challenge from context (passed from QR)
            val chalB = ctx.chal 
            val transcript = MicroPaymentHandshake.computeTranscript(ctx.sid!!, m1.epk_A, ctx.ephPub, m1.chal_A, chalB, m1.pass_A.pass.passId, ctx.myPass!!.pass.passId, m1.amount_p)
            
            sessionChannel = SessionChannel.derive(ss, transcript, ctx.sid, false)
            
            currentPaymentContext = ctx.copy(
                payerId = m1.pass_A.pass.walletId,
                amount = m1.amount_p.toInt(),
                chal = m1.chal_A, // Payer challenge
                chalA = chalB, // Payee challenge
                peerPass = m1.pass_A
            )
            
            notifyProgress(PaymentPhase.IDENTITY, "Alice verified. Proving my identity...")
            sendM2Inverted()
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M1 Process Error: ${e.message}")
            sendError(1005, "ERR-1005: M1 Process Fail - ${e.message}")
        }
    }

    // ==================== INVERTED HANDOVER LOGIC ====================

    fun startInvertedHandoverPayer(payerId: String, payeeId: String, amount: Int, sid: String, aliceBleUuid: UUID, bobChallenge: ByteArray, aliceChallenge: ByteArray, bobEpk: ByteArray, bobPass: PassEnvelope, payerPass: PassEnvelope, callbacks: PaymentCallbacks) {
        stop()
        Log.d(TAG, "🚀 Starting PAYER (Server) for $aliceBleUuid")
        this.paymentCallbacks = callbacks; this.SERVICE_UUID = aliceBleUuid; this.m3Sent = false; this.finalized = false
        logUuid("PAYER_START")
        startPaymentTimeout()
        scope.launch {
            notifyProgress(PaymentPhase.DISCOVERY, "Initializing hardware security...")
            val ephA = SecureKeyStore.generateEphemeralKeyPair() ?: return@launch callbacks.onPaymentError("Key failed")
            currentPaymentContext = PaymentContext(payerId, payeeId, amount, ephA.private.encoded, ephA.public.encoded, bobChallenge, aliceChallenge, sid, payerPass, bobPass, aliceBleUuid)
            val ss = SecureKeyStore.computeSharedSecret(ephA.private, KeyManager.bytesToPublicKey(bobEpk, "X25519")) ?: return@launch callbacks.onPaymentError("Secret failed")
            val transcript = MicroPaymentHandshake.computeTranscript(sid, KeyManager.publicKeyToBytes(ephA.public), bobEpk, aliceChallenge, bobChallenge, payerPass.pass.passId, bobPass.pass.passId, amount.toLong())
            sessionChannel = SessionChannel.derive(ss, transcript, sid, true)
            setupGattServer(); startAdvertising(sid.take(6))
            notifyProgress(PaymentPhase.DISCOVERY, "Waiting for recipient to connect...")
        }
    }

    fun startInvertedHandoverPayee(aliceBleUuid: UUID, sid: String, aliceId: String, aliceEpk: ByteArray, chalA: ByteArray, amount: Long, passIdA: String, callbacks: PaymentCallbacks) {
        stop()
        Log.d(TAG, "🔍 Starting PAYEE (Client) for $aliceBleUuid")
        this.paymentCallbacks = callbacks; this.SERVICE_UUID = aliceBleUuid; this.m3Sent = false; this.finalized = false
        logUuid("PAYEE_START")
        startPaymentTimeout()
        scope.launch {
            notifyProgress(PaymentPhase.DISCOVERY, "Initializing hardware security...")
            val ephB = SecureKeyStore.generateEphemeralKeyPair() ?: return@launch callbacks.onPaymentError("Key failed")
            val chalB = ByteArray(32).apply { java.security.SecureRandom().nextBytes(this) }
            val passB = SecureStorage.getPass() ?: return@launch callbacks.onPaymentError("Pass missing")
            currentPaymentContext = PaymentContext(aliceId, SecureStorage.getWalletId()!!, amount.toInt(), ephB.private.encoded, ephB.public.encoded, chalA, chalB, sid, passB, null, aliceBleUuid)
            val ss = SecureKeyStore.computeSharedSecret(ephB.private, KeyManager.bytesToPublicKey(aliceEpk, "X25519")) ?: return@launch callbacks.onPaymentError("Secret failed")
            val transcript = MicroPaymentHandshake.computeTranscript(sid, aliceEpk, KeyManager.publicKeyToBytes(ephB.public), chalA, chalB, passIdA, passB.pass.passId, amount)
            sessionChannel = SessionChannel.derive(ss, transcript, sid, false)
            onDeviceFound = { address -> adapter?.getRemoteDevice(address)?.let { connectToDevice(it) }; onDeviceFound = null }
            startScanning(sid.take(6)); notifyProgress(PaymentPhase.DISCOVERY, "Seeking payer phone...")
        }
    }

    // ==================== PROTOCOL PHASES ====================

    private suspend fun sendWithRetry(type: Byte, data: ByteArray, expectedResponseType: Byte? = null) {
        var attempts = 0
        val maxAttempts = 3
        
        while (attempts < maxAttempts) {
            if (currentPaymentContext == null) return
            
            Log.d(TAG, "Sending message type ${type.toInt()} (Attempt ${attempts + 1})")
            sendData(byteArrayOf(type) + data)
            
            if (expectedResponseType == null) return // Fire and forget
            
            try {
                responseDeferred = CompletableDeferred()
                withTimeout(5000L) {
                    responseDeferred?.await()
                }
                Log.d(TAG, "Received response for type ${type.toInt()}")
                return // Success
            } catch (e: TimeoutCancellationException) {
                attempts++
                if (attempts < maxAttempts) {
                    Log.w(TAG, "Timeout waiting for type ${expectedResponseType.toInt()}, retrying...")
                }
            }
        }
        
        Log.e(TAG, "Failed to send message type ${type.toInt()} after $maxAttempts attempts")
        if (!finalized) {
            sendError(6001, "Communication timeout. Please try again.")
        }
    }

    private suspend fun sendM2Inverted() {
        val ctx = currentPaymentContext ?: return
        Log.d(TAG, "[PROT] > M2: Sending Identity Proof...")
        notifyProgress(PaymentPhase.IDENTITY, "Signing identity binding...")
        try {
            val encrypted = withContext(Dispatchers.Default) {
                val sigB = try {
                    SecureKeyStore.sign(ctx.payeeId, ShadowProtocol.TAG_SESSION_AUTH, ctx.chal)
                } catch (e: android.security.keystore.UserNotAuthenticatedException) {
                    Log.w(TAG, "[PROT] M2 Sign requires Biometrics")
                    // Notify UI to show Biometric Prompt
                    mainHandler.post { paymentCallbacks?.onChallengeReceived(ctx.chal) }
                    return@withContext null // Wait for user to authenticate and retry
                }

                if (sigB == null) throw Exception("Hardware returned null signature")
                
                val chalA = ctx.chalA ?: throw Exception("Payer challenge missing in context")
                val myPass = ctx.myPass ?: throw Exception("My security pass missing in context")
                
                // WP-FIX: UDLB - Fetch current local state to share with Alice
                val localHead = HashChainManager.head(context, ctx.payeeId)
                val localCounter = HashChainManager.nextCounter(context, ctx.payeeId)

                val m2 = MicroPaymentHandshake.SessionAuth(
                    epk_B = ctx.ephPub, 
                    chal_B = chalA, 
                    sig_B = sigB, 
                    pass_B = myPass,
                    payeeHead = localHead,
                    payeeCounter = localCounter
                )
                val encoded = MicroPaymentHandshake.encodeSessionAuth(m2)
                sessionChannel?.seal(MicroPaymentHandshake.MSG_M2_AUTH, encoded) ?: throw Exception("Seal failed")
            } ?: return

            sendWithRetry(MicroPaymentHandshake.MSG_M2_AUTH, encrypted, MicroPaymentHandshake.MSG_M3_COMMIT)
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M2 Generation Error: ${e.message}")
            sendError(2000, "ERR-2000: M2 Hardware Sign Fail - ${e.message}")
        }
    }

    private suspend fun handleM2Inverted(plaintext: ByteArray) {
        responseDeferred?.complete(Unit)
        val m2 = try {
            MicroPaymentHandshake.decodeSessionAuth(plaintext)
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M2 Decode Fail: ${e.message}")
            return sendError(2001, "ERR-2001: M2 Decode Fail - ${e.message}")
        }
        val ctx = currentPaymentContext ?: return
        Log.d(TAG, "[PROT] < M2: Identity Proof received from ${m2.pass_B.pass.walletId}")
        
        // Update context with newly received information
        ctx.peerPass = m2.pass_B
        
        notifyProgress(PaymentPhase.IDENTITY, "Recipient verified. Finalizing audit...")
        
        // PRD FIX: Binding Check - Does the BLE device match the QR device?
        val preAuditedPass = ctx.peerPass?.pass
        if (preAuditedPass != null) {
            if (m2.pass_B.pass.walletId != preAuditedPass.walletId || 
                m2.pass_B.pass.devicePubKeyHash != preAuditedPass.devicePubKeyHash) {
                Log.e(TAG, "[PROT] PRE-AUDIT MISMATCH: BLE device != QR device!")
                return sendError(2003, "ERR-2003: Session Hijack Detected")
            }
        }

        try {
            val peerPub = KeyManager.bytesToPublicKey(HexUtils.decodeSafe(m2.pass_B.pass.devicePubKey ?: ""))
            if (!Signer.verify(ShadowProtocol.TAG_SESSION_AUTH, peerPub, ctx.chalA!!, m2.sig_B)) {
                Log.e(TAG, "[PROT] Bob Identity Verification Failed (Signature Mismatch)")
                return sendError(2002, "ERR-2002: Recipient Identity Bind Fail")
            }
            
            Log.d(TAG, "[PROT] Mutual Audit OK. Proceeding to payment...")
            currentPaymentContext = ctx.copy(
                peerPass = m2.pass_B, 
                chal = m2.chal_B,
                payeeHead = m2.payeeHead,
                payeeCounter = m2.payeeCounter
            )
            
            handleM2Ready()
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M2 Processing Error: ${e.message}")
            sendError(2003, "ERR-2003: M2 Verify Fail - ${e.message}")
        }
    }


    private suspend fun handleM2Ready() {
        responseDeferred?.complete(Unit)
        val ctx = currentPaymentContext ?: return
        Log.d(TAG, "[PROT] Phase 2 OK: Bob is READY. Deducting money and sending M3.")
        notifyProgress(PaymentPhase.DEBITING, "Preparing secure payment block...")
        
        if (m3Sent) return
        val walletId = ctx.payerId
        
        try {
            // WP-FIX: Alice (Payer) - Move funds to reserve BEFORE signing/sending M3
            val reserved = withContext(Dispatchers.IO) {
                BucketManager(context).reserveFunds(walletId, ctx.amount.toLong())
            }
            if (reserved is BucketManager.ReservationResult.Error) {
                Log.e(TAG, "[PROT] Reservation failed: ${reserved.message}")
                return sendError(reserved.code.toInt(), reserved.message)
            }

            val (block, sigA, encrypted) = if (ctx.committedBlock != null && ctx.committedSigA != null) {
                Log.i(TAG, "[PROT] Re-using existing committed block #${ctx.committedBlock!!.counter}")
                val m3Payload = MicroPaymentHandshake.encodeHandoverM3(ctx.myPass!!, ctx.committedBlock!!, ctx.committedSigA!!)
                val enc = sessionChannel?.seal(MicroPaymentHandshake.MSG_M3_COMMIT, m3Payload) ?: throw Exception("Seal fail")
                Triple(ctx.committedBlock!!, ctx.committedSigA!!, enc)
            } else {
                withContext(Dispatchers.Default) {
                    notifyProgress(PaymentPhase.DEBITING, "Signing debit block with hardware...")
                    val nextCounter = HashChainManager.nextCounter(context, walletId)
                    val head = HashChainManager.head(context, walletId)
                    val peerPubKeyHash = ShadowProtocol.sha256(HexUtils.decodeSafe(ctx.peerPass?.pass?.devicePubKeyHash ?: ""))
                    
                    // WP-FIX: UDLB - Construct block with BOTH Payer and Payee links
                    val b = DebitBlock(
                        v = 1, 
                        chainId = "SHADOW", 
                        walletId = walletId, 
                        counter = nextCounter, 
                        prevHash = head, 
                        amountP = ctx.amount.toLong(), 
                        payeePubKeyHash = peerPubKeyHash, 
                        payeeWalletId = ctx.payeeId, 
                        payeeChal = ctx.chal, 
                        payerPassId = ctx.myPass?.pass?.passId ?: "", 
                        payeePassId = ctx.peerPass?.pass?.passId ?: "", 
                        genesisEpoch = ctx.myPass?.pass?.genesisEpoch ?: 1, 
                        ts = System.currentTimeMillis() / 1000,
                        payeeCounter = ctx.payeeCounter,
                        payeePrevHash = ctx.payeeHead
                    )
                    
                    val blockData = MicroPaymentHandshake.encodeDebitBlockData(b)
                    val signature = SecureKeyStore.sign(walletId, ShadowProtocol.TAG_DEBIT_BLOCK, blockData) ?: run {
                        Log.e(TAG, "[PROT] Alice TEE Sign failed")
                        throw Exception("Hardware Debit Fail")
                    }

                    val m3Payload = MicroPaymentHandshake.encodeHandoverM3(ctx.myPass!!, b, signature)
                    val enc = sessionChannel?.seal(MicroPaymentHandshake.MSG_M3_COMMIT, m3Payload) ?: throw Exception("Seal fail")
                    
                    Triple(b, signature, enc)
                }
            }

            // WP-FIX: Save the committed block and signature for M4 finalizing and retries
            ctx.committedBlock = block
            ctx.committedSigA = sigA
            
            Log.d(TAG, "[PROT] > M3: Sending signed block #${block.counter}")
            notifyProgress(PaymentPhase.DEBITING, "Pushing funds to recipient...")
            
            // Mark as sent only when we actually trigger the Bluetooth write
            m3Sent = true
            
            m4TimeoutJob = scope.launch {
                delay(15000)
                if (!finalized) {
                    Log.w(TAG, "[PROT] M4 Receipt Timeout. Finalizing locally (Doubtful Block).")
                    finalizeAliceLocally(block, sigA, null, isDoubtful = true)
                }
            }
            sendWithRetry(MicroPaymentHandshake.MSG_M3_COMMIT, encrypted, MicroPaymentHandshake.MSG_M4_RECEIPT)
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M3 Generation Error: ${e.message}")
            // Rollback is handled inside sendError
            sendError(3001, "ERR-3001: M3 Commit Fail - ${e.message}")
        }
    }

    private suspend fun handleM3(plaintext: ByteArray) {
        responseDeferred?.complete(Unit)
        if (m3Received) return; m3Received = true
        val ctx = currentPaymentContext ?: return
        
        try {
            val (encryptedM4, block, sigA) = withContext(Dispatchers.Default) {
                val (alicePass, b, sA) = MicroPaymentHandshake.decodeHandoverM3(plaintext)
                
                Log.d(TAG, "[PROT] < M3: Received block #${b.counter} for ${b.amountP} paise")
                notifyProgress(PaymentPhase.AUDIT, "Auditing payment block...")

                val alicePub = KeyManager.bytesToPublicKey(HexUtils.decodeSafe(alicePass.pass.devicePubKey ?: ""))
                if (!Signer.verify(ShadowProtocol.TAG_DEBIT_BLOCK, alicePub, MicroPaymentHandshake.encodeDebitBlockData(b), sA)) {
                    throw Exception("Payment Signature Verification Fail")
                }
                
                if (!b.payeeChal.contentEquals(ctx.chalA)) {
                    throw Exception("Session Replay Protection")
                }
                
                // Credit Bob's hardware vault
                notifyProgress(PaymentPhase.DEBITING, "Finalizing hardware receipt...")
                
                // WP-FIX: UDLB - Verify Bob's linkage in the block matches his current state
                val localHead = HashChainManager.head(context, ctx.payeeId)
                val localCounter = HashChainManager.nextCounter(context, ctx.payeeId)
                
                if (b.payeeCounter != localCounter || !b.payeePrevHash!!.contentEquals(localHead)) {
                    // This could happen if a concurrent payment settled, but in P2P it's rare.
                    // We log it and proceed if we want to be permissive, or fail if we want strictness.
                    Log.w(TAG, "[PROT] UDLB Linkage Mismatch: Alice expected $localCounter, Bob at $localCounter")
                }

                // WP-FIX: Bob signs the UNIFIED block for Alice's receipt.
                val sigB = SecureKeyStore.sign(ctx.payeeId, ShadowProtocol.TAG_RECEIPT, MicroPaymentHandshake.encodeDebitBlockData(b)) ?: throw Exception("Receipt sign fail")

                // Bob (Payee) appends: aliceSig (sA) and Bob receipt sig (sigB)
                val coSignedBlock = b.copy(payeeSig = sigB)
                HashChainManager.append(context, coSignedBlock, sA, isPayer = false)
                
                QueueManager(context).addTransaction(
                    amount = b.amountP.toInt(),
                    payerId = b.walletId,
                    payeeId = b.payeeWalletId,
                    counter = b.counter,
                    payerSignature = sA,
                    payeeSignature = sigB,
                    method = "OFFLINE_RECEIVE",
                    status = QueueManager.STATUS_PROCESSED,
                    localId = ctx.sid ?: UUID.randomUUID().toString()
                )
                
                val receipt = Receipt(
                    1, 
                    ShadowProtocol.sha256(ShadowProtocol.TAG_BLOCK_HASH.toByteArray() + byteArrayOf(0x00) + MicroPaymentHandshake.encodeDebitBlockData(b)), 
                    ctx.payeeId, 
                    localCounter, 
                    localHead, 
                    ctx.chal, 
                    System.currentTimeMillis() / 1000
                )
                val encodedM4 = MicroPaymentHandshake.encodeM4(receipt, sigB)
                val encM4 = sessionChannel!!.seal(MicroPaymentHandshake.MSG_M4_RECEIPT, encodedM4)
                Triple(encM4, b, sA)
            }

            mainHandler.post { 
                notifyProgress(PaymentPhase.SUCCESS, "💸 Received ₹${block.amountP/100.0} ✓")
                
                // Bob (Payee) - Notify user immediately
                com.offlinewallet.utils.NotificationHelper.showPaymentNotification(
                    context, 
                    "💸 Payment Received", 
                    "Received ₹${block.amountP/100.0} from ${ctx.peerPass?.pass?.displayName ?: "Alice"}"
                )

                val uiReceipt = com.offlinewallet.models.Receipt(1, ByteArray(32), block.payeeWalletId, 0, ByteArray(32), block.payeeChal, System.currentTimeMillis() / 1000)
                paymentCallbacks?.onPaymentAccepted(uiReceipt) 
            }

            Log.d(TAG, "[PROT] > M4: Sending receipt co-signature...")
            sendData(byteArrayOf(MicroPaymentHandshake.MSG_M4_RECEIPT) + encryptedM4)
            
            // Bob (Payee) is done. 
            mainHandler.post { 
                paymentCallbacks?.onPaymentComplete(SecureStorage.getBalance().toInt())
                cancelPaymentTimeout()
                mainHandler.postDelayed({ stop() }, 3000)
            }
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M3 Validation/Storage Error: ${e.message}")
            sendError(3005, "ERR-3005: ${e.message}")
        }
    }

    private suspend fun handleM4(plaintext: ByteArray) {
        responseDeferred?.complete(Unit)
        if (finalized) return
        
        m4TimeoutJob?.cancel()
        m4TimeoutJob = null
        
        val ctx = currentPaymentContext ?: return
        
        try {
            withContext(Dispatchers.Default) {
                val (receipt, sigB) = MicroPaymentHandshake.decodeM4(plaintext)
                Log.d(TAG, "[PROT] < M4: Received co-signature for block #${ctx.sid}")
                
                val bobPub = ctx.peerPass?.pass?.devicePubKey?.let { KeyManager.bytesToPublicKey(HexUtils.decodeSafe(it)) }
                
                // WP-FIX: Reuse the EXACT SAME block that was sent in M3
                val block = ctx.committedBlock ?: throw Exception("Committed block missing")
                val sigA = ctx.committedSigA ?: throw Exception("Committed signature missing")
                
                if (bobPub != null) {
                    val receiptData = MicroPaymentHandshake.encodeDebitBlockData(block)
                    if (!Signer.verify(ShadowProtocol.TAG_RECEIPT, bobPub, receiptData, sigB)) {
                        Log.e(TAG, "[PROT] M4 Receipt Co-Signature Validation Failed")
                    }
                }
                finalizeAliceLocally(block, sigA, sigB)
            }
        } catch (e: Exception) {
            Log.e(TAG, "[PROT] M4 Finalization Error: ${e.message}")
            sendError(4001, "ERR-4001: M4 Process Fail - ${e.message}")
        }
    }

    private fun finalizeAliceLocally(block: DebitBlock, sigA: ByteArray, sigB: ByteArray?, isDoubtful: Boolean = false) {
        if (finalized && !isDoubtful) return; finalized = true
        scope.launch(Dispatchers.IO) {
            try {
                val coSignedBlock = block.copy(payerSig = sigA, payeeSig = sigB)
                // WP-FIX: Alice appends the co-signed block to HER history.
                // In her ledger, both sigA and sigB now match HER linearization.
                HashChainManager.append(context, coSignedBlock, sigA, sigB, isPayer = true)
                QueueManager(context).addTransaction(
                    amount = block.amountP.toInt(), payerId = block.walletId, payeeId = block.payeeWalletId,
                    counter = block.counter, payerSignature = sigA, payeeSignature = sigB ?: ByteArray(0),
                    method = "OFFLINE_SEND", status = QueueManager.STATUS_PROCESSED, localId = currentPaymentContext?.sid ?: UUID.randomUUID().toString()
                )
                withContext(Dispatchers.Main) {
                    val phase = if (isDoubtful) PaymentPhase.DOUBTFUL else PaymentPhase.SUCCESS
                    val msg = if (isDoubtful) "⚠️ Sent, but Bob disconnected. Verify manually." else "💸 Sent ₹${block.amountP/100.0} ✓"
                    
                    notifyProgress(phase, msg)
                    paymentCallbacks?.onPaymentComplete(SecureStorage.getBalance().toInt())
                    cancelPaymentTimeout()
                    mainHandler.postDelayed({ stop() }, if (isDoubtful) 8000 else 3000)
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ [CRITICAL] Failed to finalize payment: ${e.message}")
                withContext(Dispatchers.Main) {
                    notifyProgress(PaymentPhase.ERROR, "Security Conflict: ${e.message}")
                    paymentCallbacks?.onPaymentError(e.message ?: "Finalization Conflict")
                }
            }
        }
    }

    private suspend fun handleEncryptedMessage(msgType: Byte, plaintext: ByteArray) {
        when (msgType) {
            MicroPaymentHandshake.MSG_M1_INIT -> handleM1(plaintext)
            MicroPaymentHandshake.MSG_M2_AUTH -> handleM2Inverted(plaintext)
            MicroPaymentHandshake.MSG_M2_READY -> handleM2Ready()
            MicroPaymentHandshake.MSG_M3_COMMIT -> handleM3(plaintext)
            MicroPaymentHandshake.MSG_M4_RECEIPT -> handleM4(plaintext)
            MicroPaymentHandshake.MSG_PROTOCOL_ERROR -> handleRemoteError(plaintext)
        }
    }

    private fun handleRemoteError(payload: ByteArray) {
        finalized = true // Prevent any race with timeout
        m4TimeoutJob?.cancel()
        m4TimeoutJob = null
        
        try {
            val err = MicroPaymentHandshake.decodeError(payload)
            Log.e(TAG, "❌ [REMOTE_ERR] Code ${err.code}: ${err.message}")
            
            // Notify user of peer failure
            com.offlinewallet.utils.NotificationHelper.showPaymentNotification(
                context, 
                "⚠️ Transaction Aborted", 
                "Peer reported security error: ${err.message}"
            )

            notifyProgress(PaymentPhase.ERROR, "Peer reported error: ${err.message}", errorCode = "PEER-ERR-${err.code}")
            mainHandler.post { onError?.invoke(err.message); paymentCallbacks?.onPaymentError(err.message) }
            stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error decoding remote error: ${e.message}")
            sendError(7001, "Protocol breakdown")
        }
    }

    private fun handlePaymentMessage(data: ByteArray) {
        try {
            val type = data.firstOrNull() ?: return; val payload = data.copyOfRange(1, data.size)
            
            if (type == MicroPaymentHandshake.MSG_M1_INIT) {
                scope.launch { handleM1(payload) }
                return
            }

            if (type == MicroPaymentHandshake.MSG_PROTOCOL_ERROR) {
                handleRemoteError(payload)
                return
            }

            sessionChannel?.let { channel ->
                // WP-FIX: Run decryption inside coroutine but with EXPLICIT error handling
                // to prevent MAC failures from crashing the entire app.
                scope.launch {
                    try { 
                        val plaintext = channel.open(type, payload)
                        handleEncryptedMessage(type, plaintext) 
                    } catch (e: Exception) { 
                        Log.e(TAG, "❌ [CRYPTO] AEAD Open failed (likely key mismatch): ${e.message}")
                        // Tell the user why it failed instead of crashing
                        sendError(5001, "Security Handshake Failed (MAC Mismatch). Please scan again.") 
                    } 
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Protocol handling error: ${e.message}")
        }
    }

    // ==================== BLE CORE ====================

    fun startScanning(bleId: String? = null) {
        if (isScanning) return
        val now = System.currentTimeMillis()
        if (now - lastScanTime < 5000) {
            notifyProgress(PaymentPhase.DISCOVERY, "Bluetooth busy, retrying in 5s...")
            mainHandler.postDelayed({ if (!isScanning && currentPaymentContext != null) startScanning(bleId) }, 5500)
            return
        }
        lastScanTime = now
        val scanner = adapter?.bluetoothLeScanner ?: run { notifyProgress(PaymentPhase.ERROR, "Bluetooth disabled"); return }
        stopScanning(); targetBleId = bleId; isScanning = true
        
        // WP-FIX: Alice always filters by the Static Service UUID
        Log.d(TAG, "🚀 [SCAN_START] Filtering by Static UUID: $WALLET_SERVICE_UUID")
        try {
            scanner.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(WALLET_SERVICE_UUID)).build()), ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), scanCallback)
        } catch (e: Exception) { isScanning = false; notifyProgress(PaymentPhase.ERROR, "Bluetooth hardware busy") }
        scanTimeoutRunnable = Runnable { stopScanning() }
        mainHandler.postDelayed(scanTimeoutRunnable!!, 15000)
    }
    fun stopScanning() { isScanning = false; scanTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }; scanTimeoutRunnable = null; try { adapter?.bluetoothLeScanner?.stopScan(scanCallback) } catch (_: Exception) {} }
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(ct: Int, res: ScanResult) {
            val record = res.scanRecord ?: return
            
            val serviceUuids = record.serviceUuids
            if (serviceUuids != null && serviceUuids.any { it.uuid == WALLET_SERVICE_UUID }) {
                Log.d(TAG, "✅ Found device advertising Wallet Service: ${res.device.address}")
                stopScanning()
                onDeviceFound?.invoke(res.device.address)
            }
        }
        override fun onScanFailed(errorCode: Int) {
            isScanning = false
            val msg = when (errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "Scanner already running"
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "Bluetooth busy (OS Limit). Wait 5s."
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "Bluetooth LE not supported"
                6 -> "Scanning too frequently. Please wait 5s."
                else -> "Bluetooth Scan Error ($errorCode)"
            }
            notifyProgress(PaymentPhase.ERROR, msg)
            if (errorCode == 6 || errorCode == SCAN_FAILED_APPLICATION_REGISTRATION_FAILED) { onError?.invoke("OS_SCAN_THROTTLE: $msg"); stop() }
        }
    }
    fun connectToDevice(device: BluetoothDevice) { 
        Log.d(TAG, "🚀 [CONN] Initiating GATT Connection to ${device.address} (Reconnect count: $reconnectAttempts)")
        notifyProgress(PaymentPhase.CONNECTING, "Connecting to recipient...")
        
        // Reliability Fix: Some devices fail if we connect immediately after scan result
        mainHandler.postDelayed({
            Log.d(TAG, "🚀 [CONN] Calling connectGatt...")
            gatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE) 
        }, 500)
    }

    private fun reconnectAndRetry() {
        val device = gatt?.device
        Log.w(TAG, "🔁 [RETRY] Tearing down wedged session for ${device?.address}...")

        val g = gatt
        if (g != null) {
            // PRD-FIX: Refresh cache BEFORE disconnecting to ensure the stack prepares for a fresh scan
            refreshGattCache(g)
            
            pendingReconnectDevice = device
            g.disconnect()
            
            mainHandler.postDelayed({
                if (pendingReconnectDevice != null) {
                    Log.w(TAG, "⚠️ [RETRY] Disconnect confirmation timed out, forcing close anyway")
                    forceCloseAndReconnect()
                }
            }, 2000)
        } else {
            device?.let { connectToDevice(it) }
        }
    }

    private fun forceCloseAndReconnect() {
        val device = pendingReconnectDevice
        pendingReconnectDevice = null
        Log.d(TAG, "🚀 [RETRY] Forcing GATT close and re-connecting to ${device?.address}")
        
        gatt?.let { 
            refreshGattCache(it)
            try { it.close() } catch (_: Exception) {} 
        }
        gatt = null
        
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            reconnectAttempts++
            mainHandler.postDelayed({
                device?.let { connectToDevice(it) }
            }, 500)
        } else {
            Log.e(TAG, "❌ [FAIL] Reached max reconnect attempts")
            onError?.invoke("Connection failed after multiple retries.")
            stop()
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onPhyUpdate(g: BluetoothGatt, tx: Int, rx: Int, status: Int) {
            Log.d(TAG, "📡 [PHY] Update: TX=$tx, RX=$rx, Status=$status")
        }

        override fun onConnectionStateChange(g: BluetoothGatt, s: Int, ns: Int) { 
            Log.d(TAG, "🚀 [CALLBACK] onConnectionStateChange: Status=$s, NewState=$ns Device=${g.device.address}")
            if (s != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "❌ [GATT_ERROR] Connection state change failed with status: $s")
            }
            if (ns == BluetoothProfile.STATE_CONNECTED) {
                val targetUuid = currentPaymentContext?.aliceBleUuid ?: SERVICE_UUID
                Log.i(TAG, "🚀 [CONN] Connected to Bob. Target Service: $targetUuid. Discovering in 1000ms...")
                
                // WP-FIX: Removed aggressive refreshGattCache which can wedge certain stacks

                mainHandler.postDelayed({
                    if (gatt != null) {
                        val res = g.discoverServices()
                        Log.d(TAG, "🚀 [CONN] g.discoverServices() result: $res")
                    }
                }, 1000)
            } else { 
                Log.w(TAG, "🚀 [CONN] GATT Disconnected (Status $s)")
                
                if (pendingReconnectDevice != null) {
                    // This is the clean disconnect we were waiting for — now it's safe to close & reconnect
                    forceCloseAndReconnect()
                    return
                }

                if (currentPaymentContext != null && !finalized) { 
                    Log.e(TAG, "❌ [FAIL] Peer disconnected prematurely")
                    onError?.invoke("Peer disconnected"); stop() 
                }; g.close() 
            }
        }
        override fun onServicesDiscovered(g: BluetoothGatt, s: Int) {
            Log.d(TAG, "🚀 [CALLBACK] onServicesDiscovered: Status=$s")
            if (s != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "❌ [GATT_ERROR] Service discovery failed with status: $s")
                reconnectAndRetry()
                return
            }
            
            Log.d(TAG, "🔍 Searching for Static Service: $WALLET_SERVICE_UUID")

            val service = g.getService(WALLET_SERVICE_UUID)
            if (service == null) {
                Log.e(TAG, "❌ [FAIL] Static Service $WALLET_SERVICE_UUID not found.")
                g.services.forEach { Log.v(TAG, "Found: ${it.uuid}") }
                reconnectAndRetry()
                return
            }

            val char = service.getCharacteristic(CHAR_UUID)
            if (char == null) {
                Log.e(TAG, "❌ [FAIL] Characteristic $CHAR_UUID not found.")
                reconnectAndRetry()
                return
            }
            
            // WP-FIX: Cache the characteristic NOW while we have it.
            payerTargetChar = char
            Log.d(TAG, "✅ Service & Characteristic cached. Negotiating High-Speed MTU...")
            notifyProgress(PaymentPhase.CONNECTING, "Service discovered. Optimizing speed...")

            // WP-FIX: RE-ENABLING MTU request for production speed
            mainHandler.postDelayed({
                if (!mtuReady && gatt != null) {
                    Log.w(TAG, "⚠️ [TIMEOUT] onMtuChanged timed out. Starting subscription anyway.")
                    mtuReady = true
                    initiateSubscription()
                }
            }, 3000)
            
            g.requestMtu(517) // Request maximum MTU for high-speed transfer
        }

        private fun initiateSubscription() {
            val char = payerTargetChar
            if (char != null && gatt != null) {
                Log.d(TAG, "🚀 [STEP 8.5] Initiating notification subscription for ${char.uuid}...")
                val notifyRes = gatt?.setCharacteristicNotification(char, true)
                Log.d(TAG, "🚀 [CONN] setCharacteristicNotification result: $notifyRes")
                
                val descriptor = char.getDescriptor(CLIENT_CHARACTERISTIC_CONFIG)
                if (descriptor != null) {
                    descriptorWriteAttempts = 0
                    
                    val res = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                        gatt?.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
                    } else {
                        descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        gatt?.writeDescriptor(descriptor) == true
                    }
                    
                    Log.d(TAG, "🚀 [CONN] CCC Descriptor Write Initiated: $res (Descriptor UUID: ${descriptor.uuid})")
                    scheduleDescriptorRetry()
                } else {
                    Log.e(TAG, "❌ [CONN] CCC Descriptor (0x2902) not found! Scanning all descriptors...")
                    char.descriptors.forEach { Log.v(TAG, "Available Descriptor: ${it.uuid}") }
                }
            }
        }

        private fun scheduleDescriptorRetry() {
            descriptorTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
            descriptorTimeoutRunnable = Runnable {
                if (descriptorWriteAttempts < MAX_DESCRIPTOR_ATTEMPTS) {
                    descriptorWriteAttempts++
                    Log.w(TAG, "🚀 [RETRY] Descriptor write silent failure (Attempt $descriptorWriteAttempts). Re-writing...")
                    
                    val char = payerTargetChar
                    val descriptor = char?.getDescriptor(CLIENT_CHARACTERISTIC_CONFIG)
                    if (gatt != null && descriptor != null) {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                            gatt?.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                        } else {
                            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                            gatt?.writeDescriptor(descriptor)
                        }
                        scheduleDescriptorRetry()
                    }
                } else {
                    Log.e(TAG, "❌ [FAIL] Descriptor write failed after $MAX_DESCRIPTOR_ATTEMPTS attempts. Reconnecting...")
                    reconnectAndRetry()
                }
            }
            mainHandler.postDelayed(descriptorTimeoutRunnable!!, 5000)
        }

        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (descriptor.uuid == CLIENT_CHARACTERISTIC_CONFIG) {
                descriptorTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }; descriptorTimeoutRunnable = null

                Log.d(TAG, "🚀 [CALLBACK] onDescriptorWrite: Status=$status")
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    Log.d(TAG, "✅ [CONN] Subscribed to Bob successfully. Starting handshake...")
                    notifyProgress(PaymentPhase.IDENTITY, "Linking hardware wallets...")
                    
                    mainHandler.postDelayed({
                        Log.d(TAG, "🚀 [STEP 9] Triggering M1 Handshake")
                        scope.launch { sendM1Handshake() }
                    }, 500)
                } else {
                    Log.e(TAG, "❌ [CONN] Subscription Failed with status $status. Retrying...")
                    if (descriptorWriteAttempts < MAX_DESCRIPTOR_ATTEMPTS) {
                        descriptorWriteAttempts++
                        mainHandler.postDelayed({
                            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                            g.writeDescriptor(descriptor)
                            scheduleDescriptorRetry()
                        }, 1000)
                    } else {
                        onError?.invoke("Failed to enable notifications (GATT Error $status).")
                        stop()
                    }
                }
            }
        }

        private fun waitForMtuAndSendM1() {
            if (mtuReady) {
                mainHandler.postDelayed({
                    Log.d(TAG, "🚀 [STEP 9] MTU Ready, triggering M1 Handshake")
                    scope.launch { sendM1Handshake() }
                }, 500)
            } else {
                Log.d(TAG, "⏳ Waiting for MTU callback...")
                val waitStart = System.currentTimeMillis()
                val poller = object : Runnable {
                    override fun run() {
                        if (mtuReady || System.currentTimeMillis() - waitStart > 3000) {
                            if (!mtuReady) Log.w(TAG, "⚠️ Proceeding with default MTU (Timeout)")
                            mainHandler.postDelayed({
                                Log.d(TAG, "🚀 [STEP 9] Triggering M1 Handshake (MTU Settled)")
                                scope.launch { sendM1Handshake() }
                            }, 500)
                        } else {
                            mainHandler.postDelayed(this, 200)
                        }
                    }
                }
                mainHandler.post(poller)
            }
        }

        override fun onMtuChanged(g: BluetoothGatt?, m: Int, s: Int) { 
            Log.i(TAG, "✅ MTU changed to: $m (status: $s)")
            currentMtu = if (s == BluetoothGatt.GATT_SUCCESS) m else 23
            
            if (mtuReady) return
            mtuReady = true
            
            // WP-FIX: Use the cached characteristic directly. 
            Log.d(TAG, "🚀 [STEP 8.2] MTU Settled ($m bytes). Subscribing in 1000ms...")
            
            notifyProgress(PaymentPhase.CONNECTING, "Channel secured. Synchronizing data...")
            mainHandler.postDelayed({ initiateSubscription() }, 1000)
        }
        override fun onCharacteristicWrite(g: BluetoothGatt?, c: BluetoothGattCharacteristic?, status: Int) { 
            isWriting = false
            Log.d(TAG, "✅ Characteristic write status: $status")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                mainHandler.post { sendNextChunk() } 
            } else {
                Log.e(TAG, "❌ Write failed (status $status), retrying chunk in 200ms...")
                mainHandler.postDelayed({ sendNextChunk() }, 200)
            }
        }
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) { handleIncomingChunk(c.value) }
    }

    fun startAdvertising(bleId: String? = null) {
        if (isScanning) stopScanning()
        
        // PRD-FIX: ALWAYS stop previous advertising to prevent SID crosstalk
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (_: Exception) {}

        // PRD-FIX: Prevent redundant advertiser restarts for SAME SID
        if (bleId != null && bleId == currentAdvertisingSid) {
            Log.d(TAG, "Already advertising SID $bleId, skipping...")
            return
        }
        currentAdvertisingSid = bleId
        
        // PRD-FIX: Guard delay after stopping old advertiser
        mainHandler.postDelayed({
            executeStartAdvertising(bleId)
        }, 200)
    }

    private fun executeStartAdvertising(bleId: String?) {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW) 
            .build()
            
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(WALLET_SERVICE_UUID))
            .build()
            
        val scanRes = AdvertiseData.Builder()
            // Service Data removed for isolation
            .build()
            
        val advertiser = adapter?.bluetoothLeAdvertiser ?: run {
            Log.e(TAG, "Bluetooth Advertiser not available (Check if BLE is enabled)")
            notifyProgress(PaymentPhase.ERROR, "BLE Advertising Not Supported")
            return
        }
        
        logUuid("ADVERTISE_START")
        try {
            advertiser.startAdvertising(settings, data, scanRes, advertiseCallback)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start advertising: ${e.message}")
            notifyProgress(PaymentPhase.ERROR, "Hardware busy (BLE)")
        }
    }

    private var serviceRegistrationTimeoutRunnable: Runnable? = null
    private val REGISTRATION_TIMEOUT = 10000L // Increased to 10s for slower devices
    private var registrationRetryCount = 0
    private val MAX_REGISTRATION_RETRIES = 3

    private fun setupGattServer() { 
        Log.d(TAG, "Opening GATT Server (Attempt ${registrationRetryCount + 1})...")
        
        serviceRegistrationTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
        
        // WP-FIX: Reuse existing server if available to prevent serverIf leaks
        if (sharedGattServer != null) {
            Log.d(TAG, "Reusing existing GATT server instance.")
            gattServer = sharedGattServer
            
            // Check if our service is already there
            val existingSvc = gattServer?.getService(WALLET_SERVICE_UUID)
            if (existingSvc != null) {
                Log.d(TAG, "Service already registered. Jumping to Advertising.")
                registrationRetryCount = 0
                val sidPrefix = currentPaymentContext?.sid?.take(6)
                startAdvertising(sidPrefix)
                notifyProgress(PaymentPhase.DISCOVERY, "Waiting for Alice to connect...")
                return
            }
        } else {
            sharedGattServer = bluetoothManager.openGattServer(context, gattServerCallback)
            gattServer = sharedGattServer
        }

        if (gattServer == null) {
            Log.e(TAG, "CRITICAL: Could not open GATT Server. Bluetooth might be off or stack exhausted.")
            if (registrationRetryCount < MAX_REGISTRATION_RETRIES) {
                registrationRetryCount++
                mainHandler.postDelayed({ setupGattServer() }, 2000)
            } else {
                notifyProgress(PaymentPhase.ERROR, "Bluetooth hardware failure. Please toggle Bluetooth.")
            }
            return
        }
        
        val s = BluetoothGattService(WALLET_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val c = BluetoothGattCharacteristic(CHAR_UUID, 
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY, 
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE)
            
        val d = BluetoothGattDescriptor(CLIENT_CHARACTERISTIC_CONFIG,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE)
        c.addDescriptor(d)
        s.addCharacteristic(c)
        
        // WP-FIX: Increased watchdog to 10s and added retry logic
        serviceRegistrationTimeoutRunnable = Runnable {
            if (registrationRetryCount < MAX_REGISTRATION_RETRIES) {
                registrationRetryCount++
                Log.e(TAG, "❌ [TIMEOUT] GATT registration HUNG. Resetting server...")
                sharedGattServer?.close()
                sharedGattServer = null
                mainHandler.postDelayed({ setupGattServer() }, 2000)
            } else {
                Log.e(TAG, "❌ [FATAL] GATT registration failed after $MAX_REGISTRATION_RETRIES retries.")
                notifyProgress(PaymentPhase.ERROR, "Bluetooth stack frozen. Restart Bluetooth.")
            }
        }
        mainHandler.postDelayed(serviceRegistrationTimeoutRunnable!!, REGISTRATION_TIMEOUT)

        mainHandler.postDelayed({
            try {
                if (gattServer != null) {
                    val res = gattServer?.addService(s)
                    Log.d(TAG, "GATT Service addService() result: $res")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Exception in addService: ${e.message}")
            }
        }, 1000) 
    }

    private val advertiseCallback = object : AdvertiseCallback() { 
        override fun onStartSuccess(s: AdvertiseSettings?) { Log.d(TAG, "✅ BLE Advertising Active") }
        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "❌ BLE Advertising Failed: $errorCode")
            val msg = when(errorCode) {
                ADVERTISE_FAILED_ALREADY_STARTED -> "Already advertising"
                ADVERTISE_FAILED_DATA_TOO_LARGE -> "Advertise data too large"
                ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "BLE Advertising not supported"
                ADVERTISE_FAILED_INTERNAL_ERROR -> "Bluetooth internal error"
                ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "Too many advertisers"
                else -> "Error code $errorCode"
            }
            notifyProgress(PaymentPhase.ERROR, "Discovery fail: $msg")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onPhyUpdate(device: BluetoothDevice, tx: Int, rx: Int, status: Int) {
            Log.d(TAG, "🔍 [SERVER_PHY] Update: ${device.address}, TX=$tx, RX=$rx, Status=$status")
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            Log.d(TAG, "🔍 [SERVER] onServiceAdded: Status=$status, UUID=${service.uuid}, InstanceId=${service.instanceId}")
            
            // WP-FIX: Reset retry counters and cancel watchdog on success
            registrationRetryCount = 0
            serviceRegistrationTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
            serviceRegistrationTimeoutRunnable = null

            if (status == BluetoothGatt.GATT_SUCCESS && service.uuid == WALLET_SERVICE_UUID) {
                val sidPrefix = currentPaymentContext?.sid?.take(6)
                Log.d(TAG, "🔍 [STEP 6] Service Registered. Starting Advertising for SID Prefix: $sidPrefix")
                startAdvertising(sidPrefix)
                notifyProgress(PaymentPhase.DISCOVERY, "Waiting for Alice to connect...")
            } else if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "❌ [SERVER] Service Registration Failed: $status")
                sendError(5002, "GATT Server registration failed")
            }
        }

        override fun onConnectionStateChange(d: BluetoothDevice, s: Int, ns: Int) { 
            Log.d(TAG, "🔍 [SERVER] Connection State Change: ${d.address}, Status=$s, NewState=$ns")
            connectedDevice = if (ns == BluetoothProfile.STATE_CONNECTED) d else null
            if (ns == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "🔍 [SERVER] Alice (Payer) connected: ${d.address}")
                notifyProgress(PaymentPhase.CONNECTING, "Payer connected. Linking wallets...")
            }
            if (ns == BluetoothProfile.STATE_DISCONNECTED) { 
                Log.w(TAG, "🔍 [SERVER] Client disconnected")
                subscriptionMap.remove(d)
                if (currentPaymentContext != null && !finalized) { 
                    Log.e(TAG, "❌ [FAIL] Client disconnected before finishing payment")
                    onError?.invoke("Peer disconnected")
                    stop() 
                } 
            }
        }
        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            Log.d(TAG, "🔍 [SERVER] Descriptor Write Request from ${device.address}. UUID: ${descriptor.uuid}")
            
            // WP-FIX: Send response IMMEDIATELY before processing logic to avoid GATT timeout
            if (responseNeeded) {
                val res = gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                Log.d(TAG, "🔍 [SERVER] Descriptor Response Sent: $res (reqId: $requestId)")
            }

            if (descriptor.uuid == CLIENT_CHARACTERISTIC_CONFIG) {
                val subscribed = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                subscriptionMap[device] = subscribed
                Log.d(TAG, "🔍 [SERVER] Client Subscribed=$subscribed. Ready for M1.")
                if (subscribed) {
                    notifyProgress(PaymentPhase.IDENTITY, "Secure link established. Auditing payer...")
                }
            }
        }
        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) { 
            Log.d(TAG, "🔍 [SERVER] Characteristic Write Request: ${value.size} bytes. Handing to reassembler.")
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
            }
            handleIncomingChunk(value) 
        }
        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            Log.d(TAG, "🔍 [SERVER] MTU changed for ${device.address}: $mtu")
            currentMtu = mtu // WP-FIX: Bob also needs to know the MTU to send large chunks fast
        }

        override fun onNotificationSent(d: BluetoothDevice, s: Int) { 
            Log.d(TAG, "🔍 [SERVER] Notification sent to ${d.address}, Status=$s")
            isWriting = false; if (s == 0) mainHandler.post { sendNextChunk() } 
        }
    }

    fun sendData(data: ByteArray) { val chunks = chunkData(data); pendingWriteQueue.clear(); pendingWriteQueue.addAll(chunks); isWriting = false; sendNextChunk() }
    private fun sendNextChunk() {
        if (isWriting || pendingWriteQueue.isEmpty()) return
        val chunk = pendingWriteQueue.removeAt(0)
        isWriting = true
        
        Log.d(TAG, "Sending chunk (${chunk.size} bytes)...")
        val success = if (gatt != null && payerTargetChar != null) {
            val props = payerTargetChar?.properties ?: 0
            if (props and BluetoothGattCharacteristic.PROPERTY_WRITE == 0) {
                Log.e(TAG, "Characteristic does not support WRITE!")
            }

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                gatt?.writeCharacteristic(payerTargetChar!!, chunk, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                payerTargetChar?.value = chunk
                @Suppress("DEPRECATION")
                gatt?.writeCharacteristic(payerTargetChar) == true
            }
        } 
        else if (gattServer != null && connectedDevice != null) { 
            if (subscriptionMap[connectedDevice] == true) { 
                val c = gattServer?.getService(SERVICE_UUID)?.getCharacteristic(CHAR_UUID)
                c?.value = chunk
                val res = gattServer?.notifyCharacteristicChanged(connectedDevice, c, false) == true 
                Log.d(TAG, "gattServer.notify: $res")
                res
            } 
            else { Log.w(TAG, "Device not subscribed, delaying notify..."); isWriting = false; false }
        } else { Log.e(TAG, "No gatt or server to send!"); isWriting = false; false }
        
        if (!success) { 
            Log.e(TAG, "Write rejected by OS (likely MTU or busy). Retrying...")
            isWriting = false
            mainHandler.postDelayed({ sendNextChunk() }, 200) 
        }
    }
    private fun handleIncomingChunk(v: ByteArray) {
        if (v.isEmpty()) return
        synchronized(chunkMap) {
            when (v[0]) {
                0x01.toByte() -> {
                    chunkMap.clear()
                    dispatchFullMessage(v.copyOfRange(1, v.size))
                }
                0x00.toByte() -> {
                    if (v.size >= 3) {
                        val total = v[1].toInt() and 0xFF
                        val index = v[2].toInt() and 0xFF
                        val payload = v.copyOfRange(3, v.size)

                        // If index 0, this is a new message start
                        if (index == 0) {
                            chunkMap.clear()
                            expectedChunks = total
                        }

                        // Store chunk
                        chunkMap[index] = payload

                        // Check if we have all chunks
                        if (chunkMap.size >= expectedChunks && (0 until expectedChunks).all { chunkMap.containsKey(it) }) {
                            val bos = java.io.ByteArrayOutputStream()
                            for (i in 0 until expectedChunks) {
                                bos.write(chunkMap[i]!!)
                            }
                            chunkMap.clear()
                            dispatchFullMessage(bos.toByteArray())
                        }
                    }
                }
                else -> if (v[0].toInt() in 1..8) scope.launch { handlePaymentMessage(v) }
            }
        }
    }
    private fun dispatchFullMessage(d: ByteArray) { 
        try {
            if (d.isNotEmpty() && d[0].toInt() in 1..8) scope.launch { handlePaymentMessage(d) } 
            else mainHandler.post { onDataReceived?.invoke(d) } 
        } catch (e: Exception) {
            Log.e(TAG, "Full message dispatch error: ${e.message}")
        }
    }
    private fun chunkData(d: ByteArray): List<ByteArray> {
        // PRD-FIX: Increased safe chunk size for high MTU performance
        // Overhead: 1 (Header) + 1 (Total) + 1 (Index) = 3 bytes
        val safeMtu = if (currentMtu > 23) currentMtu - 10 else 16
        
        if (d.size <= safeMtu) return listOf(byteArrayOf(0x01) + d)
        val chunks = mutableListOf<ByteArray>()
        val total = (d.size + safeMtu - 1) / safeMtu
        for (i in 0 until total) {
            val start = i * safeMtu
            val end = minOf((i + 1) * safeMtu, d.size)
            // Packet: [Header(1)] [Total(1)] [Index(1)] [Data]
            chunks.add(byteArrayOf(0x00, total.toByte(), i.toByte()) + d.copyOfRange(start, end))
        }
        return chunks
    }
    private fun startPaymentTimeout() { cancelPaymentTimeout(); paymentTimeoutRunnable = Runnable { stop() }; mainHandler.postDelayed(paymentTimeoutRunnable!!, 90000) }
    private fun cancelPaymentTimeout() { paymentTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }; paymentTimeoutRunnable = null }
    private fun notifyProgress(phase: PaymentPhase, message: String, errorCode: String? = null) {
        val ctx = currentPaymentContext
        val pName = ctx?.peerPass?.pass?.displayName
        val amt = ctx?.amount?.toLong()
        val initials = pName?.take(1)?.uppercase()
        val pId = if (isPayerRole) ctx?.payeeId else ctx?.payerId

        onPhaseChanged?.invoke(PaymentSessionProgress(
            phase = phase,
            message = message,
            errorCode = errorCode,
            peerName = pName,
            peerId = pId,
            amountP = amt,
            payeeInitials = initials,
            isPayer = isPayerRole
        ))
    }

    private fun sendError(c: Int, m: String) { 
        Log.e(TAG, "🚨 Sending Protocol Error $c: $m")
        notifyProgress(PaymentPhase.ERROR, m, errorCode = "ERR-$c")
        
        currentPaymentContext?.let { scope.launch(Dispatchers.IO) { 
            // Alice: Rollback local reserve if applicable
            try { BucketManager(context).rollbackReservedFunds(it.payerId, it.amount.toLong()) } catch (_: Exception) {}
            
            // Try to notify peer of the failure reason
            try {
                val err = MicroPaymentHandshake.ProtocolError(c, m)
                val encoded = MicroPaymentHandshake.encodeError(err)
                val payload = byteArrayOf(MicroPaymentHandshake.MSG_PROTOCOL_ERROR) + encoded
                sendData(payload)
                delay(1000) // Wait for GATT write to complete
            } catch (_: Exception) {}
            
            withContext(Dispatchers.Main) { stop() }
        } } ?: run {
            mainHandler.post { onError?.invoke(m); paymentCallbacks?.onPaymentError(m) }
            stop() 
        }
    }
    private fun refreshGattCache(gatt: BluetoothGatt): Boolean {
        return try {
            val method = gatt.javaClass.getMethod("refresh")
            val res = method.invoke(gatt) as Boolean
            Log.d(TAG, "GATT Cache Refresh Result: $res")
            res
        } catch (e: Exception) {
            Log.e(TAG, "GATT cache refresh failed: ${e.message}")
            false
        }
    }

    fun stop() { 
        m4TimeoutJob?.cancel()
        m4TimeoutJob = null
        
        // WP-FIX: Proactive Rollback on manual stop if we have reserved funds but haven't sent M3 yet
        currentPaymentContext?.let { ctx ->
            if (m3Sent == false && ctx.amount > 0) {
                Log.w(TAG, "🛑 Session stopped before M3 sent. Rolling back ${ctx.amount} reserved paise.")
                scope.launch(Dispatchers.IO) {
                    try { BucketManager(context).rollbackReservedFunds(ctx.payerId, ctx.amount.toLong()) } catch (_: Exception) {}
                }
            }
        }

        currentPaymentContext?.erase(); sessionChannel?.erase(); stopScanning()
        currentAdvertisingSid = null
        SERVICE_UUID = WALLET_SERVICE_UUID
        registrationRetryCount = 0
        
        serviceRegistrationTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }
        serviceRegistrationTimeoutRunnable = null

        mtuReady = false; descriptorWriteAttempts = 0; discoveryRetryAttempts = 0; reconnectAttempts = 0; isFirstConnection = true
        pendingReconnectDevice = null
        descriptorTimeoutRunnable?.let { mainHandler.removeCallbacks(it) }; descriptorTimeoutRunnable = null
        
        // WP-FIX: Do NOT close the sharedGattServer here.
        // We only disconnect the gatt (client) and stop advertising.
        try { 
            advertiser?.stopAdvertising(advertiseCallback)
            gatt?.disconnect()
            gatt?.close() 
        } catch (_: Exception) {}
        gatt = null; connectedDevice = null; pendingWriteQueue.clear(); isWriting = false; currentPaymentContext = null; sessionChannel = null; m3Sent = false 
    }
}
