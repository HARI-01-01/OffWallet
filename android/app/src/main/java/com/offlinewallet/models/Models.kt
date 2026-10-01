package com.offlinewallet.models

import com.google.gson.annotations.SerializedName

// ---------- Protocol v1 Structures ----------

data class DebitBlock(
    @SerializedName("v") val v: Int,
    @SerializedName("chain_id") val chainId: String,
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("counter") val counter: Long,
    @SerializedName("prev_hash") val prevHash: ByteArray,
    @SerializedName("amount_p") val amountP: Long,
    @SerializedName("payee_pubkey_hash") val payeePubKeyHash: ByteArray,
    @SerializedName("payee_wallet_id") val payeeWalletId: String,
    @SerializedName("payee_chal") val payeeChal: ByteArray,
    @SerializedName("payer_pass_id") val payerPassId: String,
    @SerializedName("payee_pass_id") val payeePassId: String,
    @SerializedName("genesis_epoch") val genesisEpoch: Long,
    @SerializedName("ts") val ts: Long,
    @SerializedName("payee_counter") val payeeCounter: Long? = null,
    @SerializedName("payee_prev_hash") val payeePrevHash: ByteArray? = null,
    @SerializedName("payer_sig") var payerSig: ByteArray? = null,
    @SerializedName("payee_sig") var payeeSig: ByteArray? = null
)

data class Receipt(
    val v: Int,
    val blockHash: ByteArray,
    val payeeWalletId: String,
    val payeeCounter: Long,
    val payeePrevHash: ByteArray,
    val payerChal: ByteArray,
    val ts: Long
)

data class Ack(
    val v: Int,
    val receiptHash: ByteArray
)

// ---------- Registration (v1) ----------

data class UserRegisterRequest(
    @SerializedName("wallet_name") val walletName: String
)

data class UserRegisterResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("attest_challenge") val attestChallenge: String,
    @SerializedName("challenge_expires_at") val challengeExpiresAt: Long,
    @SerializedName("ephemeral_server_pubkey") val ephemeralServerPubKey: String,
    @SerializedName("server_spki_hash") val serverSpkiHash: String
)

data class ServerPassKey(
    @SerializedName("kid") val kid: String,
    @SerializedName("alg") val alg: String,
    @SerializedName("pub") val pub: String
)

// ---------- Activate (v1) ----------

data class ActivateRequest(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("device_pubkey") val devicePubKey: String,
    @SerializedName("attestation_chain") val attestationChain: List<String>,
    @SerializedName("integrity_token") val integrityToken: String,
    @SerializedName("encrypted_aes_key") val encryptedAesKey: String,
    @SerializedName("device_label") val deviceLabel: String
)

data class ActivateResponse(
    @SerializedName("genesis") val genesis: GenesisData,
    @SerializedName("kid") val kid: String,
    @SerializedName("sig") val sig: String,
    @SerializedName("server_public_key") val serverPublicKey: String? = null,
    @SerializedName("active_device_token") val activeDeviceToken: String,
    @SerializedName("device_id") val deviceId: String,
    @SerializedName("recovery_shard_1") val recoveryShard1: String? = null
)

data class GenesisData(
    @SerializedName("v") val v: Int,
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("device_pubkey_hash") val devicePubKeyHash: String,
    @SerializedName("balance_p") val balanceP: Long,
    @SerializedName("counter") val counter: Long,
    @SerializedName("genesis_epoch") val genesisEpoch: Long,
    @SerializedName("issued_at") val issuedAt: Long,
    @SerializedName("server_seq") val serverSeq: Long
)

// ---------- Login ----------

data class UserLoginRequest(
    @SerializedName("email") val email: String,
    @SerializedName("password") val password: String
)

data class UserLoginResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("email") val email: String,
    @SerializedName("wallet_name") val walletName: String,
    @SerializedName("balance") val balance: Long,
    @SerializedName("counter") val counter: Long = 0L,
    @SerializedName("status") val status: String,
    @SerializedName("public_key") val publicKey: String? = null,
    @SerializedName("private_key") val privateKey: String? = null,
    @SerializedName("aes_key") val aesKey: String? = null,
    @SerializedName("server_public_key") val serverPublicKey: String? = null,
    @SerializedName("server_signature") val serverSignature: String? = null,
    @SerializedName("dev_token") val devToken: String? = null,
    @SerializedName("firebase_token") val firebaseToken: String? = null,
    @SerializedName("qr_data") val qrData: String? = null,
    @SerializedName("qr_name") val qrName: String? = null,
    @SerializedName("keys_provided") val keysProvided: Boolean = false,
    @SerializedName("message") val message: String? = null
)

// ---------- Security Pass (v1) ----------

data class Pass(
    @SerializedName("v") val v: Int,
    @SerializedName("kid") val kid: String,
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("display_name") val displayName: String,
    @SerializedName("device_pubkey_hash") val devicePubKeyHash: String,
    @SerializedName("device_pubkey") val devicePubKey: String? = null,
    @SerializedName("attest_tier") val attestTier: String,
    @SerializedName("per_tx_cap_p") val perTxCapP: Long,
    @SerializedName("aggregate_cap_p") val aggregateCapP: Long,
    @SerializedName("txn_count_cap") val txnCountCap: Long,
    @SerializedName("recv_unsettled_cap_p") val recvUnsettledCapP: Long,
    @SerializedName("recv_per_peer_cap_p") val recvPerPeerCapP: Long,
    @SerializedName("pass_id") val passId: String,
    @SerializedName("server_seq") val serverSeq: Long,
    @SerializedName("issued_at") val issuedAt: Long,
    @SerializedName("expires_at") val expiresAt: Long,
    @SerializedName("genesis_epoch") val genesisEpoch: Long,
    @SerializedName("last_settled_counter") val lastSettledCounter: Long,
    @SerializedName("last_settled_head") val lastSettledHead: String
)

data class PassEnvelope(
    @SerializedName("pass") val pass: Pass,
    @SerializedName("sig") val sig: String
)

// ---------- QR ----------

data class V1QR(
    @SerializedName("v") val v: Int,
    @SerializedName("pass") val pass: PassEnvelope,
    @SerializedName("sid") val sid: String,
    @SerializedName("epk_B") val epk_B: String,
    @SerializedName("chal_B") val chal_B: String,
    @SerializedName("ble_uuid") val bleUuid: String,
    @SerializedName("amount_p") val amountP: Long? = null,
    @SerializedName("history") val history: List<DebitBlock> = emptyList()
)

data class QRCodeData(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("name") val name: String,
    @SerializedName("public_key") val publicKeyHex: String? = null,
    @SerializedName("amount") val amount: Int = 0,
    @SerializedName("timestamp") val timestamp: Long = System.currentTimeMillis() / 1000,
    @SerializedName("ble_id") val bleId: String? = null,
    @SerializedName("bt_name") val btName: String? = null,
    @SerializedName("type") val type: String = "payment_request",
    @SerializedName("version") val version: String = "1.0"
)

// ---------- Legacy Nonce (For compatibility) ----------

data class NonceRequest(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("device_id") val deviceId: String
)

data class NonceResponse(
    @SerializedName("nonce_id") val nonceId: String,
    @SerializedName("nonce_value") val nonceValue: String,
    @SerializedName("sequence_number") val sequenceNumber: Int,
    @SerializedName("server_signature") val serverSignature: String,
    @SerializedName("expires_at") val expiresAt: Long
)

// ---------- Sync ----------

data class SyncTransactionItem(
    @SerializedName("block") val block: DebitBlock,
    @SerializedName("sig") val sig: String,
    @SerializedName("local_id") val localId: String? = null
)

data class OfflineSyncRequest(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("transactions") val transactions: List<SyncTransactionItem>,
    @SerializedName("integrity_token") val integrityToken: String? = null,
    @SerializedName("device_pubkey_hash") val devicePubKeyHash: String? = null
)

data class OfflineSyncResponse(
    @SerializedName("synced_count") val syncedCount: Int,
    @SerializedName("failed_count") val failedCount: Int,
    @SerializedName("results") val results: List<SyncResultItem>,
    @SerializedName("message") val message: String? = null,
    @SerializedName("new_pass") val newPass: PassEnvelope? = null
)

data class SyncResultItem(
    @SerializedName("local_id", alternate = ["localId"]) val localId: String,
    @SerializedName("status") val status: String,
    @SerializedName("balance_after", alternate = ["balanceAfter"]) val balanceAfter: Int? = null,
    @SerializedName("payee_signature", alternate = ["payeeSignature"]) val payeeSignature: String? = null
)

// ---------- Common ----------

data class ApiResponse<T>(
    @SerializedName("status") val status: String,
    @SerializedName("data") val data: T? = null,
    @SerializedName("error") val error: String? = null,
    @SerializedName("message") val message: String? = null,
    @SerializedName("detail") val detail: String? = null 
)

data class OnlinePaymentResult(
    val success: Boolean,
    val message: String,
    val transactionId: String = "",
    val balanceAfter: Int = 0
)

data class BucketStatusResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("status") val status: String,
    @SerializedName("expires_at") val expiresAt: Long,
    @SerializedName("genesis_epoch") val genesisEpoch: Int = 1
)

data class BucketTopupRequest(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("amount") val amount: Int
)

data class BucketTopupResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("lite_balance_after") val balance: Long,
    @SerializedName("lite_counter") val counter: Long,
    @SerializedName("lite_server_signature") val serverSignature: String,
    @SerializedName("main_balance_after") val mainBalanceAfter: Long,
    @SerializedName("expires_at") val expiresAt: Long,
    @SerializedName("issued_at") val issuedAt: Long? = null,
    @SerializedName("server_public_key") val serverPublicKey: String? = null,
    @SerializedName("prev_hash") val prevHash: String? = null
)

data class SendPaymentRequest(
    @SerializedName("payer_id") val payerId: String,
    @SerializedName("payee_id") val payeeId: String,
    @SerializedName("amount") val amount: Int,
    @SerializedName("payer_signature") val payerSignature: String,
    @SerializedName("memo") val memo: String? = null
)

data class SendPaymentResponse(
    @SerializedName("local_id") val localId: String,
    @SerializedName("amount") val amount: Int,
    @SerializedName("payer_id") val payerId: String,
    @SerializedName("payee_id") val payeeId: String,
    @SerializedName("payer_balance_after") val payerBalanceAfter: Int,
    @SerializedName("payee_balance_after") val payeeBalanceAfter: Int,
    @SerializedName("message") val message: String
)

data class UserLookupResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("email") val email: String,
    @SerializedName("phone") val phone: String? = null,
    @SerializedName("full_name") val fullName: String? = null,
    @SerializedName("wallet_name") val walletName: String,
    @SerializedName("status") val status: String
)

data class QRCodeResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("name") val name: String,
    @SerializedName("qr_data") val qrData: String,
    @SerializedName("type") val type: String
)

data class VerifyTokenRequest(
    @SerializedName("firebase_token") val firebaseToken: String
)

data class VerifyTokenResponse(
    @SerializedName("uid") val uid: String? = null,
    @SerializedName("email") val email: String? = null,
    @SerializedName("email_verified") val emailVerified: Boolean = false,
    @SerializedName("firebase_verified") val firebaseVerified: Boolean = false,
    @SerializedName("expires_at") val expiresAt: String? = null,
    @SerializedName("message") val message: String? = null
)

data class TransactionHistoryResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("transactions") val transactions: List<TransactionItem>,
    @SerializedName("count") val count: Int
)

data class TransactionItem(
    @SerializedName("local_id") val localId: String,
    @SerializedName("amount") val amount: Int,
    @SerializedName("payer_id") val payerId: String,
    @SerializedName("payee_id") val payeeId: String,
    @SerializedName("status") val status: String,
    @SerializedName("timestamp") val timestamp: Long
)

data class Transaction(
    val localId: String,
    val amount: Int,
    val payerId: String,
    val payeeId: String,
    val timestamp: Long,
    val status: String,
    val counter: Long,
    val method: String,
    val payerSignature: ByteArray? = null,
    val payeeSignature: ByteArray? = null
)

data class UploadTransactionRequest(
    @SerializedName("local_id") val localId: String,
    @SerializedName("amount") val amount: Long,
    @SerializedName("payer_id") val payerId: String,
    @SerializedName("payee_id") val payeeId: String,
    @SerializedName("counter") val counter: Long,
    @SerializedName("timestamp") val timestamp: Long,
    @SerializedName("payer_signature") val payerSignature: String,
    @SerializedName("payee_signature") val payeeSignature: String,
    @SerializedName("device_id") val deviceId: String,
    @SerializedName("api_key") val apiKey: String,
    @SerializedName("method") val method: String = "OFFLINE",
    @SerializedName("nonce_value") val nonceValue: String? = null,
    @SerializedName("prev_block_hash") val prevBlockHash: String? = null,
    @SerializedName("block_hash") val blockHash: String? = null
)

data class UploadTransactionResponse(
    @SerializedName("status") val status: String,
    @SerializedName("local_id") val localId: String? = null,
    @SerializedName("message") val message: String? = null
)

data class VerifyResponse(
    @SerializedName("valid") val valid: Boolean,
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("expires_at") val expiresAt: Long
)

data class BalanceResponse(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("balance") val balance: Long
)

data class TamperReportRequest(
    @SerializedName("wallet_id") val walletId: String,
    @SerializedName("reason") val reason: String,
    @SerializedName("apk_hash") val apkHash: String,
    @SerializedName("device_id") val deviceId: String
)
