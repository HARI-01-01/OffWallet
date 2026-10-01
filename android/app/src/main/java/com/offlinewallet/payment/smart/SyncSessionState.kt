package com.offlinewallet.payment.smart

enum class SyncPhase {
    PREPARING,    // Checking internet, tokens
    FETCHING,     // Reading local blockchain
    INTEGRITY,    // Getting Play Integrity Token
    UPLOADING,    // Sending to server
    PROCESSING,   // Handling server response
    SUCCESS,
    ERROR
}

data class SyncSessionProgress(
    val phase: SyncPhase,
    val message: String = "",
    val settledCount: Int = 0,
    val refundCount: Int = 0,
    val results: List<SyncResultDetail> = emptyList(),
    val errorCode: String? = null
)

data class SyncResultDetail(
    val localId: String,
    val amountP: Long,
    val status: String,
    val peerId: String
)
