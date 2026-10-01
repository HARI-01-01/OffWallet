package com.offlinewallet.payment.ble

enum class PaymentPhase {
    DISCOVERY,    // 0: Searching/Advertising
    CONNECTING,   // 1: GATT Connection & MTU
    IDENTITY,     // 2: M1/M2 Identity Handshake
    AUDIT,        // 3: Ledger History Audit
    DEBITING,     // 4: M3 Pushing Funds
    FINALIZING,   // 5: M4 Receipt & Storage
    SUCCESS,      // 6: Done
    ERROR,        // 7: Failed
    DOUBTFUL      // 8: Waiting for Receipt (Debit likely sent)
}

data class PaymentSessionProgress(
    val phase: PaymentPhase,
    val message: String = "",
    val errorCode: String? = null,
    val peerName: String? = null,
    val peerId: String? = null,
    val amountP: Long? = null,
    val payeeInitials: String? = null,
    val isPayer: Boolean = true
)
