package com.offlinewallet.models

import com.google.gson.annotations.SerializedName

enum class BlockchainNodeType {
    GENESIS,
    TOPUP,
    PAYMENT_SENT,
    PAYMENT_RECEIVED
}

data class BlockchainNode(
    val id: String,
    val type: BlockchainNodeType,
    val amountP: Long,
    val counter: Long,
    val timestamp: Long,
    val prevHash: String,
    val hash: String,
    val peerId: String? = null,
    val status: String = "COMMITTED"
)
