# Shadow v1 Structures

This document defines the canonical fields for all signed payloads. 
Field order is fixed and MUST NOT change.

## 1. Block
Used for debiting funds from a payer to a payee.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version (currently 1) |
| 2 | chain_id | Str | Environment ID (e.g., "prod", "staging") |
| 3 | wallet_id | Str | Payer's wallet ID |
| 4 | counter | U64 | Monotonic transaction counter |
| 5 | prev_hash | Bytes | SHA256 of the previous block |
| 6 | amount_p | U64 | Amount in integer paise |
| 7 | payee_pubkey_hash | Bytes | SHA256 of payee's device public key |
| 8 | payee_wallet_id | Str | Payee's wallet ID |
| 9 | payee_chal | Bytes | Random challenge from payee |
| 10 | payer_pass_id | Str | ID of the Pass Alice is using |
| 11 | payee_pass_id | Str | ID of the Pass Bob is using |
| 12 | genesis_epoch | U64 | Current epoch of the payer |
| 13 | ts | U64 | Payer's local timestamp |

## 2. Pass
Issued by the server to grant offline spend capacity.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version |
| 2 | kid | Str | Key ID used to sign this Pass |
| 3 | wallet_id | Str | Wallet ID this Pass belongs to |
| 4 | display_name | Str | User-facing name |
| 5 | device_pubkey_hash | Bytes | SHA256 of the authorized device key |
| 6 | attest_tier | Str | STRONGBOX, TEE, or SOFTWARE |
| 7 | per_tx_cap_p | U64 | Max amount per transaction |
| 8 | aggregate_cap_p | U64 | Max unsettled aggregate amount |
| 9 | txn_count_cap | U64 | Max unsettled transaction count |
| 10 | recv_unsettled_cap_p | U64 | Max amount Bob can receive offline |
| 11 | recv_per_peer_cap_p | U64 | Max amount from a single peer |
| 12 | pass_id | Str | Unique ID for this Pass |
| 13 | server_seq | U64 | Server-side sequence for the wallet |
| 14 | issued_at | U64 | Timestamp of issuance |
| 15 | expires_at | U64 | Timestamp of expiry |
| 16 | genesis_epoch | U64 | Wallet's current genesis epoch |
| 17 | last_settled_counter | U64 | Counter at last settlement |
| 18 | last_settled_head | Bytes | Head hash at last settlement |

## 3. Genesis
Initial state signed by the server.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version |
| 2 | wallet_id | Str | Wallet ID |
| 3 | device_pubkey_hash | Bytes | Authorized device key hash |
| 4 | balance_p | U64 | Initial balance in paise |
| 5 | counter | U64 | Initial counter value |
| 6 | genesis_epoch | U64 | Epoch index |
| 7 | issued_at | U64 | Timestamp |
| 8 | server_seq | U64 | Server sequence |

## 4. Receipt
Bob's proof of payment.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version |
| 2 | block_hash | Bytes | Hash of the block being receipted |
| 3 | payee_wallet_id | Str | Payee's wallet ID |
| 4 | payee_counter | U64 | Payee's own receive counter |
| 5 | payee_prev_hash | Bytes | Payee's previous head hash |
| 6 | payer_chal | Bytes | Challenge from Alice |
| 7 | ts | U64 | Payee's local timestamp |

## 5. Ack
Alice's acknowledgement of the receipt.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version |
| 2 | receipt_hash | Bytes | Hash of the Receipt |

## 6. TopUp
Authorizes adding funds to a wallet.

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | v | U8 | Version |
| 2 | wallet_id | Str | Wallet ID |
| 3 | device_pubkey_hash | Bytes | Device key hash |
| 4 | amount_p | U64 | Amount to add |
| 5 | topup_seq | U64 | Monotonic top-up sequence |
| 6 | psp_ref | Str | Payment provider reference |
| 7 | genesis_epoch | U64 | Target epoch |
| 8 | issued_at | U64 | Issuance time |
| 9 | expires_at | U64 | Expiry time |
