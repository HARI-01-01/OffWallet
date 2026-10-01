# ⚙️ Shadow Protocol Backend Service

> **FastAPI Async Settlement Engine & Trust Anchor for OffWallet**

---

## 📋 Architecture Overview

The backend service acts as the **Root of Trust** and **Settlement Gateway** for the OffWallet ecosystem. Built with **Python 3.10+**, **FastAPI**, and **Google Firebase Firestore**, it enforces protocol invariants while allowing the mobile app to operate 100% offline during transactions.

### Key Responsibilities:
1. **Registration Ceremony & Hardware Binding**: Validates Google Play Integrity tokens and Hardware Attestation certificates before issuing the Genesis Block.
2. **Shamir's Secret Sharing (2-of-3 Key Escrow)**: Generates and shards the AES-256 database encryption key, keeping Shard 2 on the server.
3. **Security Pass Issuance**: Signs and issues 24-hour spending passes containing offline caps (`per_tx_cap`, `aggregate_cap`) and the latest settled ledger anchor.
4. **Dual-Head Settlement Engine**: Atomically settles UDLB blocks, moving both Payer and Payee heads forward in a single Firestore transaction.
5. **Passive Linkage Repair**: Automatically reconstructs missing block history using the global settlement document store.

---

## 🔌 API Endpoints Reference

### 1. Authentication & Registration
- `POST /api/v1/auth/challenge`
  - Generates a random 32-byte registration challenge for anti-replay verification.
- `POST /api/v1/auth/register`
  - Validates Play Integrity & Hardware Attestation.
  - Generates Genesis Block (Block 0) signed by Server Master Key.
  - Performs X25519 EKE to transfer encrypted Master AES Key.

### 2. Vault Management & Pass
- `POST /api/v1/bucket/topup`
  - Deducts online main balance and issues a signed UDLB Top-up block.
  - Advances server-side sync state for the wallet.
- `GET /api/v1/pass/refresh`
  - Issues a fresh, signed Security Pass containing the latest `last_settled_counter` and `last_settled_head`.

### 3. Settlement & Reconciliation
- `POST /api/v1/offline/sync`
  - Reconciles offline UDLB transactions.
  - Verifies Payer and Payee Ed25519/ECDSA signatures against registered device public keys.
  - Atomically updates balances and advances sync state for **both** participants.
  - Returns a fresh Security Pass to reset the app's offline transaction counter (0/10).

### 4. Health & Admin
- `GET /health`
  - Returns server health, version (`2.0.2`), and timestamp.

---

## 🗄️ Firestore Database Schema

| Collection | Purpose | Key Fields |
| :--- | :--- | :--- |
| `users` | Device & Profile Storage | `wallet_id`, `device_pubkey`, `attest_tier`, `aes_key`, `recovery_shard_2` |
| `buckets` | Online & Offline Balances | `wallet_id`, `balance` (online), `lite_balance` (offline), `counter` |
| `sync_state` | Monotonic Ledger Heads | `wallet_id`, `head_counter`, `head_hash`, `last_sync_at` |
| `settlements` | UDLB Block Document Store | `block_hash`, `payer_id`, `payee_id`, `counter`, `payee_counter`, `payer_signature`, `payee_signature` |
| `devices` | Active Device Bindings | `device_id`, `wallet_id`, `is_active` |

---

## 🧪 Testing & Utilities

### 1. Run E2E Integration Tests
```bash
# Activate virtual environment
source venv/bin/activate

# Run deep settlement verification
ENV=development python3 src/test_settlement_deep.py

# Run full lifecycle integration test
ENV=development python3 src/test_full_cycle.py

# Run edge-case stress scenarios
ENV=development python3 src/test_stress_scenarios.py
```

### 2. Reset System Database
```bash
# Wipes Firestore collections and master keys for clean demo runs
ENV=development python3 src/reset_system.py
```

---

## 🚀 Running locally

```bash
# Start FastAPI server with Uvicorn
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
