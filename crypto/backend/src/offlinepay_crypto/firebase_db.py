"""Firebase Firestore Database Adapter."""

from __future__ import annotations

import time
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import FieldFilter, Query

from .logging_utils import get_logger

logger = get_logger("offlinepay.firebase")

class FirebaseDB:
    """Firebase Firestore database adapter."""
    
    def __init__(self, skip_initialization: bool = False):
        """
        Initialize Firestore client.
        
        Args:
            skip_initialization: If True, skip Firebase initialization (for testing)
        """
        self._initialized = False
        self.db = None
        
        # Check if Firebase is already initialized
        if firebase_admin._apps:
            logger.info("Firebase already initialized")
            self._init_firestore()
            return
        
        if skip_initialization:
            logger.warning("Firebase not initialized - running in skip mode")
            return
        
        # Try to initialize Firebase
        try:
            self._init_firebase()
            self._init_firestore()
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {e}")
            raise RuntimeError(f"Firebase initialization failed: {e}")
    
    def _find_credentials(self) -> Optional[str]:
        """Find Firebase credentials file in multiple locations."""
        locations = [
            os.path.join(os.getcwd(), "firebase-adminsdk.json"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "firebase-adminsdk.json"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firebase-adminsdk.json"),
            os.getenv("GOOGLE_APPLICATION_CREDENTIALS", ""),
            os.getenv("FIREBASE_CREDENTIALS", ""),
            os.path.expanduser("~/firebase-adminsdk.json"),
            Path("firebase-adminsdk.json").resolve(),
        ]
        
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        locations.append(os.path.join(src_dir, "firebase-adminsdk.json"))
        
        for path in locations:
            if path and os.path.exists(path):
                logger.info(f"Found Firebase credentials at: {path}")
                return path
        
        logger.error(f"Firebase credentials not found. Searched in: {locations}")
        return None
    
    def _init_firebase(self):
        """Initialize Firebase Admin SDK."""
        cred_path = self._find_credentials()
        
        if not cred_path:
            raise FileNotFoundError(
                "Firebase credentials not found. Please ensure firebase-adminsdk.json "
                "is in the project root or src/ directory."
            )
        
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully")
    
    def _init_firestore(self):
        """Initialize Firestore client."""
        try:
            self.db = firestore.client()
            self._initialized = True
            self._init_collections()
            logger.info("Firestore client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Firestore client: {e}")
            raise
    
    def _init_collections(self):
        """Initialize collection references."""
        if not self.db:
            return
            
        self.users = self.db.collection("users")
        self.buckets = self.db.collection("buckets")
        self.transactions = self.db.collection("transactions")
        self.devices = self.db.collection("devices")
        self.api_keys = self.db.collection("api_keys")
        self.ledger = self.db.collection("ledger")
        self.settlements = self.db.collection("settlements")
        self.fraud_logs = self.db.collection("fraud_logs")
        self.user_meta = self.db.collection("user_meta")
        self.nonces = self.db.collection("nonces")
        self.challenges = self.db.collection("challenges")
        self.sync_state = self.db.collection("sync_state")
        self.sessions = self.db.collection("sessions")

    def _ensure_initialized(self):
        """Ensure Firebase is initialized before operations."""
        if not self._initialized:
            raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    
    # ==================== USER OPERATIONS ====================
    
    def get_user(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get user by wallet_id."""
        self._ensure_initialized()
        try:
            doc = self.users.document(wallet_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting user {wallet_id}: {e}")
            return None
    
    def get_user_by_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        """Get user by phone number."""
        self._ensure_initialized()
        try:
            query = self.users.where(
                filter=FieldFilter("phone", "==", phone)
            ).limit(1).get()
            for doc in query:
                data = doc.to_dict()
                data["wallet_id"] = doc.id
                return data
            return None
        except Exception as e:
            logger.error(f"Error getting user by phone {phone}: {e}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email address."""
        self._ensure_initialized()
        try:
            query = self.users.where(
                filter=FieldFilter("email", "==", email)
            ).limit(1).get()
            for doc in query:
                data = doc.to_dict()
                data["wallet_id"] = doc.id
                return data
            return None
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None

    def get_user_by_uid(self, firebase_uid: str) -> Optional[Dict[str, Any]]:
        """Get user by Firebase UID."""
        self._ensure_initialized()
        try:
            query = self.users.where(
                filter=FieldFilter("firebase_uid", "==", firebase_uid)
            ).limit(1).get()
            for doc in query:
                data = doc.to_dict()
                data["wallet_id"] = doc.id
                return data
            return None
        except Exception as e:
            logger.error(f"Error getting user by UID {firebase_uid}: {e}")
            return None
    
    def create_user(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """Create a new user."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            data["updated_at"] = int(time.time())
            self.users.document(wallet_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating user {wallet_id}: {e}")
            return False
    
    def update_user(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """Update user data."""
        self._ensure_initialized()
        try:
            data["updated_at"] = int(time.time())
            self.users.document(wallet_id).update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating user {wallet_id}: {e}")
            return False

    def get_next_pass_seq(self, wallet_id: str) -> int:
        """Get next monotonic sequence number for a security pass."""
        self._ensure_initialized()
        try:
            user_ref = self.users.document(wallet_id)

            @firestore.transactional
            def update_in_transaction(transaction, ref):
                snapshot = ref.get(transaction=transaction)
                if not snapshot.exists:
                    return 1

                current_seq = snapshot.to_dict().get("server_pass_seq", 0)
                new_seq = current_seq + 1
                transaction.update(ref, {"server_pass_seq": new_seq})
                return new_seq

            return update_in_transaction(self.db.transaction(), user_ref)
        except Exception as e:
            logger.error(f"Error getting next pass seq for {wallet_id}: {e}")
            return int(time.time()) # Fallback to timestamp if transaction fails

    # ==================== BUCKET OPERATIONS ====================
    
    def get_bucket(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get bucket by wallet_id."""
        self._ensure_initialized()
        try:
            doc = self.buckets.document(wallet_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting bucket {wallet_id}: {e}")
            return None
    
    def create_bucket(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """Create a new bucket."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            data["updated_at"] = int(time.time())
            data["status"] = data.get("status", "ACTIVE")
            data["last_synced"] = data.get("last_synced", int(time.time()))
            self.buckets.document(wallet_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating bucket {wallet_id}: {e}")
            return False
    
    def update_bucket(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        self._ensure_initialized()
        try:
            if "updated_at" not in data:
                data["updated_at"] = int(time.time())
            
            doc_ref = self.buckets.document(wallet_id)
            doc = doc_ref.get()
            if not doc.exists:
                logger.warning(f"Bucket {wallet_id} not found")
                return False
            
            doc_ref.update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating bucket {wallet_id}: {e}")
            return False
    
    def update_bucket_counter(self, wallet_id: str, new_counter: int) -> bool:
        self._ensure_initialized()
        try:
            bucket_ref = self.buckets.document(wallet_id)
            
            @firestore.transactional
            def update_in_transaction(transaction, ref):
                snapshot = ref.get(transaction=transaction)
                if not snapshot.exists:
                    return False
                
                current_counter = snapshot.to_dict().get("counter", 0)
                if current_counter != new_counter - 1:
                    return False
                
                transaction.update(ref, {
                    "counter": new_counter,
                    "updated_at": int(time.time())
                })
                return True
            
            return update_in_transaction(self.db.transaction(), bucket_ref)
        except Exception as e:
            logger.error(f"Error updating bucket counter {wallet_id}: {e}")
            return False
    
    # ==================== LITE BUCKET OPERATIONS ====================
    
    def get_lite_bucket(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get lite wallet bucket data."""
        self._ensure_initialized()
        try:
            doc = self.buckets.document(wallet_id).get()
            if not doc.exists:
                return None
            data = doc.to_dict()
            return {
                "lite_balance": data.get("lite_balance", 0),
                "lite_counter": data.get("lite_counter", 0),
                "lite_encrypted_balance": data.get("lite_encrypted_balance"),
                "lite_encrypted_counter": data.get("lite_encrypted_counter"),
                "lite_server_signature": data.get("lite_server_signature"),
                "lite_expires_at": data.get("lite_expires_at", 0),
                "lite_last_synced": data.get("lite_last_synced", 0),
                "status": data.get("status", "ACTIVE"),
            }
        except Exception as e:
            logger.error(f"Error getting lite bucket {wallet_id}: {e}")
            return None
    
    def update_lite_bucket(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """Update lite wallet bucket."""
        self._ensure_initialized()
        try:
            if "updated_at" not in data:
                data["updated_at"] = int(time.time())
            
            doc_ref = self.buckets.document(wallet_id)
            doc = doc_ref.get()
            if not doc.exists:
                doc_ref.set(data)
                return True
            
            doc_ref.update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating lite bucket {wallet_id}: {e}")
            return False
        
    # ==================== USER META OPERATIONS ====================
    
    def create_user_meta(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """Create user metadata."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            data["updated_at"] = int(time.time())
            self.user_meta.document(wallet_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating user meta {wallet_id}: {e}")
            return False
    
    def get_user_meta(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get user metadata."""
        self._ensure_initialized()
        try:
            doc = self.user_meta.document(wallet_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting user meta {wallet_id}: {e}")
            return None
    
    # ==================== TRANSACTION OPERATIONS ====================
    
    def create_transaction(self, local_id: str, data: Dict[str, Any]) -> bool:
        """Create a new transaction."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            data["updated_at"] = int(time.time())
            self.transactions.document(local_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating transaction {local_id}: {e}")
            return False
    
    def update_transaction(self, local_id: str, data: Dict[str, Any]) -> bool:
        """Update transaction data."""
        self._ensure_initialized()
        try:
            data["updated_at"] = int(time.time())
            self.transactions.document(local_id).update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating transaction {local_id}: {e}")
            return False

    def get_transaction_by_id(self, local_id: str) -> Optional[Dict[str, Any]]:
        """Get transaction by local_id."""
        self._ensure_initialized()
        try:
            doc = self.transactions.document(local_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting transaction {local_id}: {e}")
            return None

    def get_transaction_by_local_id(self, local_id: str) -> Optional[Dict[str, Any]]:
        """Alias for get_transaction_by_id."""
        return self.get_transaction_by_id(local_id)

    def update_transaction_status(self, local_id: str, status: str, data: Optional[Dict[str, Any]] = None) -> bool:
        """Update transaction status."""
        self._ensure_initialized()
        try:
            update_data = {"status": status, "updated_at": int(time.time())}
            if data:
                update_data.update(data)
            self.transactions.document(local_id).update(update_data)
            return True
        except Exception as e:
            logger.error(f"Error updating transaction {local_id}: {e}")
            return False

    def get_pending_transactions(
        self, 
        status: Optional[str] = None, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get pending transactions."""
        self._ensure_initialized()
        try:
            query = self.transactions
            if status:
                query = query.where(filter=FieldFilter("status", "==", status))
            
            docs = query.get()
            results = [
                {**doc.to_dict(), "local_id": doc.id} 
                for doc in docs
            ]
            results.sort(key=lambda x: x.get("created_at", 0))
            return results[:limit]
        except Exception as e:
            logger.error(f"Error getting pending transactions: {e}")
            return []
    
    def get_pending_transactions_by_payer(self, payer_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending transactions for a specific payer."""
        self._ensure_initialized()
        try:
            query = self.transactions.where(
                filter=FieldFilter("payer_id", "==", payer_id)
            ).where(
                filter=FieldFilter("status", "in", ["PENDING", "QUEUED"])
            ).order_by("created_at").limit(limit)

            docs = query.get()
            return [
                {**doc.to_dict(), "local_id": doc.id}
                for doc in docs
            ]
        except Exception as e:
            logger.error(f"Error getting pending transactions for {payer_id}: {e}")
            return []

    def delete_from_queue(self, local_id: str) -> bool:
        """Delete a transaction from the queue."""
        self._ensure_initialized()
        try:
            self.transactions.document(local_id).delete()
            return True
        except Exception as e:
            logger.error(f"Error deleting transaction {local_id}: {e}")
            return False
    
    def get_queue_count(self, status: Optional[str] = None) -> int:
        """Get count of transactions in queue."""
        self._ensure_initialized()
        try:
            query = self.transactions
            if status:
                query = query.where(filter=FieldFilter("status", "==", status))
            docs = query.get()
            return len(docs)
        except Exception as e:
            logger.error(f"Error getting queue count: {e}")
            return 0

    def deactivate_devices(self, wallet_id: str) -> bool:
        """Deactivate all active devices for a wallet."""
        self._ensure_initialized()
        try:
            query = self.devices.where(
                filter=FieldFilter("wallet_id", "==", wallet_id)
            ).where(
                filter=FieldFilter("is_active", "==", True)
            ).get()

            for doc in query:
                doc.reference.update({
                    "is_active": False,
                    "deactivated_at": int(time.time())
                })
            return True
        except Exception as e:
            logger.error(f"Error deactivating devices for {wallet_id}: {e}")
            return False
        """Get device by device_id."""
        self._ensure_initialized()
        try:
            doc = self.devices.document(device_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting device {device_id}: {e}")
            return None
    
    def create_device(self, device_id: str, data: Dict[str, Any]) -> bool:
        """Create a new device."""
        self._ensure_initialized()
        try:
            data["registered_at"] = int(time.time())
            data["last_seen"] = int(time.time())
            self.devices.document(device_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating device {device_id}: {e}")
            return False
    
    def touch_device(self, device_id: str) -> bool:
        """Update device last_seen timestamp."""
        self._ensure_initialized()
        try:
            self.devices.document(device_id).update({
                "last_seen": int(time.time())
            })
            return True
        except Exception as e:
            logger.error(f"Error touching device {device_id}: {e}")
            return False
    
    # ==================== API KEY OPERATIONS ====================
    
    def get_api_key(self, api_key_hash: str) -> Optional[Dict[str, Any]]:
        """Get API key by hash."""
        self._ensure_initialized()
        try:
            query = self.api_keys.where(
                filter=FieldFilter("api_key_hash", "==", api_key_hash)
            ).limit(1).get()
            for doc in query:
                return doc.to_dict()
            return None
        except Exception as e:
            logger.error(f"Error getting API key: {e}")
            return None
    
    def create_api_key(self, key_id: str, data: Dict[str, Any]) -> bool:
        """Create a new API key."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            data["revoked"] = data.get("revoked", False)
            self.api_keys.document(key_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating API key {key_id}: {e}")
            return False
    
    def touch_api_key(self, api_key_hash: str) -> bool:
        """Update API key last_used timestamp."""
        self._ensure_initialized()
        try:
            query = self.api_keys.where(
                filter=FieldFilter("api_key_hash", "==", api_key_hash)
            ).limit(1).get()
            for doc in query:
                doc.reference.update({"last_used": int(time.time())})
                return True
            return False
        except Exception as e:
            logger.error(f"Error touching API key: {e}")
            return False
    
    def revoke_api_key(self, api_key_hash: str) -> bool:
        """Revoke API key."""
        self._ensure_initialized()
        try:
            query = self.api_keys.where(
                filter=FieldFilter("api_key_hash", "==", api_key_hash)
            ).limit(1).get()
            for doc in query:
                doc.reference.update({"revoked": True})
                return True
            return False
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return False
    
    # ==================== SETTLEMENT OPERATIONS ====================
    
    def create_settlement(self, local_id: str, data: Dict[str, Any]) -> bool:
        """Create a settlement record."""
        self._ensure_initialized()
        try:
            data["settled_at"] = int(time.time())
            data["status"] = data.get("status", "SETTLED")
            self.settlements.document(local_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating settlement {local_id}: {e}")
            return False
    
    def get_settlement(self, local_id: str) -> Optional[Dict[str, Any]]:
        """Get settlement by local_id."""
        self._ensure_initialized()
        try:
            doc = self.settlements.document(local_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting settlement {local_id}: {e}")
            return None

    def get_settlement_by_hash(self, block_hash: str) -> Optional[Dict[str, Any]]:
        """Get settlement by block_hash (Unique Index)."""
        self._ensure_initialized()
        try:
            # We use block_hash as the document ID for deduplication
            doc = self.settlements.document(block_hash).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting settlement by hash {block_hash}: {e}")
            return None

    def save_refund(self, block_hash: str, wallet_id: str, amount: int, counter: int) -> bool:
        """Mark a block as REFUNDED on the server to prevent future settlement."""
        self._ensure_initialized()
        try:
            self.settlements.document(block_hash).set({
                "block_hash": block_hash,
                "payer_id": wallet_id,
                "amount": amount,
                "counter": counter,
                "status": "REFUNDED",
                "timestamp": int(time.time()),
                "updated_at": int(time.time())
            })
            return True
        except Exception as e:
            logger.error(f"Error saving refund for {block_hash}: {e}")
            return False

    def get_settlement_by_counter(self, wallet_id: str, counter: int) -> Optional[Dict[str, Any]]:
        """Get settlement by wallet_id and counter (Gap filling)."""
        self._ensure_initialized()
        try:
            query = self.settlements.where(
                filter=FieldFilter("payer_id", "==", wallet_id)
            ).where(
                filter=FieldFilter("counter", "==", counter)
            ).limit(1).get()
            for doc in query:
                return doc.to_dict()
            return None
        except Exception as e:
            logger.error(f"Error getting settlement by counter {wallet_id}:{counter}: {e}")
            return None

    # ==================== SYNC STATE OPERATIONS ====================

    def get_sync_state(self, wallet_id: str) -> Dict[str, Any]:
        """Get sync state for a wallet."""
        self._ensure_initialized()
        try:
            doc = self.sync_state.document(wallet_id).get()
            if doc.exists:
                return doc.to_dict()

            # Initial state from bucket if sync_state doesn't exist
            bucket = self.get_bucket(wallet_id)
            initial = {
                "wallet_id": wallet_id,
                "head_counter": bucket.get("counter", 0) if bucket else 0,
                "head_hash": bucket.get("last_block_hash", "0" * 64) if bucket and bucket.get("last_block_hash") else "0" * 64,
                "hwm_timestamp": 0,
                "genesis_epoch": bucket.get("genesis_epoch", 1) if bucket else 1,
                "status": "ACTIVE",
                "last_sync_at": int(time.time())
            }
            self.sync_state.document(wallet_id).set(initial)
            return initial
        except Exception as e:
            logger.error(f"Error getting sync state {wallet_id}: {e}")
            return {"head_counter": 0, "head_hash": "0" * 64, "genesis_epoch": 1, "status": "ACTIVE"}

    def update_sync_state(self, wallet_id: str, counter: int, block_hash: str, hwm_timestamp: Optional[int] = None, status: str = "ACTIVE") -> bool:
        """Update sync state using set(merge=True) to handle non-existent documents."""
        self._ensure_initialized()
        try:
            update_data = {
                "wallet_id": wallet_id,
                "head_counter": counter,
                "head_hash": block_hash,
                "status": status,
                "last_sync_at": int(time.time())
            }
            if hwm_timestamp is not None:
                update_data["hwm_timestamp"] = hwm_timestamp

            self.sync_state.document(wallet_id).set(update_data, merge=True)
            return True
        except Exception as e:
            logger.error(f"Error updating sync state {wallet_id}: {e}")
            return False

    # ==================== FRAUD LOGS ====================
    
    def log_fraud(self, data: Dict[str, Any]) -> bool:
        """Log a fraud event."""
        self._ensure_initialized()
        try:
            data["timestamp"] = int(time.time())
            self.fraud_logs.add(data)
            return True
        except Exception as e:
            logger.error(f"Error logging fraud: {e}")
            return False
    
    # ==================== LEDGER OPERATIONS ====================
    
    def create_ledger_entry(self, data: Dict[str, Any]) -> bool:
        """Create a ledger entry."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            self.ledger.add(data)
            return True
        except Exception as e:
            logger.error(f"Error creating ledger entry: {e}")
            return False
    
    def get_ledger(self, wallet_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get ledger entries for a wallet."""
        self._ensure_initialized()
        try:
            query = self.ledger.where(
                filter=FieldFilter("wallet_id", "==", wallet_id)
            ).order_by("timestamp", direction=Query.DESCENDING).limit(limit)
            
            docs = query.get()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            logger.error(f"Error getting ledger for {wallet_id}: {e}")
            return []

    # ==================== NONCE OPERATIONS ====================

    def create_nonce(self, nonce_id: str, data: Dict[str, Any]) -> bool:
        """Create a new session nonce."""
        self._ensure_initialized()
        try:
            data["created_at"] = int(time.time())
            self.nonces.document(nonce_id).set(data)
            return True
        except Exception as e:
            logger.error(f"Error creating nonce {nonce_id}: {e}")
            return False

    def get_nonce(self, nonce_id: str) -> Optional[Dict[str, Any]]:
        """Get nonce by ID."""
        self._ensure_initialized()
        try:
            doc = self.nonces.document(nonce_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting nonce {nonce_id}: {e}")
            return None

    def update_nonce_status(self, nonce_id: str, status: str) -> bool:
        """Update nonce status (ACTIVE, USED, EXPIRED, REVOKED)."""
        self._ensure_initialized()
        try:
            self.nonces.document(nonce_id).update({
                "status": status,
                "updated_at": int(time.time())
            })
            return True
        except Exception as e:
            logger.error(f"Error updating nonce {nonce_id}: {e}")
            return False

    def get_latest_nonce(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """Get the latest active nonce for a wallet (Memory-optimized to avoid index errors)."""
        self._ensure_initialized()
        try:
            # Simple query to avoid composite index requirement
            query = self.nonces.where(
                filter=FieldFilter("wallet_id", "==", wallet_id)
            ).get()

            # Filter and sort in memory
            active_nonces = []
            for doc in query:
                data = doc.to_dict()
                if data.get("status") == "ACTIVE":
                    data["nonce_id"] = doc.id
                    active_nonces.append(data)

            if not active_nonces:
                return None

            # Sort by sequence_number descending
            active_nonces.sort(key=lambda x: x.get("sequence_number", 0), reverse=True)
            return active_nonces[0]

        except Exception as e:
            logger.error(f"Error getting latest nonce for {wallet_id}: {e}")
            return None

    # ==================== UTILITY ====================

    def delete_all_data(self) -> bool:
        """Delete all data (for testing only)."""
        self._ensure_initialized()
        try:
            collections = [
                self.users, self.buckets, self.transactions, 
                self.devices, self.api_keys, self.ledger, 
                self.settlements, self.user_meta, self.fraud_logs,
                self.nonces, self.challenges, self.sync_state,
                self.sessions
            ]
            for collection in collections:
                docs = collection.get()
                for doc in docs:
                    doc.reference.delete()
            return True
        except Exception as e:
            logger.error(f"Error deleting data: {e}")
            return False
