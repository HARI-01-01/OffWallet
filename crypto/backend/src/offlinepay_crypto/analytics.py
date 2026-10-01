"""Analytics and monitoring for the Firebase-based offline payment backend."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import psutil

from models.analytics import ActivityLog, BucketStats, SystemHealth, TransactionStats, UserStats
from .firebase_db import FirebaseDB
from .logging_utils import get_logger

class Analytics:
    """System monitoring and analytics for Firestore."""

    def __init__(self, db: FirebaseDB):
        self.db = db
        self.start_time = time.time()
        self.logger = get_logger("offlinepay.analytics")

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Fetch list of all users with basic metadata."""
        try:
            docs = self.db.users.get()
            users = []
            for doc in docs:
                d = doc.to_dict()
                users.append({
                    "wallet_id": doc.id,
                    "wallet_name": d.get("wallet_name", "Unknown"),
                    "email": d.get("email", ""),
                    "status": d.get("status", "ACTIVE"),
                    "attest_tier": d.get("attest_tier", "TEE"),
                    "created_at": d.get("created_at", 0)
                })
            return sorted(users, key=lambda x: x["created_at"], reverse=True)
        except Exception as e:
            self.logger.error(f"Error fetching all users: {e}")
            return []

    def get_user_stats(self) -> Dict[str, Any]:
        """Fetch user statistics from Firestore."""
        try:
            # Note: Firestore count() is efficient but requires fetching documents if not using aggregation queries
            users_docs = self.db.users.get()
            total_users = len(users_docs)
            # ... (rest of the logic stays)

            active_users = 0
            users_by_status = {}
            new_users_today = 0
            today_cutoff = int(time.time()) - 86400

            for doc in users_docs:
                data = doc.to_dict()
                status = data.get("status", "UNKNOWN")
                users_by_status[status] = users_by_status.get(status, 0) + 1

                if data.get("created_at", 0) > today_cutoff:
                    new_users_today += 1

                # Check bucket for activity (simplified)
                wallet_id = doc.id
                bucket = self.db.get_bucket(wallet_id)
                if bucket and bucket.get("balance", 0) > 0:
                    active_users += 1

            return UserStats(
                total_users=total_users,
                active_users=active_users,
                new_users_today=new_users_today,
                users_by_status=users_by_status,
            ).model_dump()
        except Exception as e:
            self.logger.error(f"Error fetching user stats: {e}")
            return UserStats(total_users=0, active_users=0, new_users_today=0, users_by_status={}).model_dump()

    def get_transaction_stats(self) -> Dict[str, Any]:
        """Fetch transaction statistics from Firestore."""
        try:
            settlements = self.db.settlements.get()
            total_transactions = len(settlements)
            total_volume = 0
            transactions_today = 0
            volume_today = 0
            today_cutoff = int(time.time()) - 86400

            for doc in settlements:
                data = doc.to_dict()
                amount = data.get("amount", 0)
                total_volume += amount

                if data.get("timestamp", 0) > today_cutoff:
                    transactions_today += 1
                    volume_today += amount

            # Get counts for different statuses from transactions collection
            pending_count = self.db.get_queue_count("QUEUED")
            failed_count = self.db.get_queue_count("FAILED")

            return TransactionStats(
                total_transactions=total_transactions,
                total_volume=total_volume,
                transactions_today=transactions_today,
                volume_today=volume_today,
                pending_count=pending_count,
                failed_count=failed_count,
                settled_count=total_transactions,
                fraud_detected=0, # Placeholder
            ).model_dump()
        except Exception as e:
            self.logger.error(f"Error fetching transaction stats: {e}")
            return { "total_transactions": 0, "total_volume": 0 }

    def get_transaction_trend(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get daily transaction volume for the last X days."""
        cutoff = int(time.time()) - (days * 86400)
        try:
            settlements = self.db.settlements.where("timestamp", ">=", cutoff).get()
            trend_map = {}

            # Initialize map with last X days to ensure we have entries for zero-activity days
            now = datetime.now()
            for i in range(days):
                d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
                trend_map[d] = {"date": d, "volume": 0, "count": 0}

            for doc in settlements:
                data = doc.to_dict()
                ts = data.get("timestamp", 0)
                date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                if date_str in trend_map:
                    trend_map[date_str]["volume"] += data.get("amount", 0)
                    trend_map[date_str]["count"] += 1

            return sorted(trend_map.values(), key=lambda x: x["date"])
        except Exception as e:
            self.logger.error(f"Error fetching trend: {e}")
            return []

    def get_system_health(self) -> Dict[str, Any]:
        """Fetch system health metrics."""
        uptime = int(time.time() - self.start_time)
        db_connected = self.db._initialized

        memory = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=None)

        return SystemHealth(
            status="healthy" if db_connected else "unhealthy",
            uptime=uptime,
            database_connected=db_connected,
            redis_connected=False,
            queue_size=self.db.get_queue_count("QUEUED"),
            memory_usage=round(memory.percent, 1),
            cpu_usage=round(cpu, 1),
        ).model_dump()

    def get_activity_logs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch recent transaction logs."""
        try:
            docs = self.db.settlements.order_by("timestamp", direction="DESCENDING").limit(limit).get()
            logs = []
            for doc in docs:
                data = doc.to_dict()
                logs.append({
                    "timestamp": datetime.fromtimestamp(data.get("timestamp", 0)).isoformat(),
                    "event_type": "settlement",
                    "user_id": data.get("payer_id"),
                    "details": {
                        "amount": data.get("amount"),
                        "payee": data.get("payee_id"),
                        "status": "SETTLED",
                        "method": data.get("method"),
                        "block_hash": data.get("block_hash")
                    }
                })
            return logs
        except Exception as e:
            self.logger.error(f"Error fetching activity logs: {e}")
            return []

    def get_security_audit(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recent security audit logs (fraud and attestation)."""
        try:
            docs = self.db.fraud_logs.order_by("timestamp", direction="DESCENDING").limit(limit).get()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            self.logger.error(f"Error fetching security audit: {e}")
            return []

    def get_security_specs(self) -> Dict[str, Any]:
        """Return the technical specifications of the security system."""
        return {
            "keystore_aliases": {
                "transaction_keys": "offlinepay_<wallet_id>",
                "master_aes_key": "offlinepay_master_secret",
                "nonce_key": "offlinepay_nonce_key",
                "apk_hash_ref": "offlinepay_apk_hash"
            },
            "algorithms": {
                "block_signing": "ECDSA with P-256 (Hardware-Backed)",
                "data_encryption": "AES-256-GCM (Hardware-Backed)",
                "hash_chain": "SHA-256",
                "attestation": "Android Key Attestation (TEE/StrongBox)"
            },
            "backend_storage": {
                "buckets": "Wallet metadata, balance, counter, last_block_hash",
                "nonces": "Server-signed session tokens",
                "settlements": "Immutable audit trail of cleared blocks",
                "telemetry": "App heartbeat logs"
            },
            "functionality": {
                "verification": "The app walks through the entire hash chain back to the Genesis block before authorizing any transaction.",
                "tamper_detection": "The current block hash is sealed in the Android Keystore (hardware). If the SQLite database is manually edited, the hash mismatch is detected instantly.",
                "recovery": "When the app comes online, it performs a 'Walk-Back' sync. The server compares the client's claimed chain against its verified records to detect rollbacks or double-spends."
            }
        }

    def get_user_journey(self, wallet_id: str) -> List[Dict[str, Any]]:
        """Assemble the complete lifecycle of a user from telemetry and settlements."""
        try:
            # 1. Get Telemetry - Query by ID then sort in memory to avoid index errors
            telemetry_query = self.db.db.collection("telemetry").where("wallet_id", "==", wallet_id).get()

            journey = []
            for doc in telemetry_query:
                journey.append(doc.to_dict())

            # 2. Get Settlements
            settlements = self.db.settlements.where("payer_id", "==", wallet_id).get()
            for doc in settlements:
                data = doc.to_dict()
                journey.append({
                    "event_type": "OFFLINE_PAYMENT_SETTLED",
                    "timestamp": data.get("timestamp"),
                    "event_data": {
                        "amount": data.get("amount"),
                        "payee": data.get("payee_id"),
                        "method": data.get("method"),
                        "status": "VERIFIED"
                    }
                })

            # Sort by timestamp in memory
            return sorted(journey, key=lambda x: x.get("timestamp", 0))
        except Exception as e:
            self.logger.error(f"Error fetching user journey: {e}")
            return []

    def get_user_sync_history(self, wallet_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch synchronization attempts for a user."""
        try:
            docs = self.db.db.collection("sync_attempts").where("wallet_id", "==", wallet_id).order_by("timestamp", direction="DESCENDING").limit(limit).get()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            self.logger.error(f"Error fetching sync history for {wallet_id}: {e}")
            return []

    def get_blockchain_ledger(self, wallet_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch the linked hash chain for a specific wallet, including system blocks."""
        try:
            # 1. Fetch blocks where user is Payer (Standard Payments)
            payer_docs = self.db.settlements.where("payer_id", "==", wallet_id).get()

            # 2. Fetch blocks where user is Payee (Top-ups, Genesis, and Received Payments)
            payee_docs = self.db.settlements.where("payee_id", "==", wallet_id).get()

            # Combine and deduplicate by block_hash
            all_blocks = {}
            for doc in payer_docs:
                data = doc.to_dict()
                all_blocks[data["block_hash"]] = data

            for doc in payee_docs:
                data = doc.to_dict()
                all_blocks[data["block_hash"]] = data

            results = list(all_blocks.values())

            # Sort by counter descending (to show latest head first)
            results.sort(key=lambda x: x.get("counter", 0), reverse=True)

            return results[:limit]
        except Exception as e:
            self.logger.error(f"Error fetching blockchain: {e}")
            return []

    def get_dashboard(self) -> Dict[str, Any]:
        """Assemble full dashboard payload."""
        # For small volumes, we can afford bucket stats too
        buckets = self.db.buckets.get()
        total_balance = sum(b.to_dict().get("balance", 0) for b in buckets)
        frozen_count = sum(1 for b in buckets if b.to_dict().get("status") == "FROZEN")

        stats = BucketStats(
            total_buckets=len(buckets),
            total_balance=total_balance,
            average_balance=int(total_balance / len(buckets)) if buckets else 0,
            frozen_count=frozen_count,
            expired_count=0 # Placeholder
        )

        return {
            "status": "success",
            "data": {
                "users": self.get_user_stats(),
                "transactions": self.get_transaction_stats(),
                "buckets": stats.model_dump(),
                "health": self.get_system_health(),
                "activity": self.get_activity_logs(),
                "security_audit": self.get_security_audit(),
                "security_specs": self.get_security_specs(),
                "timestamp": datetime.now().isoformat(),
            }
        }

class AnomalyDetector:
    def __init__(self, db: FirebaseDB):
        self.db = db
        self.logger = get_logger("offlinepay.detector")

    def check_alerts(self) -> List[Dict[str, Any]]:
        alerts = []
        try:
            # 1. Check pending transactions spike
            pending = self.db.get_queue_count("QUEUED")
            # In a real app, we'd query historical averages.
            # For hackathon, we use a fixed threshold.
            if pending > 50:
                alerts.append({
                    "level": "WARNING",
                    "title": "Pending Transactions Spike",
                    "message": f"There are {pending} transactions awaiting sync.",
                    "timestamp": int(time.time())
                })

            # 2. Check recent fraud events
            recent_frauds = self.db.fraud_logs.where("timestamp", ">", int(time.time()) - 3600).get()
            if len(recent_frauds) > 0:
                alerts.append({
                    "level": "CRITICAL",
                    "title": "Recent Fraud Detected",
                    "message": f"{len(recent_frauds)} fraud events in the last hour.",
                    "timestamp": int(time.time())
                })
        except Exception as e:
            self.logger.error(f"Error checking alerts: {e}")

        return alerts
