"""
Firestore-like SQLite Database for testing.
"""

import sqlite3
import time
from typing import Any, Dict, List, Optional


class DocumentReference:
    def __init__(self, db, table, doc_id):
        self.db = db; self.table = table; self.id = doc_id
    def get(self, transaction=None):
        with self.db._get_connection() as conn:
            table_name = "offline_bucket" if self.table == "buckets" else self.table
            id_col = "wallet_id"
            if table_name in ["settlements", "pending_queue"]: id_col = "local_id"
            elif table_name == "devices": id_col = "device_id"
            row = conn.execute(f"SELECT * FROM {table_name} WHERE {id_col} = ?", (self.id,)).fetchone()
            if row:
                class Snapshot:
                    def __init__(self, data): self._data = dict(data); self.exists = True
                    def to_dict(self): return self._data
                    def get(self, key, default=None): return self._data.get(key, default)
                return Snapshot(row)
            return type('Snapshot', (), {'exists': False, 'to_dict': lambda s: None})()
    def set(self, data, transaction=None):
        if self.table == "settlements": self.db.create_settlement(self.id, data.get('transaction_id'), data.get('payer_id'), data.get('payee_id'), data.get('amount'), data.get('counter'))
        elif self.table == "buckets": self.db.create_bucket(self.id, data)
    def update(self, data, transaction=None): self.db.update_bucket(self.id, data)

class CollectionReference:
    def __init__(self, db, table): self.db = db; self.table = table
    def document(self, doc_id): return DocumentReference(self.db, self.table, doc_id)
    def get(self):
        with self.db._get_connection() as conn:
            table_name = "offline_bucket" if self.table == "buckets" else self.table
            rows = conn.execute(f"SELECT * FROM {table_name}").fetchall()
            return [type('Snapshot', (), {'to_dict': lambda s, r=r: dict(r), 'reference': None})() for r in rows]

class MockTransaction:
    def update(self, ref, data): ref.update(data)
    def set(self, ref, data): ref.set(data)
    def get(self, ref): return ref.get()

class Database:
    def __init__(self, db_path: str = "offline_wallet.db"):
        self.db_path = db_path; self._init_db(); self.db = self
        self.users = CollectionReference(self, "users")
        self.buckets = CollectionReference(self, "buckets")
        self.settlements = CollectionReference(self, "settlements")
        self.transactions = CollectionReference(self, "pending_queue")
        self.devices = CollectionReference(self, "devices")
        self.api_keys = CollectionReference(self, "api_keys")
        self.sync_state = CollectionReference(self, "sync_state")

    def transaction(self): return MockTransaction()
    def _get_connection(self): conn = sqlite3.connect(self.db_path); conn.row_factory = sqlite3.Row; return conn
    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (wallet_id TEXT PRIMARY KEY, email TEXT, phone TEXT, password_hash TEXT, public_key BLOB, created_at INTEGER)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, public_key BLOB, registered_at INTEGER, last_seen INTEGER, status TEXT DEFAULT 'ACTIVE')''')
            conn.execute('''CREATE TABLE IF NOT EXISTS api_keys (key_id TEXT PRIMARY KEY, api_key_hash TEXT UNIQUE, merchant_id TEXT, created_at INTEGER, expires_at INTEGER, revoked INTEGER DEFAULT 0, last_used INTEGER)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS offline_bucket (wallet_id TEXT PRIMARY KEY, balance INTEGER DEFAULT 0, counter INTEGER DEFAULT 0, last_block_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000', encrypted_balance BLOB, encrypted_counter BLOB, server_signature BLOB, created_at INTEGER, updated_at INTEGER, expires_at INTEGER, last_synced INTEGER, status TEXT DEFAULT 'ACTIVE')''')
            conn.execute('''CREATE TABLE IF NOT EXISTS pending_queue (local_id TEXT PRIMARY KEY, amount INTEGER, payer_id TEXT, payee_id TEXT, counter INTEGER, timestamp INTEGER, payer_signature BLOB, payee_signature BLOB, status TEXT DEFAULT 'QUEUED', retry_count INTEGER DEFAULT 0, created_at INTEGER, updated_at INTEGER)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS ledger_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, transaction_id TEXT, wallet_id TEXT, amount INTEGER, entry_type TEXT, balance_before INTEGER, balance_after INTEGER, timestamp INTEGER, description TEXT, created_at INTEGER)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS settlements (local_id TEXT PRIMARY KEY, transaction_id TEXT, payer_id TEXT, payee_id TEXT, amount INTEGER, counter INTEGER, status TEXT DEFAULT 'SETTLED', settled_at INTEGER)''')
            conn.commit()

    def create_user(self, wallet_id, *args, **kwargs):
        data = args[0] if args and isinstance(args[0], dict) else kwargs
        email = data.get('email') or (args[0] if args and not isinstance(args[0], dict) else None)
        with self._get_connection() as conn:
            conn.execute("INSERT INTO users (wallet_id, email, phone, password_hash, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)", (wallet_id, email, data.get('phone'), data.get('password_hash'), data.get('public_key') or data.get('device_pubkey'), int(time.time())))
        return True

    def get_user(self, wallet_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE wallet_id = ?", (wallet_id,)).fetchone()
            return dict(row) if row else None

    def create_device(self, device_id, *args, **kwargs):
        data = args[0] if args and isinstance(args[0], dict) else kwargs
        with self._get_connection() as conn:
            conn.execute("INSERT INTO devices (device_id, public_key, registered_at, last_seen) VALUES (?, ?, ?, ?)", (device_id, data.get('public_key') or data.get('device_pubkey') or (args[0] if args and not isinstance(args[0], dict) else None), int(time.time()), int(time.time())))
        return True

    def get_device(self, device_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            return dict(row) if row else None

    def touch_device(self, device_id):
        with self._get_connection() as conn: conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?", (int(time.time()), device_id))

    def create_bucket(self, wallet_id, *args, **kwargs):
        data = args[0] if args and isinstance(args[0], dict) else kwargs
        balance = data.get('balance', 0)
        if not balance and args and not isinstance(args[0], dict): balance = args[0]
        with self._get_connection() as conn:
            conn.execute("""INSERT INTO offline_bucket (wallet_id, balance, counter, encrypted_balance, encrypted_counter, server_signature, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (wallet_id, balance, data.get('counter', 0), data.get('encrypted_balance'), data.get('encrypted_counter'), data.get('server_signature'), data.get('expires_at'), int(time.time()), int(time.time())))
        return True

    def get_bucket(self, wallet_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM offline_bucket WHERE wallet_id = ?", (wallet_id,)).fetchone()
            return dict(row) if row else None

    def update_bucket(self, wallet_id, *args, **kwargs):
        data = args[0] if args and isinstance(args[0], dict) else kwargs
        with self._get_connection() as conn:
            if isinstance(data, dict) and data:
                fields = []; values = []
                allowed = ['balance', 'counter', 'updated_at', 'status', 'expires_at', 'last_synced', 'encrypted_balance', 'encrypted_counter', 'server_signature', 'last_block_hash']
                for k, v in data.items():
                    if k in allowed:
                        if hasattr(v, 'value'): # Handle Mock Increment
                            fields.append(f"{k} = {k} + ?")
                            values.append(v.value)
                        else:
                            fields.append(f"{k} = ?")
                            values.append(v)
                if not fields: return True
                values.append(wallet_id)
                sql = f"UPDATE offline_bucket SET {', '.join(fields)} WHERE wallet_id = ?"
                print(f"DEBUG SQL: {sql} | {values}")
                conn.execute(sql, tuple(values))
            elif args:
                conn.execute("UPDATE offline_bucket SET balance = ?, counter = ?, updated_at = ? WHERE wallet_id = ?", (args[0], args[1] if len(args) > 1 else 0, int(time.time()), wallet_id))
        return True

    def update_bucket_counter(self, wallet_id, new_counter):
        with self._get_connection() as conn:
            cursor = conn.execute("UPDATE offline_bucket SET counter = ?, updated_at = ? WHERE wallet_id = ? AND counter = ?", (new_counter, int(time.time()), wallet_id, new_counter - 1))
            return cursor.rowcount > 0

    def add_to_queue(self, data):
        with self._get_connection() as conn:
            conn.execute("""INSERT INTO pending_queue (local_id, amount, payer_id, payee_id, counter, timestamp, payer_signature, payee_signature, status, retry_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (data['local_id'], data['amount'], data['payer_id'], data['payee_id'], data['counter'], data['timestamp'], data['payer_signature'], data.get('payee_signature'), data.get('status', 'QUEUED'), data.get('retry_count', 0), int(time.time()), int(time.time())))
        return True

    def create_transaction(self, local_id, data): return self.add_to_queue(data)
    def create_pending_transaction(self, **kwargs): return self.add_to_queue(kwargs)
    def get_pending_transactions(self, status=None, limit=100):
        with self._get_connection() as conn:
            rows = conn.execute(f"SELECT * FROM pending_queue {'WHERE status = ?' if status else ''} LIMIT ?", (status, limit) if status else (limit,)).fetchall()
            return [dict(r) for r in rows]
    def update_transaction_status(self, local_id, status, extra_data=None):
        with self._get_connection() as conn:
            if extra_data and 'retry_count' in extra_data: conn.execute("UPDATE pending_queue SET status = ?, retry_count = ?, updated_at = ? WHERE local_id = ?", (status, extra_data['retry_count'], int(time.time()), local_id))
            else: conn.execute("UPDATE pending_queue SET status = ?, updated_at = ? WHERE local_id = ?", (status, int(time.time()), local_id))
        return True
    def update_queue_status(self, local_id, status): return self.update_transaction_status(local_id, status)
    def delete_from_queue(self, local_id):
        with self._get_connection() as conn: return conn.execute("DELETE FROM pending_queue WHERE local_id = ?", (local_id,)).rowcount > 0
    def get_queue_count(self, status=None):
        with self._get_connection() as conn: return conn.execute(f"SELECT COUNT(*) FROM pending_queue {'WHERE status = ?' if status else ''}", (status,) if status else ()).fetchone()[0]
    def get_transaction_by_id(self, local_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM pending_queue WHERE local_id = ?", (local_id,)).fetchone()
            return dict(row) if row else None
    def create_ledger_entry(self, **kwargs):
        with self._get_connection() as conn:
            conn.execute("""INSERT INTO ledger_entries (transaction_id, wallet_id, amount, entry_type, balance_before, balance_after, timestamp, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (kwargs['transaction_id'], kwargs['wallet_id'], kwargs['amount'], kwargs['entry_type'], kwargs['balance_before'], kwargs['balance_after'], kwargs['timestamp'], kwargs.get('description'), int(time.time())))
        return True
    def get_ledger(self, wallet_id):
        with self._get_connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM ledger_entries WHERE wallet_id = ? ORDER BY timestamp DESC", (wallet_id,)).fetchall()]
    def create_settlement(self, local_id, transaction_id, payer_id, payee_id, amount, counter):
        with self._get_connection() as conn: conn.execute("INSERT INTO settlements (local_id, transaction_id, payer_id, payee_id, amount, counter, settled_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (local_id, transaction_id, payer_id, payee_id, amount, counter, int(time.time())))
        return True
    def get_settlement(self, local_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM settlements WHERE local_id = ?", (local_id,)).fetchone()
            return dict(row) if row else None
    def get_settlement_by_hash(self, block_hash): return self.get_settlement(block_hash)
    def get_settlement_by_counter(self, wallet_id, counter):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM settlements WHERE payer_id = ? AND counter = ?", (wallet_id, counter)).fetchone()
            return dict(row) if row else None
    def create_api_key(self, key_id, api_key, merchant_id, expires_at):
        with self._get_connection() as conn: conn.execute("INSERT INTO api_keys (key_id, api_key_hash, merchant_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", (key_id, api_key, merchant_id, int(time.time()), expires_at))
        return True
    def get_api_key(self, api_key):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE api_key_hash = ?", (api_key,)).fetchone()
            return dict(row) if row else None
    def revoke_api_key(self, api_key):
        with self._get_connection() as conn: return conn.execute("UPDATE api_keys SET revoked = 1 WHERE api_key_hash = ?", (api_key,)).rowcount > 0
    def touch_api_key(self, api_key):
        with self._get_connection() as conn: conn.execute("UPDATE api_keys SET last_used = ? WHERE api_key_hash = ?", (int(time.time()), api_key))
    def get_sync_state(self, wallet_id):
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM offline_bucket WHERE wallet_id = ?", (wallet_id,)).fetchone()
            if row:
                bucket = dict(row)
                return {"wallet_id": wallet_id, "head_counter": bucket.get("counter", 0), "head_hash": bucket.get("last_block_hash", "0" * 64), "status": bucket.get("status", "ACTIVE")}
            return {"head_counter": 0, "head_hash": "0" * 64, "status": "ACTIVE"}
    def update_sync_state(self, wallet_id, counter, block_hash, status="ACTIVE"):
        with self._get_connection() as conn: conn.execute("UPDATE offline_bucket SET counter = ?, last_block_hash = ?, status = ?, updated_at = ? WHERE wallet_id = ?", (counter, block_hash, status, int(time.time()), wallet_id))
        return True
    def clear_all_data(self):
        with self._get_connection() as conn:
            for t in ["users", "devices", "api_keys", "offline_bucket", "pending_queue", "ledger_entries", "settlements"]: conn.execute(f"DELETE FROM {t}")
            conn.commit()
    def deactivate_devices(self, wallet_id): pass
