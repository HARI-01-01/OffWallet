# handle SQLite database schema and connection
# all sensitive data is encrypted at the application
import sqlite3
import os
from typing import Optional,List,Dict,Any

class Database:
    # manages sqlite databasae connection and schema
    
    DB_PATH="offline_wallet.db"
    
    def __init__(self,db_path:Optional[str]=None):
        self.db_path = db_path or Database.DB_PATH
        self._init_db()
        
    def _init_db(self):
        """Create tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Table 1: offline_bucket
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS offline_bucket (
                    wallet_id TEXT PRIMARY KEY,
                    balance INTEGER DEFAULT 0,
                    counter INTEGER DEFAULT 0,
                    encrypted_balance BLOB,
                    encrypted_counter BLOB,
                    server_signature BLOB,
                    created_at INTEGER DEFAULT (strftime('%s', 'now')),
                    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
                    expires_at INTEGER,
                    last_synced INTEGER,
                    status TEXT DEFAULT 'ACTIVE'
                )
            """)

            # Table 2: pending_queue
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pending_queue (
                    local_id TEXT PRIMARY KEY,
                    amount INTEGER NOT NULL,
                    payer_id TEXT NOT NULL,
                    payee_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    payer_signature BLOB NOT NULL,
                    payee_signature BLOB,
                    status TEXT DEFAULT 'QUEUED',
                    retry_count INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT (strftime('%s', 'now')),
                    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)

            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_queue_status 
                ON pending_queue (status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_queue_created 
                ON pending_queue (created_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_bucket_status 
                ON offline_bucket (status)
            """)

            conn.commit()
        
    def _get_connection(self)->sqlite3.Connection:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        
    # # Bucket operation
    def get_bucket(self,wallet_id:str)->Optional[Dict[str,Any]]:
            # get user offline bucket
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                "SELECT * FROM offline_bucket WHERE wallet_id = ?",
                (wallet_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
    
    def create_bucket(
        self,
        wallet_id:str,
        balance:int=0,
        counter:int=0,
        encrypted_balance:bytes = b"",
        encrypted_counter:bytes = b"",
        server_signature:bytes = b"",
        expires_at:Optional[int]=None,
    )->bool:
        # create a new offline bucket
        import time
        
        if expires_at is None:
            expires_at = int(time.time())+86400
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO offline_bucket (
                    wallet_id, balance, counter,
                    encrypted_balance, encrypted_counter,
                    server_signature, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                wallet_id, balance, counter,
                encrypted_balance, encrypted_counter,
                server_signature, expires_at
            ))
            conn.commit()
            return True
        
    def update_bucket(
            self,
            wallet_id:str,
            balance:Optional[int]=None,
            counter:Optional[int]=None,
            encrypted_balance:Optional[bytes]=None,
            encrypted_counter:Optional[bytes]=None,
            server_signature:Optional[bytes]=None,
            expires_at:Optional[int]=None,
            last_synced:Optional[int]=None,
            status:Optional[str]=None
        )->bool:
            import time
            updates = []
            params = []
            
            if balance is not None:
                updates.append("balance = ?")
                params.append(balance)
            if counter is not None:
                updates.append("counter = ?")
                params.append(counter)
            if encrypted_balance is not None:
                updates.append("encrypted_balance = ?")
                params.append(encrypted_balance)
            if encrypted_counter is not None:
                updates.append("encrypted_counter = ?")
                params.append(encrypted_counter)
            if server_signature is not None:
                updates.append("server_signature = ?")
                params.append(server_signature)
            if last_synced is not None:
                updates.append("last_synced = ?")
                params.append(last_synced)
            if status is not None:
                updates.append("status = ?")
                params.append(status)
            if expires_at is not None:
                updates.append("expires_at = ?")
                params.append(expires_at)
                
            if not updates:
                return True
            
            updates.append("updated_at = ?")
            params.append(int(time.time()))
            params.append(wallet_id)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"""
                UPDATE offline_bucket 
                SET {', '.join(updates)}
                WHERE wallet_id = ?
            """, params)
                conn.commit()
                return cursor.rowcount > 0
    def update_bucket_counter(self,wallet_id:str,new_counter:int)->bool:
        # atomicity update counter
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE offline_bucket 
                SET counter = ?, updated_at = strftime('%s', 'now')
                WHERE wallet_id = ? AND counter = ? - 1
            """, (new_counter, wallet_id, new_counter))
            conn.commit()
            return cursor.rowcount > 0
            
            
    # # Pending Queue operation
    def add_to_queue(self,transaction:Dict[str,Any])->bool:
        # add a transaction to the pending queue
        import time
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pending_queue (
                    local_id, amount, payer_id, payee_id,
                    counter, timestamp, payer_signature,
                    payee_signature, status, retry_count,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transaction['local_id'],
                transaction['amount'],
                transaction['payer_id'],
                transaction['payee_id'],
                transaction['counter'],
                transaction['timestamp'],
                transaction['payer_signature'],
                transaction.get('payee_signature', b''),
                transaction.get('status', 'QUEUED'),
                transaction.get('retry_count', 0),
                int(time.time()),
                int(time.time()),
            ))
            conn.commit()
            return True
        
    def get_pending_transactions(
        self,
        status:Optional[str]=None,
        limit:int=100
    )->List[Dict[str,Any]]:
        #  get transaction from the pending queue
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("""
                    SELECT * FROM pending_queue 
                    WHERE status = ?
                    ORDER BY created_at ASC
                    LIMIT ?
                """, (status, limit))
            else:
                cursor.execute("""
                    SELECT * FROM pending_queue 
                    ORDER BY created_at ASC
                    LIMIT ?
                """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
        
    def update_queue_status(
        self,
        local_id:str,
        status:str,
        retry_count:Optional[int] = None,
    )->bool:
        # update a transaction status in the queue
        import time
        updates = ["status = ?", "updated_at = ?"]
        params = [status, int(time.time())]

        if retry_count is not None:
            updates.append("retry_count = ?")
            params.append(retry_count)

        params.append(local_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE pending_queue 
                SET {', '.join(updates)}
                WHERE local_id = ?
            """, params)
            conn.commit()
            return cursor.rowcount > 0
    def delete_from_queue(self,local_id:str)->bool:
        # delete a transaction from the queue (after processing..)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM pending_queue WHERE local_id = ?",
                (local_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        
    def get_queue_count(self,status:Optional[str]=None)->int:
        # get count of transaction in queue
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    "SELECT COUNT(*) FROM pending_queue WHERE status = ?",
                    (status,)
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM pending_queue")
            return cursor.fetchone()[0]
    def clear_all_data(self) -> None:
        """Clear all data from tables (for testing)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM offline_bucket")
            cursor.execute("DELETE FROM pending_queue")
            conn.commit()