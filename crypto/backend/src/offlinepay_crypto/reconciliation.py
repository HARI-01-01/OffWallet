# upload pending transaction to server

import time
from typing import Optional, List, Dict, Any, Tuple
from .firebase_db import FirebaseDB
from .queue_manager import QueueManager

class ReconciliationDispatcher:
    MAX_RETRIES = 3
    RETRY_DELAY = 60
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        self.queue = QueueManager(self.db)

    def is_online(self) -> bool:
        return True

    def get_pending(self) -> List[Dict[str, Any]]:
        return self.queue.get_pending_transactions()
    
    def upload_transaction(self, transaction: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        # In production: Send HTTPS POST to /api/v1/offline/reconcile
        return True, None
    
    def mark_synced(self, local_id: str) -> bool:
        return self.queue.mark_as_processed(local_id)
    
    def mark_failed(self, local_id: str) -> bool:
        return self.queue.mark_as_failed(local_id)
    
    def should_try(self, local_id: str) -> bool:
        tx = self.queue.get_transaction(local_id)
        if not tx:
            return False
        
        retry_count = tx.get('retry_count', 0)
        return retry_count < self.MAX_RETRIES

    def sync_all(self) -> Dict[str, int]:
        if not self.is_online():
            return {'synced': 0, 'failed': 0, 'retryable': 0}
        
        pending = self.get_pending()
        result = {'synced': 0, 'failed': 0, 'retryable': 0}
        
        for tx in pending:
            local_id = tx['local_id']
            success, error = self.upload_transaction(tx)
            if success:
                if self.mark_synced(local_id):
                    result['synced'] += 1
            else:
                if self.should_try(local_id):
                    self.mark_failed(local_id)
                    result['retryable'] += 1
                else:
                    self.queue.mark_as_permanently_failed(local_id)
                    result['failed'] += 1
        return result
        
    def sync_single(self, local_id: str) -> Tuple[bool, str]:
        if not self.is_online():
            return False, "Offline"
        
        tx = self.queue.get_transaction(local_id)
        if not tx: 
            return False, "NOT_FOUND"
        success, error = self.upload_transaction(tx)
        
        if success:
            self.mark_synced(local_id)
            return True, "SYNCED"
        if self.should_try(local_id):
            self.mark_failed(local_id)
            return False, "RETRY"

        self.queue.mark_as_permanently_failed(local_id)
        return False, "FAILED"
    
    def get_sync_status(self) -> Dict[str, Any]:
        pending = self.get_pending()
        return {
            'pending_count': len(pending),
            'pending_amount': sum(tx.get('amount', 0) for tx in pending),
            'failed_count': self.queue.get_queue_count('FAILED_TO_PROCESS'),
            'is_online': self.is_online(),
        }
