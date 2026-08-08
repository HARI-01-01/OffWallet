# automatically retries failed transaction
# users exponential backoff to retry up to 3 times over 7 days

import time
from typing import Optional, List, Dict, Any, Tuple
from .firebase_db import FirebaseDB
from .queue_manager import QueueManager

# These imports might still exist and need refactoring if they use old Database
# For now, we align the scheduler itself.
from .detection import DoubleSpendDetector
from .settlement import SettlementEngine

class AutoRescueScheduler:
    
    MAX_RETRIES = 3
    BASE_DELAY = 300 # 5 MIN
    MAX_WINDOW = 604800 # 7 DAY
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        self.queue = QueueManager(self.db)
        
    def get_retryable_transaction(self) -> List[Dict[str, Any]]:
        return self.queue.get_retryable_transaction()
    
    def should_retry(self, transaction: Dict[str, Any]) -> Tuple[bool, str]:
        local_id = transaction.get('local_id')
        retry_count = transaction.get('retry_count', 0)
        created_at = transaction.get('created_at', 0)
        
        if retry_count >= self.MAX_RETRIES:
            return False, f"Max retries ({self.MAX_RETRIES}) exceeded"
        
        if int(time.time()) - created_at > self.MAX_WINDOW:
            return False, "Time Window 7 day exceeded"
        
        return True, f"Retry {retry_count + 1} of { self.MAX_RETRIES}"
    
    def get_next_retry_time(self, retry_count: int) -> int:
        delay = self.BASE_DELAY * (2**retry_count)
        return int(time.time()) + delay
    
    def retry_transaction(self, transaction: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict]]:
        local_id = transaction.get('local_id')
        payer_id = transaction.get('payer_id')
        payee_id = transaction.get('payee_id')
        amount = transaction.get('amount')
        counter = transaction.get('counter')
        
        should, reason = self.should_retry(transaction)
        if not should:
            return False, reason, None
        
        detector = DoubleSpendDetector(self.db)
        valid, error, fraud_info = detector.validate(
            payer_id=payer_id,
            counter=counter,
            amount=amount,
            local_id=local_id,
            update=False,
        )
        if not valid:
            self.queue.mark_as_permanently_failed(local_id=local_id)
            return False, f"Validation failed: {error}", fraud_info
        
        engine = SettlementEngine(self.db)
        success, error, result = engine.settle(
            payer_id=payer_id,
            payee_id=payee_id,
            amount=amount,
            local_id=local_id,
            counter=counter,
        )
        if success:
            self.queue.mark_as_processed(local_id)
            return True, "SETTLED", result
        self.queue.increment_retry(local_id)
        
        return False, f"Settlement failed: {error}", result
    
    def run(self) -> Dict[str, int]:
        # run auto rescue scheduler
        retryable = self.get_retryable_transaction()
        
        result = {'processed': 0, 'retried': 0, 'failed': 0}
        for tx in retryable:
            success, status, data = self.retry_transaction(tx)
            if success:
                result['processed'] += 1
            else:
                if 'Max retries' in status or '7 days' in status:
                    result['failed'] += 1
                else:
                    result['retried'] += 1
        return result
    
    def clear(self) -> int:
        return self.queue.clear_all()
    
    def get_stats(self) -> Dict[str, int]:
        failed = self.queue.get_failed_transaction()
        retryable = self.queue.get_retryable_transaction()
        processed = self.queue.get_queue_count()
        
        return {
            'failed_count': len(failed),
            'retryable_count': len(retryable),
            'processed_count': (processed),
        }   
