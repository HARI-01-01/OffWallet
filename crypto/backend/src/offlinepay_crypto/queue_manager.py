# handles pending transaction queue operation
#  manages queued transaction waiting for server reconciliation

import time
import uuid
from typing import Optional,Dict,Any,Tuple

from .database import Database
from .encryptor import Encryptor
from .signer import Signer

class QueueManager:
    # Manages pending transaction queue operations
    
    MAX_RETRIES = 3
    QUEUE_STATUS_QUEUED = "QUEUED"
    QUEUE_STATUS_PROCESSED = "PROCESSED"
    QUEUE_STATUS_FAILED = "FAILED_TO_PROCESS"
    QUEUE_STATUS_PERMANENTLY_FAILED = "PERMANENTLY_FAILED"
    
    def __init__(self,db:Optional[Database]=None):
        self.db =db or Database()
        
    # Core operation
    def add_transaction(
        self,
        amount:int,
        payer_id:str,
        payee_id:str,
        counter:int,
        payer_signature:bytes,
        payee_signature:bytes=b"",
        local_id:Optional[str]=None,
    )->str:
        # add a transaction to the pending queue after nfc tap
        
        if local_id is None:
            local_id = str(uuid.uuid4())
            
        transaction = {
            'local_id':local_id,
            'amount':amount,
            'payer_id':payer_id,
            'payee_id':payee_id,
            'counter':counter,
            'timestamp':int(time.time()),
            'payer_signature':payer_signature,
            'payee_signature':payee_signature,
            'status':self.QUEUE_STATUS_QUEUED,
            'retry_count':0,
        }
        
        success = self.db.add_to_queue(transaction)
        if not success:
            raise ValueError(f"Failed to add transaction to queue: {local_id}")
        
        return local_id
    
    def get_pending_transactions(
        self,
        limit:int = 100
    )->list[Dict[str,Any]]:
        # get all queued transaction 
        return self.db.get_pending_transactions(
            status=self.QUEUE_STATUS_QUEUED,
            limit=limit
        )
    
    def get_transaction(self,local_id:str)->Optional[Dict[str,Any]]:
        # get specific transaction by local_id
        
        all_transaction = self.db.get_pending_transactions(limit=1000)
        for tx in all_transaction:
            if tx['local_id'] == local_id:
                return tx
        
        return None
    
    def mark_as_processed(self,local_id:str)->bool:
        # mark a transaction as processed
        
        return self.db.update_queue_status(
            local_id=local_id,
            status=self.QUEUE_STATUS_PROCESSED
        )
    
    def marks_as_failed(self,local_id:str)->bool:
        # mark a transaction as failed
        
        return self.db.update_queue_status(
            local_id=local_id,
            status=self.QUEUE_STATUS_FAILED
        )
    
    def marks_as_permanently_failed(self,local_id:str)->bool:
        # mark a transaction as permanently_failed
        
        return self.db.update_queue_status(
            local_id=local_id,
            status=self.QUEUE_STATUS_PERMANENTLY_FAILED
        )
    
    def increment_retry(self,local_id:str)->bool:
        # increment retry count for a transaction
        
        tx = self.get_transaction(local_id)
        if not tx:
            return False
        
        new_retry_count = tx.get('retry_count',0)+1
        
        return self.db.update_queue_status(
            local_id,
            self.QUEUE_STATUS_FAILED,
            new_retry_count
        )
        
    def should_retry(self,local_id)->Tuple[bool,Optional[str]]:
        # check if a transaction should be retried
        
        tx = self.get_transaction(local_id)
        if not tx:
            return False,"Transaction not found"
        
        status = tx.get('status')
        retry_count = tx.get('retry_count',0)
        
        if status !=self.QUEUE_STATUS_FAILED:
            return False,f"Status is  {status} not Failed"
        
        if retry_count >= self.MAX_RETRIES:
            return False,f"Max retries ({self.MAX_RETRIES}) exceeded"
        
        return True, f"Retry {retry_count+1} of {self.MAX_RETRIES}"
    
    def delete_processed(self,older_than_days:int=7)->int:
        # delete all processed transaction older then nday
        
        processed = self.db.get_pending_transactions(
            self.QUEUE_STATUS_PROCESSED,
            limit=10000
        )
        
        cutoff = int(time.time()) - (older_than_days * 86400)
        deleted_count = 0
        
        for tx in processed:
            if older_than_days <= 0 or  tx.get('created_at',0) < cutoff:
                if self.db.delete_from_queue(tx['local_id']):
                    deleted_count+=1

        return deleted_count
    
    def get_queue_count(self,status:Optional[str]=None)->int:
        # get count of transaction in queue
        
        return self.db.get_queue_count(status)
        
    def get_total_pending_amount(self)->int:
        # get total amount of all queued transaction

        pending = self.get_pending_transactions(limit=10000)
        return sum(tx.get('amount',0) for tx in pending)
    
    def has_pending(self)->bool:
        return self.get_queue_counter(self.QUEUE_STATUS_QUEUED) > 0
    
    def get_failed_transaction(self)->list[Dict[str,Any]]:
        
        return self.db.get_pending_transactions(
            self.QUEUE_STATUS_FAILED,
            limit=1000
        )
        
    def get_retryable_transaction(self)->list[Dict[str,Any]]:
        
        failed = self.get_failed_transaction()
        retryable = []
        
        for tx in failed:
            if self.should_retry(tx['local_id']):
                retryable.append(tx)
                
        return retryable
    
    def clear_all(self)->int:
        all_tx = self.db.get_pending_transactions(status=None,limit=10000)
        cnt = 0
        for tx in all_tx:
            if self.db.delete_from_queue(tx['local_id']):
                cnt+=1
        return cnt