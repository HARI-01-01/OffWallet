# double spend detection engin: validates incoming transaction

import time
from typing import Optional,Tuple,Dict,Any

from .database import Database

class DoubleSpendDetector:
    def __init__(self,db:Optional[Database]=None):
        self.db = db or Database
        
    def validate(
        self,
        payer_id:str,
        counter:int,
        amount:int,
        local_id:str,
    )->Tuple[bool,Optional[str],Dict[str,Any]]:
        # validate incoming transaction.
        
        bucket = self.db.get_bucket(payer_id)
        if not bucket:
            return False,'Payer not found',{}
        if  bucket.get('status') == 'FROZEN':
            return False, "Bucket frozen", {'status':"Frozen"}
        last_counter = bucket.get('counter',0)
        
        if counter<=last_counter:
            fraud_type = self._classify_fraud(counter,last_counter)
            return False,f"Fraud detected: {fraud_type}",{
                "fraud_type":fraud_type,
                "last_counter":last_counter,
                "incoming_counter":counter,
            }
        
        if counter!=last_counter+1:
            return False, "Counter gap detected", {
                "fraud_type": "COUNTER_GAP",
                "last_counter": last_counter,
                "incoming_counter": counter,
            }
        balance = bucket.get('balance',0)
        if balance< amount:
            return False, "Insufficient balance",{
                "balance":balance,
                "amount":amount,
            }
        return True,None,{}    
        
    def _classify_fraud(self,counter:int,last_counter:int)->str:
        if counter == last_counter:
            return "DOUBLE_SPEND"
        if counter < last_counter:
            return "REPLAY_ATTACK"
        
        return "INVAILD_COUNTER"
    
    def process_transaction(
        self,
        data:Dict[str,Any]
    )->Tuple[bool,Optional[str],Dict[str,Any]]:
        payer_id = data.get('payer_id')
        counter = data.get('counter')
        amount = data.get('amount')
        local_id = data.get('local_id')
        
        vaild,error,fraud_info = self.validate(
            payer_id,
            counter,
            amount,local_id
        )
        if not vaild:
            self._log_fraud(
                local_id,payer_id,counter,fraud_info
            )
        
            if fraud_info.get('fraud_type') in ['DOUBLE_SPEND', 'REPLAY_ATTACK', 'COUNTER_GAP']:
                self._freeze_bucket(payer_id,fraud_info['fraud_type'])
            
            return False,error,fraud_info
        self._reverse_funds(payer_id,counter,amount)
        return True,None,{'status':"RESERVED"}
    
    def _log_fraud(
        self,
        local_id:str,
        payer_id:str,
        counter:str,
        fraud_info:Dict[str,Any],
    )->None:
         # In production: insert into fraud_log table
        print(f"FRAUD DETECTED: {fraud_info.get('fraud_type')}")
        print(f"   Payer: {payer_id}, Counter: {counter}")
        print(f"   Details: {fraud_info}")
        
    def _freeze_bucket(self,payer_id:str,reason:str)->bool:
        return self.db.update_bucket(
            payer_id,'FORZEN'
        )
    
    def _reserve_funds(self,payer_id:str,counter:int,amount:int)->bool:
        bucket = self.db.get_bucket(payer_id)
        if not bucket:
            return False
        
        new_balance = bucket.get('balance',0) - amount
        
        return self.db.update_bucket(
            payer_id,
            counter,
            new_balance,
            int(time.time())
        )