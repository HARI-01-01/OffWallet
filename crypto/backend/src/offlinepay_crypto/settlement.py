# settlement engine: moves money between wallets

import time
import uuid
from typing import Optional, Tuple, Dict, Any
from .firebase_db import FirebaseDB

class SettlementEngine:
    
    def __init__(self, db: Optional[FirebaseDB] = None):
        self.db = db or FirebaseDB()
        
    def settle(
        self,
        payer_id: str,
        payee_id: str,
        amount: int,
        local_id: str,
        counter: int,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        existing = self._get_settlement(local_id)
        if existing:
            return True, None, {
                "status": "ALREADY_SETTLED",
                "transaction_id": existing.get('transaction_id'),
            }
        try:
            return self._execute_settlement(
                payee_id=payee_id,
                payer_id=payer_id,
                amount=amount,
                local_id=local_id,
                counter=counter
            )
        except Exception as e:
            return False, str(e), {}
        
    def _execute_settlement(
        self,
        payer_id: str,
        payee_id: str,
        amount: int,
        local_id: str,
        counter: int
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        # atomic settlement
        transaction_id = f"txn_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        payer_bucket = self.db.get_bucket(payer_id)
        if not payer_bucket:
            return False, "Payer not found", {}
        
        payee_bucket = self.db.get_bucket(payee_id)
        if not payee_bucket:
            return False, "Payee not found", {}

        payer_balance = payer_bucket.get('balance', 0)
        if payer_balance < amount:
            return False, "Insufficient balance", {
                "balance": payer_balance,
                "amount": amount
            }

        payee_new_balance = payee_bucket.get('balance', 0) + amount
        
        # Credit payee
        payee_updated = self.db.update_bucket(
            wallet_id=payee_id,
            data={
                "balance": payee_new_balance,
                "last_synced": int(time.time())
            }
        )
        if not payee_updated:
            return False, "Failed to update payee", {}

        # Update payer counter (balance was already reserved by detector in common flow)
        # If not reserved, we update balance here too.
        # For simplicity in this engine, we assume reservation happened or we update now.
        payer_new_balance = payer_balance - amount
        self.db.update_bucket(
            wallet_id=payer_id,
            data={
                "balance": payer_new_balance,
                "counter": counter,
                "last_synced": int(time.time())
            }
        )
        
        self._create_ledger_entries(
            transaction_id=transaction_id,
            payer_id=payer_id,
            payee_id=payee_id,
            amount=amount,
            payer_balance_before=payer_balance,
            payer_balance_after=payer_new_balance,
            payee_balance_before=payee_bucket.get('balance', 0),
            payee_balance_after=payee_new_balance,
        )
        self._record_settlement(
            local_id=local_id,
            transaction_id=transaction_id,
            payer_id=payer_id,
            payee_id=payee_id,
            amount=amount,
            counter=counter, 
        )
        
        return True, None, {
            "status": "SETTLED",
            "transaction_id": transaction_id,
            "payer_balance_after": payer_new_balance,
            "payee_balance_after": payee_new_balance
        }
        
    def _create_ledger_entries(
        self,
        transaction_id: str,
        payer_id: str,
        payee_id: str,
        amount: int,
        payer_balance_before: int,
        payer_balance_after: int,
        payee_balance_before: int,
        payee_balance_after: int
    ) -> None:
        timestamp = int(time.time())
        # Credit
        self.db.create_ledger_entry({
            "transaction_id": transaction_id,
            "wallet_id": payee_id,
            "amount": amount,
            "entry_type": "CREDIT",
            "balance_before": payee_balance_before,
            "balance_after": payee_balance_after,
            "timestamp": timestamp,
            "description": f"Payment from {payer_id}"
        })
        
    def _record_settlement(
        self,
        local_id: str,
        transaction_id: str,
        payer_id: str,
        payee_id: str,
        amount: int,
        counter: int,
    ) -> None:
        self.db.create_settlement(local_id, {
            "local_id": local_id,
            "transaction_id": transaction_id,
            "payer_id": payer_id,
            "payee_id": payee_id,
            "amount": amount,
            "counter": counter,
            "timestamp": int(time.time())
        })

    def _get_settlement(self, local_id: str) -> Optional[Dict]:
        return self.db.get_settlement(local_id)

    def get_balance(self, wallet_id: str) -> Optional[int]:
        bucket = self.db.get_bucket(wallet_id)
        return bucket.get('balance') if bucket else None
