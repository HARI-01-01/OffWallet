"""
Shadow Protocol v1 Handshake Engine.
Implements the M1-M4 protocol flow used during Alice-to-Bob NFC/BLE transfers.
"""

import time
import secrets
from typing import Optional, Tuple, Dict, Any
from .hasher import Hasher
from .signer import Signer
from .serializer import Serializer

class NFCHandshake:

    @staticmethod
    def verify_m1_presentation(
        payload: Dict[str, Any],
        active_sid: str,
        expected_payer_id: Optional[str] = None
    ) -> bool:
        """
        Payee (Bob) verifies Alice's presentation.
        """
        # 1. SID Check (Ticket Verification)
        if payload.get("sid") != active_sid:
            return False
            
        # 2. Payer ID Check (Optional binding if Bob only wants one Alice)
        if expected_payer_id and payload.get("walletId") != expected_payer_id:
            return False

        return True

    @staticmethod
    def build_m2_response(
        ble_uuid: str,
        challenge_b: bytes,
        private_key_b: bytes
    ) -> Dict[str, Any]:
        """
        Bob generates the challenge response.
        """
        # In the full protocol Bob also signs Alice's challenge to prove identity
        return {
            'ble_uuid': ble_uuid,
            'challenge': challenge_b.hex()
        }

    @staticmethod
    def build_debit_block_m3(
        wallet_id: str,
        payee_id: str,
        amount: int,
        sid: str,
        challenge_b: bytes,
        private_key_a: bytes,
        prev_hash: str,
        counter: int
    ) -> Dict[str, Any]:
        """
        Alice generates the signed payment block.
        """
        timestamp = int(time.time())
        
        # Block data to be signed
        block = {
            'v': 1,
            'chain_id': 'SHADOW',
            'wallet_id': wallet_id,
            'payee_wallet_id': payee_id,
            'amount_p': amount,
            'sid': sid,
            'payee_chal': challenge_b.hex(),
            'prev_hash': prev_hash,
            'counter': counter,
            'ts': timestamp
        }
        
        # Canonical representation for signing
        # Format aligned with App's Serializer
        data_to_sign = f"{sid}:{amount}:{wallet_id}:{payee_id}:{counter}:{timestamp}".encode()
        
        block['sig_A'] = Signer.sign_with_bytes(private_key_a, data_to_sign).hex()
        return block

    @staticmethod
    def verify_debit_block_m3(
        block: Dict[str, Any],
        payer_public_key: bytes
    ) -> bool:
        """
        Bob verifies Alice's payment block.
        """
        try:
            sid = block['sid']
            amount = block['amount_p']
            wallet_id = block['wallet_id']
            payee_id = block['payee_wallet_id']
            counter = block['counter']
            timestamp = block['ts']
            sig_a = bytes.fromhex(block['sig_A'])
            
            data_to_verify = f"{sid}:{amount}:{wallet_id}:{payee_id}:{counter}:{timestamp}".encode()
            
            return Signer.verify_with_bytes(payer_public_key, data_to_verify, sig_a)
        except Exception:
            return False
