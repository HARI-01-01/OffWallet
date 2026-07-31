#!/usr/bin/env python3
"""
Test script for BucketManager.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offlinepay_crypto.bucket_manager import BucketManager
from offlinepay_crypto.encryptor import Encryptor
from offlinepay_crypto.key_manager import KeyManager
from offlinepay_crypto.signer import Signer


def test_bucket_manager():
    print("💰 Testing BucketManager...")
    print("-" * 40)

    # 1. Setup: Generate server keys and AES key
    server_private, server_public = KeyManager.generate_key_pair()
    aes_key = Encryptor.generate_key()

    # 2. Create bucket manager
    manager = BucketManager()
    wallet_id = "alice_123"

    # 3. Server signs bucket
    initial_balance = 5000  # $50
    bucket_data = f"{wallet_id}:{initial_balance}:0".encode()
    server_signature = Signer.sign(server_private, bucket_data)

    # 4. Create bucket
    print("Creating bucket with $50...")
    manager.create_bucket(
        wallet_id=wallet_id,
        initial_balance=initial_balance,
        aes_key=aes_key,
        server_public_key=server_public,
        server_signature=server_signature,
    )
    print("✅ Bucket created")

    # 5. Check balance
    balance = manager.check_balance(wallet_id, aes_key)
    print(f"Balance: ${balance/100:.2f}")
    assert balance == 5000

    # 6. Test deduct funds
    print("\nTesting deduction of $10...")
    success, new_balance, new_counter, error = manager.deduct_funds(
        wallet_id, 1000, aes_key
    )
    print(f"Success: {success}")
    print(f"New balance: ${new_balance/100:.2f}")
    print(f"New counter: {new_counter}")
    assert new_balance == 4000
    assert new_counter == 1

    # 7. Check counter
    counter = manager.get_counter(wallet_id, aes_key)
    print(f"Counter: {counter}")
    assert counter == 1

    # 8. Test insufficient funds
    print("\nTesting insufficient funds deduction of $100...")
    success, new_balance, new_counter, error = manager.deduct_funds(
        wallet_id, 10000, aes_key
    )
    print(f"Success: {success}")
    print(f"Error: {error}")
    assert success is False
    assert error == "Insufficient balance"

    # 9. Test add funds
    print("\nTesting add funds ($20)...")
    new_balance = 6000  # $60
    bucket_data = f"{wallet_id}:{new_balance}:1".encode()
    server_signature = Signer.sign(server_private, bucket_data)

    success, new_balance, error = manager.add_funds(
        wallet_id=wallet_id,
        amount=2000,
        aes_key=aes_key,
        server_public_key=server_public,
        server_signature=server_signature,
    )
    print(f"Success: {success}")
    print(f"New balance: ${new_balance/100:.2f}")
    assert new_balance == 6000

    # 10. Test expiry check
    print("\nTesting expiry check...")
    is_expired = manager.is_expired(wallet_id)
    print(f"Is expired: {is_expired}")
    assert is_expired is False

    print("-" * 40)
    print("🎉 All BucketManager tests complete!")


if __name__ == "__main__":
    test_bucket_manager()