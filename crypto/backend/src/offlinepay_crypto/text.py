#!/usr/bin/env python3
"""
Test User Management & Replenishment.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offlinepay_crypto.user import UserManager
from offlinepay_crypto.key_manager import KeyManager


def test_user_manager():
    print("👤 Testing User Management...")
    print("-" * 40)

    # 1. Setup
    manager = UserManager()
    print("✅ UserManager initialized")

    # 2. Generate server keys
    server_priv, server_pub = KeyManager.generate_key_pair()
    server_priv_bytes = KeyManager.private_key_to_bytes(server_priv)
    server_pub_bytes = KeyManager.public_key_to_bytes(server_pub)

    # 3. Register user
    print("\n1. Registering user...")
    success, error, user_data = manager.register_user(
        email="alice@example.com",
        phone="+1234567890",
        password="secure_password",
        initial_balance=5000,
        server_private_key=server_priv_bytes,
        server_public_key=server_pub_bytes,
    )
    print(f"Success: {success}")
    print(f"Wallet ID: {user_data.get('wallet_id')}")
    assert success

    wallet_id = user_data['wallet_id']
    aes_key = bytes.fromhex(user_data['aes_key'])

    # 4. Check balance
    print("\n2. Checking balance...")
    balance = manager.get_balance(wallet_id, aes_key)
    print(f"Balance: ${balance/100:.2f}")
    assert balance == 5000

    # 5. Generate 2FA code
    print("\n3. Generating 2FA code...")
    otp = manager.generate_2fa_code(wallet_id)
    print(f"OTP: {otp}")
    assert len(otp) == 6

    # 6. Add funds
    print("\n4. Adding funds ($20)...")
    success, error, result = manager.add_funds(
        wallet_id=wallet_id,
        amount=2000,
        aes_key=aes_key,
        server_private_key=server_priv_bytes,
        server_public_key=server_pub_bytes,
        twofa_code=otp,
    )
    print(f"Success: {success}")
    print(f"Result: {result}")
    assert success
    assert result['new_balance'] == 7000

    # 7. Check updated balance
    print("\n5. Checking updated balance...")
    balance = manager.get_balance(wallet_id, aes_key)
    print(f"Balance: ${balance/100:.2f}")
    assert balance == 7000

    # 8. Test account freeze
    print("\n6. Testing account freeze...")
    success = manager.freeze_account(wallet_id)
    print(f"Freeze success: {success}")
    assert success

    status = manager.check_bucket_status(wallet_id)
    print(f"Status after freeze: {status}")
    assert status == 'FROZEN'

    # 9. Test account unfreeze
    print("\n7. Testing account unfreeze...")
    success = manager.unfreeze_account(wallet_id)
    print(f"Unfreeze success: {success}")
    assert success

    status = manager.check_bucket_status(wallet_id)
    print(f"Status after unfreeze: {status}")
    assert status == 'ACTIVE'

    print("-" * 40)
    print("🎉 All User Management tests complete!")


if __name__ == "__main__":
    test_user_manager()