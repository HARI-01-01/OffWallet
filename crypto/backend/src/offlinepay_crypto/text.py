#!/usr/bin/env python3
"""
Test Double-Spend Detection Engine.
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offlinepay_crypto.detection import DoubleSpendDetector
from offlinepay_crypto.database import Database


def setup_test_data():
    """Create test bucket."""
    db = Database()
    db.clear_all_data()

    db.create_bucket(
        wallet_id="alice_123",
        balance=5000,
        counter=0,
        encrypted_balance=b"",
        encrypted_counter=b"",
        server_signature=b"",
        expires_at=9999999999,
    )
    return db


def test_detection():
    print("🔍 Testing Double-Spend Detection...")
    print("-" * 40)

    # 1. Setup
    db = setup_test_data()
    detector = DoubleSpendDetector(db)
    print("✅ Detector initialized")

    # 2. Valid transaction
    print("\n1. Testing valid transaction...")
    valid, error, info = detector.validate(
        payer_id="alice_123",
        counter=1,
        amount=1000,
        local_id=str(uuid.uuid4()),
    )
    print(f"Valid: {valid}, Error: {error}")
    assert valid

    # 3. Double-spend attempt
    print("\n2. Testing double-spend (same counter)...")
    valid, error, info = detector.validate(
        payer_id="alice_123",
        counter=1,
        amount=1000,
        local_id=str(uuid.uuid4()),
    )
    print(f"Valid: {valid}, Error: {error}")
    print(f"Fraud info: {info}")
    assert not valid
    assert info.get('fraud_type') == 'DOUBLE_SPEND'

    # 4. Replay attack (older counter)
    print("\n3. Testing replay attack (counter 0)...")
    valid, error, info = detector.validate(
        payer_id="alice_123",
        counter=0,
        amount=1000,
        local_id=str(uuid.uuid4()),
    )
    print(f"Valid: {valid}, Error: {error}")
    assert not valid
    assert info.get('fraud_type') == 'REPLAY_ATTACK'

    # 5. Counter gap (skipped counters)
    print("\n4. Testing counter gap (counter 5)...")
    valid, error, info = detector.validate(
        payer_id="alice_123",
        counter=5,
        amount=1000,
        local_id=str(uuid.uuid4()),
    )
    print(f"Valid: {valid}, Error: {error}")
    assert not valid
    assert info.get('fraud_type') == 'COUNTER_GAP'

    # 6. Insufficient balance
    print("\n5. Testing insufficient balance ($100)...")
    valid, error, info = detector.validate(
        payer_id="alice_123",
        counter=3,
        amount=10000,
        local_id=str(uuid.uuid4()),
    )
    print(f"Valid: {valid}, Error: {error}")
    assert not valid
    assert 'balance' in str(error)

    # 7. Test bucket freeze
    print("\n6. Testing bucket freeze...")
    bucket = db.get_bucket("alice_123")
    print(f"Status before: {bucket.get('status')}")
    detector._freeze_bucket("alice_123", "FRAUD_TEST")
    bucket = db.get_bucket("alice_123")
    print(f"Status after: {bucket.get('status')}")
    assert bucket.get('status') == 'FROZEN'

    print("-" * 40)
    print("🎉 All detection tests complete!")


if __name__ == "__main__":
    test_detection()