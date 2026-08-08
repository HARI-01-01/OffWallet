"""
Tests for analytics and dashboard monitoring.
"""

import asyncio

import src.main as main
from src.offlinepay_crypto.analytics import Analytics


def test_analytics_dashboard_metrics(temp_db, monkeypatch):
    temp_db.create_user(
        wallet_id="user_1",
        email="user1@example.com",
        phone="+1234567890",
        password_hash="hash1",
        public_key=b"pub1",
    )
    temp_db.create_bucket("user_1", balance=5000, counter=0)
    temp_db.create_bucket("user_2", balance=0, counter=0)
    temp_db.update_bucket("user_2", status="FROZEN")
    temp_db.create_pending_transaction(
        local_id="tx_1",
        amount=1000,
        payer_id="user_1",
        payee_id="user_2",
        counter=1,
        timestamp=1234567890,
        payer_signature=b"a" * 64,
        payee_signature=b"b" * 64,
        status="QUEUED",
    )

    analytics = Analytics(temp_db)

    user_stats = analytics.get_user_stats()
    transaction_stats = analytics.get_transaction_stats()
    bucket_stats = analytics.get_bucket_stats()
    health = analytics.get_system_health()
    dashboard = analytics.get_dashboard()

    assert user_stats["total_users"] == 1
    assert transaction_stats["total_transactions"] == 1
    assert bucket_stats["total_buckets"] == 2
    assert health["status"] in {"healthy", "unhealthy"}
    assert dashboard["users"]["total_users"] == 1


def test_dashboard_route_serves_html(monkeypatch, temp_db):
    monkeypatch.setattr(main, "database", temp_db)
    monkeypatch.setattr(main, "analytics", Analytics(temp_db))

    html = asyncio.run(main.dashboard())
    assert "Offline Payment Monitoring" in html
