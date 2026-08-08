import asyncio
from uuid import uuid4

import pytest

from src.main import UploadTransactionRequest, sync_ingest


def test_sync_ingest_handles_non_hex_signatures():
    request = UploadTransactionRequest(
        local_id=f"uuid-{uuid4().hex}",
        amount=1000,
        payer_id="alice_123",
        payee_id="bob_456",
        counter=1,
        timestamp=1704067500,
        payer_signature="a1b2c3d4e5f6...",
        payee_signature="f6e5d4c3b2a1...",
        device_id="device_xyz",
        api_key="sk_test_12345",
    )

    with pytest.raises(Exception) as exc_info:
        asyncio.run(sync_ingest(request))

    assert getattr(exc_info.value, "status_code", None) == 401
