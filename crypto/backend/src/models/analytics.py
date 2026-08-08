from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class UserStats(BaseModel):
    total_users: int
    active_users: int
    new_users_today: int
    users_by_status: dict


class TransactionStats(BaseModel):
    total_transactions: int
    total_volume: int
    transactions_today: int
    volume_today: int
    pending_count: int
    failed_count: int
    settled_count: int
    fraud_detected: int


class BucketStats(BaseModel):
    total_buckets: int
    total_balance: int
    average_balance: int
    frozen_count: int
    expired_count: int


class SystemHealth(BaseModel):
    status: str
    uptime: int
    database_connected: bool
    redis_connected: bool
    queue_size: int
    memory_usage: float
    cpu_usage: float


class ActivityLog(BaseModel):
    timestamp: datetime
    event_type: str
    user_id: Optional[str]
    details: dict
    ip_address: Optional[str] = None
