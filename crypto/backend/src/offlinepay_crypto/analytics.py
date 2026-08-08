"""Analytics and monitoring for the offline payment backend."""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import redis

import psutil
from sqlalchemy import func, select

from models.analytics import ActivityLog, BucketStats, SystemHealth, TransactionStats, UserStats

from .database import Database, api_keys, devices, ledger_entries, offline_bucket, pending_queue, settlements, users
from .logging_utils import get_logger, log_event
from .notification import NotificationDispatcher


class Analytics:
    """System monitoring and analytics."""

    def __init__(self, db: Database, redis_client=None, notifier: Optional[NotificationDispatcher] = None):
        self.db = db
        self.redis = redis_client
        self.notifier = notifier or NotificationDispatcher()
        self.start_time = time.time()
        self.logger = get_logger("offlinepay.analytics")

    def _row_count(self, statement) -> int:
        with self.db.engine.connect() as connection:
            return int(connection.execute(statement).scalar_one())

    def _check_redis(self) -> bool:
        if self.redis is not None:
            try:
                return bool(self.redis.ping())
            except Exception:
                return False

        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            return False

        try:

            client = redis.from_url(redis_url, decode_responses=True)
            ok = bool(client.ping())
            if ok:
                self.redis = client
            return ok
        except Exception:
            return False

    def get_user_stats(self) -> Dict[str, Any]:
        today_cutoff = int(time.time()) - 86400
        with self.db.engine.connect() as connection:
            total_users = int(connection.execute(select(func.count()).select_from(users)).scalar_one())
            active_users = int(
                connection.execute(
                    select(func.count(func.distinct(offline_bucket.c.wallet_id))).where(offline_bucket.c.balance > 0)
                ).scalar_one()
            )
            new_users_today = int(
                connection.execute(
                    select(func.count()).select_from(users).where(users.c.created_at > today_cutoff)
                ).scalar_one()
            )
            status_rows = connection.execute(
                select(offline_bucket.c.status, func.count()).group_by(offline_bucket.c.status)
            ).all()

        users_by_status = {row[0]: int(row[1]) for row in status_rows}
        return UserStats(
            total_users=total_users,
            active_users=active_users,
            new_users_today=new_users_today,
            users_by_status=users_by_status,
        ).model_dump()

    def get_transaction_stats(self) -> Dict[str, Any]:
        today_cutoff = int(time.time()) - 86400
        with self.db.engine.connect() as connection:
            total_transactions = int(connection.execute(select(func.count()).select_from(pending_queue)).scalar_one())
            total_volume = int(
                connection.execute(select(func.coalesce(func.sum(pending_queue.c.amount), 0))).scalar_one()
            )
            today_row = connection.execute(
                select(
                    func.count(),
                    func.coalesce(func.sum(pending_queue.c.amount), 0),
                ).select_from(pending_queue).where(pending_queue.c.created_at > today_cutoff)
            ).one()
            status_rows = connection.execute(
                select(pending_queue.c.status, func.count()).group_by(pending_queue.c.status)
            ).all()
            fraud_rows = connection.execute(
                select(func.count()).select_from(pending_queue).where(pending_queue.c.status == "FRAUD_DETECTED")
            ).scalar_one()

        status_counts = {row[0]: int(row[1]) for row in status_rows}
        return TransactionStats(
            total_transactions=total_transactions,
            total_volume=total_volume,
            transactions_today=int(today_row[0] or 0),
            volume_today=int(today_row[1] or 0),
            pending_count=status_counts.get("QUEUED", 0),
            failed_count=status_counts.get("FAILED_TO_PROCESS", 0),
            settled_count=status_counts.get("PROCESSED", 0),
            fraud_detected=int(fraud_rows or 0),
        ).model_dump()

    def get_bucket_stats(self) -> Dict[str, Any]:
        with self.db.engine.connect() as connection:
            total_buckets = int(connection.execute(select(func.count()).select_from(offline_bucket)).scalar_one())
            total_balance = int(
                connection.execute(select(func.coalesce(func.sum(offline_bucket.c.balance), 0))).scalar_one()
            )
            frozen_count = int(
                connection.execute(select(func.count()).select_from(offline_bucket).where(offline_bucket.c.status == "FROZEN")).scalar_one()
            )
            expired_count = int(
                connection.execute(
                    select(func.count()).select_from(offline_bucket).where(offline_bucket.c.expires_at < int(time.time()))
                ).scalar_one()
            )

        average_balance = int(total_balance / total_buckets) if total_buckets else 0
        return BucketStats(
            total_buckets=total_buckets,
            total_balance=total_balance,
            average_balance=average_balance,
            frozen_count=frozen_count,
            expired_count=expired_count,
        ).model_dump()

    def get_system_health(self) -> Dict[str, Any]:
        uptime = int(time.time() - self.start_time)
        try:
            with self.db.engine.connect() as connection:
                connection.execute(select(func.count()).select_from(users)).scalar_one()
            db_connected = True
        except Exception:
            db_connected = False

        redis_connected = self._check_redis()
        queue_size = 0
        if redis_connected and self.redis is not None:
            try:
                queue_size = int(self.redis.llen("transaction_queue"))
            except Exception:
                queue_size = 0
        else:
            try:
                queue_size = int(self.db.get_queue_count("QUEUED"))
            except Exception:
                queue_size = 0

        memory = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.0)
        status = "healthy" if db_connected else "unhealthy"

        health = SystemHealth(
            status=status,
            uptime=uptime,
            database_connected=db_connected,
            redis_connected=redis_connected,
            queue_size=queue_size,
            memory_usage=round(memory.used / memory.total * 100, 1),
            cpu_usage=round(cpu, 1),
        ).model_dump()

        if not db_connected or not redis_connected:
            log_event(
                self.logger,
                "system_health",
                "System health degraded",
                level="warning",
                context=health,
            )
            self.notifier.send_push(
                user_id="admin",
                title="System Health Alert",
                body="Offline payment backend health degraded.",
                data={"type": "SYSTEM_ALERT", "health": health},
            )
        return health

    def get_activity_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.db.engine.connect() as connection:
            rows = connection.execute(
                select(
                    pending_queue.c.local_id,
                    pending_queue.c.amount,
                    pending_queue.c.payer_id,
                    pending_queue.c.payee_id,
                    pending_queue.c.status,
                    pending_queue.c.created_at,
                )
                .order_by(pending_queue.c.created_at.desc())
                .limit(limit)
            ).all()

        logs: List[Dict[str, Any]] = []
        for row in rows:
            log = ActivityLog(
                timestamp=datetime.fromtimestamp(int(row[5])),
                event_type="transaction",
                user_id=row[2],
                details={
                    "local_id": row[0],
                    "amount": row[1],
                    "payee": row[3],
                    "status": row[4],
                },
                ip_address=None,
            )
            logs.append(log.model_dump())
        return logs

    def get_dashboard(self) -> Dict[str, Any]:
        dashboard = {
            "users": self.get_user_stats(),
            "transactions": self.get_transaction_stats(),
            "buckets": self.get_bucket_stats(),
            "health": self.get_system_health(),
            "activity": self.get_activity_logs(20),
            "timestamp": datetime.now().isoformat(),
        }
        log_event(self.logger, "dashboard", "Dashboard data requested", context={"activity_count": len(dashboard["activity"])})
        return dashboard
