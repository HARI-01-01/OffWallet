"""Simple alert helpers for system issues."""

from __future__ import annotations

from typing import Any, Dict

from .logging_utils import get_logger, log_event
from .notification import NotificationDispatcher


class AlertManager:
    def __init__(self, notifier: NotificationDispatcher | None = None):
        self.notifier = notifier or NotificationDispatcher()
        self.logger = get_logger("offlinepay.alerts")

    def raise_alert(self, title: str, body: str, details: Dict[str, Any] | None = None) -> bool:
        log_event(self.logger, "alert", title, level="warning", context=details or {})
        return self.notifier.send_push(
            user_id="admin",
            title=title,
            body=body,
            data={"type": "SYSTEM_ALERT", **(details or {})},
        )
