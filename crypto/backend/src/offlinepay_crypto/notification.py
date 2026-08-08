"""
Webhook & Notification Dispatcher: Sends notifications to users and third-party systems.
Minimal implementation for push, webhook, and fallback notifications.
"""

import json
import time
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict


@dataclass
class Notification:
    """Notification data structure."""
    user_id: str
    title: str
    body: str
    type: str  
    data: Dict[str, Any]
    timestamp: int


@dataclass
class WebhookPayload:
    event: str
    data: Dict[str, Any]
    timestamp: int


class NotificationDispatcher:
    def __init__(self):
        """Initialize dispatcher."""
        self._notification_store = []  # In-memory store for testing

    # ---------- Push Notifications ----------

    def send_push(
        self,
        user_id: str,
        title: str,
        body: str,
        data: Dict[str, Any],
    ) -> bool:
        # In production: Use FCM (Android) / APNs (iOS)
        notification = Notification(
            user_id=user_id,
            title=title,
            body=body,
            type=data.get('type', 'GENERAL'),
            data=data,
            timestamp=int(time.time()),
        )
        print(f"📱 Push to {user_id}: {title}")
        print(f"   {body}")

        # Store for in-app
        self._notification_store.append(asdict(notification))
        return True

    def notify_payment_sent(
        self,
        user_id: str,
        amount: int,
        payee_id: str,
        transaction_id: str,
        balance_after: int,
    ) -> bool:
        return self.send_push(
            user_id=user_id,
            title="Payment Sent",
            body=f"You sent ${amount/100:.2f} to {payee_id} successfully!",
            data={
                "type": "PAYMENT_SENT",
                "amount": amount,
                "payee": payee_id,
                "transaction_id": transaction_id,
                "balance_after": balance_after,
                "status": "SUCCESS",
            },
        )

    def notify_payment_received(
        self,
        user_id: str,
        amount: int,
        payer_id: str,
        transaction_id: str,
        balance_after: int,
    ) -> bool:
        return self.send_push(
            user_id=user_id,
            title="Payment Received",
            body=f"You received ${amount/100:.2f} from {payer_id}!",
            data={
                "type": "PAYMENT_RECEIVED",
                "amount": amount,
                "payer": payer_id,
                "transaction_id": transaction_id,
                "balance_after": balance_after,
                "status": "SUCCESS",
            },
        )

    def notify_fraud_alert(
        self,
        user_id: str,
        local_id: str,
        reason: str,
    ) -> bool:
        return self.send_push(
            user_id=user_id,
            title="Fraud Alert",
            body=f"Suspicious activity detected on transaction {local_id}. Contact support.",
            data={
                "type": "FRAUD_ALERT",
                "local_id": local_id,
                "reason": reason,
                "status": "FRAUD",
            },
        )

    def notify_transaction_failed(
        self,
        user_id: str,
        amount: int,
        payee_id: str,
        reason: str,
    ) -> bool:
        return self.send_push(
            user_id=user_id,
            title="Transaction Failed",
            body=f"Payment of ${amount/100:.2f} to {payee_id} failed: {reason}",
            data={
                "type": "PAYMENT_FAILED",
                "amount": amount,
                "payee": payee_id,
                "reason": reason,
                "status": "FAILED",
            },
        )

    # ---------- Webhooks ----------

    def webhook_send(
        self,
        user_id: str,
        event: str,
        data: Dict[str, Any],
    ) -> bool:
        """
        Send webhook to third-party systems.

        In production: Send HTTP POST to registered webhook endpoints
        """
        payload = WebhookPayload(
            event=event,
            data=data,
            timestamp=int(time.time()),
        )

        print(f"🔗 Webhook to {user_id}: {event}")
        print(f"   Data: {json.dumps(data)[:100]}...")

        return True

    def webhook_settlement(
        self,
        user_id: str,
        transaction_id: str,
        amount: int,
        payer_id: str,
        payee_id: str,
        status: str,
    ) -> bool:
        return self.webhook_send(
            user_id=user_id,
            event="transaction.settled",
            data={
                "transaction_id": transaction_id,
                "amount": amount,
                "payer_id": payer_id,
                "payee_id": payee_id,
                "status": status,
                "currency": "USD",
            },
        )

    # ---------- In-App Notifications ----------

    def get_in_app_notifications(
        self,
        user_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get in-app notifications for a user."""
        notifications = [
            n for n in self._notification_store
            if n.get('user_id') == user_id
        ]
        return notifications[-limit:] if notifications else []

    def mark_notification_read(
        self,
        user_id: str,
        notification_id: int,
    ) -> bool:
        """Mark a notification as read."""
        # In production: update database
        return True

    def clear_notifications(self, user_id: str) -> int:
        """Clear all notifications for a user."""
        before = len(self._notification_store)
        self._notification_store = [
            n for n in self._notification_store
            if n.get('user_id') != user_id
        ]
        return before - len(self._notification_store)

    # ---------- Fallback: Email/SMS ----------

    def send_email(
        self,
        email: str,
        subject: str,
        body: str,
    ) -> bool:
        print(f"📧 Email to {email}: {subject}")
        print(f"   {body}")
        return True

    def send_sms(
        self,
        phone: str,
        message: str,
    ) -> bool:
        print(f"📱 SMS to {phone}: {message[:50]}...")
        return True

    def notify_payment_sent_fallback(
        self,
        email: str,
        phone: str,
        amount: int,
        payee_id: str,
        transaction_id: str,
    ) -> None:
        self.send_email(
            email=email,
            subject=f"Payment Sent: ${amount/100:.2f} to {payee_id}",
            body=f"Transaction ID: {transaction_id}\nAmount: ${amount/100:.2f}\nPayee: {payee_id}",
        )
        self.send_sms(
            phone=phone,
            message=f"${amount/100:.2f} sent to {payee_id}. Txn: {transaction_id[:8]}",
        )