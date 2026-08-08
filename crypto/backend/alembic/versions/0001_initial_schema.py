"""initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-08-03 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("device_id", sa.String(), primary_key=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_seen", sa.BigInteger()),
        sa.Column("status", sa.String(), nullable=False, server_default=sa.text("'ACTIVE'")),
    )

    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.String(), primary_key=True),
        sa.Column("api_key_hash", sa.String(), nullable=False, unique=True),
        sa.Column("merchant_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("expires_at", sa.BigInteger()),
        sa.Column("revoked", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_used", sa.BigInteger()),
    )

    op.create_table(
        "users",
        sa.Column("wallet_id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("phone", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
    )

    op.create_table(
        "offline_bucket",
        sa.Column("wallet_id", sa.String(), primary_key=True),
        sa.Column("balance", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("counter", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("encrypted_balance", sa.LargeBinary()),
        sa.Column("encrypted_counter", sa.LargeBinary()),
        sa.Column("server_signature", sa.LargeBinary()),
        sa.Column("created_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("expires_at", sa.BigInteger()),
        sa.Column("last_synced", sa.BigInteger()),
        sa.Column("status", sa.String(), nullable=False, server_default=sa.text("'ACTIVE'")),
    )

    op.create_table(
        "pending_queue",
        sa.Column("local_id", sa.String(), primary_key=True),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("payer_id", sa.String(), nullable=False),
        sa.Column("payee_id", sa.String(), nullable=False),
        sa.Column("counter", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.BigInteger(), nullable=False),
        sa.Column("payer_signature", sa.LargeBinary(), nullable=False),
        sa.Column("payee_signature", sa.LargeBinary()),
        sa.Column("status", sa.String(), nullable=False, server_default=sa.text("'QUEUED'")),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
    )

    op.create_table(
        "ledger_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("transaction_id", sa.String(), nullable=False),
        sa.Column("wallet_id", sa.String(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("entry_type", sa.String(), nullable=False),
        sa.Column("balance_before", sa.Integer(), nullable=False),
        sa.Column("balance_after", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.BigInteger(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
    )

    op.create_table(
        "settlements",
        sa.Column("local_id", sa.String(), primary_key=True),
        sa.Column("transaction_id", sa.String(), nullable=False),
        sa.Column("payer_id", sa.String(), nullable=False),
        sa.Column("payee_id", sa.String(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("counter", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default=sa.text("'SETTLED'")),
        sa.Column("settled_at", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
    )

    op.create_index("idx_queue_status", "pending_queue", ["status"])
    op.create_index("idx_queue_created", "pending_queue", ["created_at"])
    op.create_index("idx_bucket_status", "offline_bucket", ["status"])
    op.create_index("idx_ledger_wallet", "ledger_entries", ["wallet_id"])
    op.create_index("idx_ledger_tx", "ledger_entries", ["transaction_id"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_index("idx_ledger_tx", table_name="ledger_entries")
    op.drop_index("idx_ledger_wallet", table_name="ledger_entries")
    op.drop_index("idx_bucket_status", table_name="offline_bucket")
    op.drop_index("idx_queue_created", table_name="pending_queue")
    op.drop_index("idx_queue_status", table_name="pending_queue")
    op.drop_table("settlements")
    op.drop_table("ledger_entries")
    op.drop_table("pending_queue")
    op.drop_table("offline_bucket")