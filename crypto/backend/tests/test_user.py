"""
Tests for UserManager persistence.
"""

from src.offlinepay_crypto.key_manager import KeyManager
from src.offlinepay_crypto.signer import Signer
from src.offlinepay_crypto.user import UserManager


def test_register_user_persists_user(temp_db):
	manager = UserManager(temp_db)
	server_priv, server_pub = KeyManager.generate_key_pair()
	server_priv_bytes = KeyManager.private_key_to_bytes(server_priv)
	server_pub_bytes = KeyManager.public_key_to_bytes(server_pub)

	success, error, user_data = manager.register_user(
		email="alice@example.com",
		phone="+1234567890",
		password="secure_password",
		initial_balance=5000,
		server_private_key=server_priv_bytes,
		server_public_key=server_pub_bytes,
	)

	assert success is True
	assert error is None
	assert user_data["wallet_id"]

	stored_user = temp_db.get_user(user_data["wallet_id"])
	assert stored_user is not None
	assert stored_user["email"] == "alice@example.com"

	bucket = temp_db.get_bucket(user_data["wallet_id"])
	assert bucket is not None
	bucket_data = f"{user_data['wallet_id']}:5000:0".encode()
	assert Signer.verify_with_bytes(server_pub_bytes, bucket_data, Signer.sign_with_bytes(server_priv_bytes, bucket_data))
