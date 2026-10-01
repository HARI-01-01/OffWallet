"""Authentication utilities with Firebase and fallback for testing."""

from __future__ import annotations

import os
import hashlib
import time
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Header

# Firebase imports
import firebase_admin
from firebase_admin import auth

from .logging_utils import get_logger

logger = get_logger("offlinepay.auth")

import jwt

# ... (rest of imports)

class AuthManager:
    # ... (rest of methods)

    def generate_device_token(self, payload: Dict[str, Any]) -> str:
        """Generate a long-lived JWT for an active device."""
        secret = os.getenv("DEVICE_JWT_SECRET", "shadow-v1-fallback-secret-long-enough-32bytes")
        return jwt.encode(payload, secret, algorithm="HS256")
    """Manage authentication with Firebase and development fallback."""
    
    def __init__(self):
        # Strictly gate dev mode to 'development' environment string
        self._dev_mode = os.getenv("ENV", "production").lower() == "development"
        
    def _is_firebase_initialized(self) -> bool:
        """Check if Firebase is initialized dynamically."""
        return bool(firebase_admin._apps)
        
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify Firebase token or use development fallback.
        """
        # 1. Development fallback for dev_ tokens
        if self._dev_mode and token.startswith("dev_"):
            wallet_id = token.replace("dev_", "")
            return {
                "uid": wallet_id,
                "wallet_id": wallet_id,
                "email": f"{wallet_id}@dev.local",
                "phone_number": "+1234567890",
                "email_verified": True,
                "phone_verified": True,
                "dev_mode": True
            }
        
        # 2. Development fallback for mock_ tokens (Android testing)
        if self._dev_mode and token.startswith("mock_token_"):
            wallet_id = token.replace("mock_token_", "")
            return {
                "uid": wallet_id,
                "wallet_id": wallet_id,
                "email": f"{wallet_id}@mock.local",
                "phone_number": "+1234567890",
                "email_verified": True,
                "phone_verified": True,
                "dev_mode": True
            }

        # 3. Check for Device JWT (Shadow Protocol Long-lived Token)
        # These are HS256 signed with our internal secret
        try:
            secret = os.getenv("DEVICE_JWT_SECRET", "shadow-v1-fallback-secret-long-enough-32bytes")
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            # If successfully decoded, it's a valid device token
            decoded["dev_mode"] = False # Treat as production-grade auth
            return decoded
        except (jwt.InvalidTokenError, jwt.DecodeError):
            # Not our device token, proceed to Firebase check
            pass

        # 4. Production: Validate Firebase token
        if not self._is_firebase_initialized():
            # If Firebase is not initialized but we're in dev mode, fall back to dev mode
            if self._dev_mode:
                logger.warning(f"Firebase not initialized, falling back to dev mode for token: {token[:10]}...")
                return {
                    "uid": "dev_fallback",
                    "wallet_id": "dev_fallback",
                    "email": "dev@fallback.local",
                    "phone_number": "+1234567890",
                    "email_verified": True,
                    "phone_verified": True,
                    "dev_mode": True
                }
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Firebase not initialized"
            )
        
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except auth.InvalidIdTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        except auth.ExpiredIdTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except auth.RevokedIdTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {str(e)}"
            )

# Create global auth manager instance
auth_manager = AuthManager()

async def get_current_user(firebase_token: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Get current authenticated user."""
    if not firebase_token:
        # Check if we are in a dashboard/admin context and in dev mode
        if os.getenv("ENV", "production").lower() == "development":
            logger.warning("No token provided, using admin fallback for development")
            return {
                "uid": "admin",
                "wallet_id": "admin",
                "email": "admin@dev.local",
                "dev_mode": True
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing firebase-token header"
        )

    logger.info(f"Authenticating user with token: {firebase_token[:15]}...")
    user = await auth_manager.verify_token(firebase_token)
    logger.info(f"User authenticated: {user.get('wallet_id') or user.get('uid')}")
    return user

async def get_current_user_optional(
    authorization: Optional[str] = Header(None)
) -> Optional[Dict[str, Any]]:
    """Get current user if authenticated, or None."""
    if not authorization:
        return None
    
    if authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        try:
            return await auth_manager.verify_token(token)
        except HTTPException:
            return None
    
    return None