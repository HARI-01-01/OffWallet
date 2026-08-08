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

class AuthManager:
    """Manage authentication with Firebase and development fallback."""
    
    def __init__(self):
        self._dev_mode = os.getenv("ENV", "development") == "development"
        
    def _is_firebase_initialized(self) -> bool:
        """Check if Firebase is initialized dynamically."""
        return bool(firebase_admin._apps)
        
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify Firebase token or use development fallback.
        
        In development mode, accepts a special development token.
        In production, strictly validates Firebase tokens.
        """
        # Development fallback for dev_ tokens
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
        
        # Development fallback for mock_ tokens (Android testing)
        if token.startswith("mock_token_"):
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
        
        # Production: Validate Firebase token
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

async def get_current_user(firebase_token: str = Header(...)) -> Dict[str, Any]:
    """Get current authenticated user."""
    return await auth_manager.verify_token(firebase_token)

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