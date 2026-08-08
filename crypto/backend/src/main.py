"""Offline Payment System - Backend API Server with Firebase Auth."""

from __future__ import annotations

import os
import sys
import time
import hashlib
import secrets
from pathlib import Path
from typing import Any, Dict, Optional,List
from datetime import datetime
import json

# Setup path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Firebase
import firebase_admin
from firebase_admin import credentials, auth

# Local imports
from offlinepay_crypto.auto_rescue import AutoRescueScheduler
from offlinepay_crypto.firebase_db import FirebaseDB
from offlinepay_crypto.user_firebase import UserManagerFirebase
from offlinepay_crypto.bucket_manager import BucketManager
from offlinepay_crypto.key_manager import KeyManager
from offlinepay_crypto.signer import Signer
from offlinepay_crypto.encryptor import Encryptor
from offlinepay_crypto.logging_utils import get_logger, log_event
from offlinepay_crypto.notification import NotificationDispatcher
from offlinepay_crypto.auth import get_current_user, get_current_user_optional, auth_manager
from offlinepay_crypto.lite_wallet import LiteWalletManager  # Add this
load_dotenv()

# ============ FIREBASE INITIALIZATION ============

def init_firebase():
    """Initialize Firebase Admin SDK."""
    try:
        if firebase_admin._apps:
            return firebase_admin.get_app()
        
        # Check for credentials in multiple locations
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
        
        if not cred_path or not os.path.exists(cred_path):
            src_cred_path = SRC_DIR / "firebase-adminsdk.json"
            if src_cred_path.exists():
                cred_path = str(src_cred_path)
        
        if not cred_path or not os.path.exists(cred_path):
            current_cred_path = Path("firebase-adminsdk.json")
            if current_cred_path.exists():
                cred_path = str(current_cred_path)
        
        if not cred_path or not os.path.exists(cred_path):
            print("⚠️ Firebase credentials not found - running in development mode")
            return None
        
        cred = credentials.Certificate(cred_path)
        app = firebase_admin.initialize_app(cred)
        print(f"✅ Firebase Admin SDK initialized with: {cred_path}")
        return app
    except Exception as e:
        print(f"⚠️ Failed to initialize Firebase: {e}")
        return None

# Initialize Firebase
firebase_app = init_firebase()

# ============ APP SETUP ============
app = FastAPI(
    title="Offline Payment System API",
    description="Backend API with Firebase Phone OTP Authentication",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ SERVICES ============
db = FirebaseDB(skip_initialization=firebase_app is None)
logger = get_logger("offlinepay.api")
user_manager = UserManagerFirebase(db)
bucket_manager = BucketManager(db)
notifications = NotificationDispatcher()

# ============ PYDANTIC MODELS ============

class RegisterRequest(BaseModel):
    """User registration request."""
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$", description="User's email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    wallet_name: str = Field(default="My Wallet", min_length=1, max_length=50, description="Wallet name")
    initial_deposit: int = Field(default=0, ge=0, le=100000000, description="Initial deposit in cents (max $1,000,000)")

class LoginRequest(BaseModel):
    """User login request with email and password."""
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$", description="User's email address")
    password: str = Field(..., min_length=8, description="Password")

class FirebaseLoginRequest(BaseModel):
    """Firebase login request with phone and token."""
    phone: str = Field(..., description="Phone number with country code")
    firebase_token: str = Field(..., description="Firebase ID token from authentication")

class VerifyTokenRequest(BaseModel):
    """Verify Firebase token request."""
    firebase_token: str = Field(..., description="Firebase ID token to verify")

class AddFundsRequest(BaseModel):
    """Add funds request."""
    wallet_id: str
    amount: int = Field(gt=0)
    firebase_token: str = Field(default="", description="Firebase token (optional in dev mode)")

class SendPaymentRequest(BaseModel):
    """Send payment request."""
    payer_id: str
    payee_id: str
    amount: int = Field(gt=0)
    payer_signature: str = Field(default="")

class TopupLiteRequest(BaseModel):
    """Top up lite wallet request."""
    amount: int = Field(gt=0, le=50000000, description="Amount in cents (max $500,000)")
    wallet_id: str = Field(..., description="Wallet ID")

# ============ AUTH ENDPOINTS ============

@app.post("/api/v1/auth/register", status_code=status.HTTP_201_CREATED)
async def register_user(request: RegisterRequest) -> Dict[str, Any]:
    """Register a new user with minimal fields."""
    try:
        # Generate wallet_id from email
        wallet_id = f"user_{hashlib.sha256(request.email.encode()).hexdigest()[:8]}"
        
        # Check if user already exists
        existing_user = db.get_user(wallet_id)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Generate wallet keys
        private_key, public_key = KeyManager.generate_key_pair()
        private_key_bytes = KeyManager.private_key_to_bytes(private_key)
        public_key_bytes = KeyManager.public_key_to_bytes(public_key)
        aes_key = Encryptor.generate_key()
        
        # ✅ USE MASTER KEY
        server_private_key, server_public_key = KeyManager.get_master_server_key()
        server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)
        server_public_key_bytes = KeyManager.public_key_to_bytes(server_public_key)
        
        # ✅ Standardized format: wallet_id|balance|counter
        bucket_data = f"{wallet_id}|{request.initial_deposit}|0".encode()
        server_signature = Signer.sign_with_bytes(server_private_key_bytes, bucket_data)
        
        # Create bucket using the bucket manager
        success = bucket_manager.create_bucket(
            wallet_id=wallet_id,
            initial_balance=request.initial_deposit,
            aes_key=aes_key,
            server_public_key=server_public_key_bytes,
            server_signature=server_signature,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create wallet bucket"
            )
        
        # Hash password
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        
        # Store user in Firestore - WITH ALL KEYS
        user_data = {
            "email": request.email,
            "password_hash": password_hash,
            "wallet_name": request.wallet_name,
            "public_key": public_key_bytes.hex(),
            "private_key": private_key_bytes.hex(),
            "aes_key": aes_key.hex(),
            "server_public_key": server_public_key_bytes.hex(),
            "server_signature": server_signature.hex(),  # ✅ Store signature
            "status": "ACTIVE",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }
        db.create_user(wallet_id, user_data)
        
        # Store metadata
        meta_data = {
            "wallet_name": request.wallet_name,
            "initial_deposit": request.initial_deposit,
        }
        db.create_user_meta(wallet_id, meta_data)
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "public_key": public_key_bytes.hex(),
                "private_key": private_key_bytes.hex(),
                "aes_key": aes_key.hex(),
                "server_public_key": server_public_key_bytes.hex(),
                "server_signature": server_signature.hex(),  # ✅ Return signature
                "balance": request.initial_deposit,
                "wallet_name": request.wallet_name,
                "message": "User registered successfully!",
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/api/v1/auth/login")
async def login_user(request: LoginRequest) -> Dict[str, Any]:
    """Login user with email and password."""
    try:
        import json
        
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        wallet_id = f"user_{hashlib.sha256(request.email.encode()).hexdigest()[:8]}"
        
        user_data = db.get_user(wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        if user_data.get("password_hash") != password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        bucket = db.get_bucket(wallet_id)
        dev_mode = os.getenv("ENV", "development") == "development"
        
        # Generate QR data
        name = user_data.get("full_name") or user_data.get("wallet_name") or user_data.get("email", "User")
        qr_data = {
            "wallet_id": wallet_id,
            "name": name,
            "type": "payment_request",
            "version": "1.0"
        }
        
        # ---- GET CURRENT BALANCE AND COUNTER ----
        current_balance = bucket.get("balance", 0) if bucket else 0
        counter = bucket.get("counter", 0) if bucket else 0
        
        # ---- ALWAYS GENERATE FRESH SIGNATURE USING MASTER KEY ----
        server_private_key, server_public_key = KeyManager.get_master_server_key()
        server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)
        server_public_key_bytes = KeyManager.public_key_to_bytes(server_public_key)
        
        # ✅ Standardized format: wallet_id|balance|counter
        bucket_data = f"{wallet_id}|{current_balance}|{counter}".encode()
        server_signature = Signer.sign_with_bytes(server_private_key_bytes, bucket_data)
        
        # ---- Check and generate keys if missing ----
        private_key = user_data.get("private_key", "")
        public_key = user_data.get("public_key", "")
        aes_key = user_data.get("aes_key", "")
        
        # If keys are missing, generate them now
        if not private_key or not public_key or not aes_key:
            logger.info(f"Keys missing for user {wallet_id}. Generating new keys...")
            
            # Generate wallet keys
            new_private_key, new_public_key = KeyManager.generate_key_pair()
            new_private_key_bytes = KeyManager.private_key_to_bytes(new_private_key)
            new_public_key_bytes = KeyManager.public_key_to_bytes(new_public_key)
            new_aes_key = Encryptor.generate_key()
            
            # Save to user document
            update_data = {
                "private_key": new_private_key_bytes.hex(),
                "public_key": new_public_key_bytes.hex(),
                "aes_key": new_aes_key.hex(),
                "server_public_key": server_public_key_bytes.hex(),
                "server_signature": server_signature.hex(),  # ✅ Store the NEW signature
                "updated_at": int(time.time())
            }
            db.update_user(wallet_id, update_data)
            
            # Set the variables for response
            private_key = new_private_key_bytes.hex()
            public_key = new_public_key_bytes.hex()
            aes_key = new_aes_key.hex()
        else:
            # Update server signature in database with fresh one
            update_data = {
                "server_signature": server_signature.hex(),  # ✅ Store the NEW signature
                "server_public_key": server_public_key_bytes.hex(),
                "updated_at": int(time.time())
            }
            db.update_user(wallet_id, update_data)
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "email": user_data.get("email"),
                "wallet_name": user_data.get("wallet_name", "My Wallet"),
                "balance": current_balance,  # ✅ Fresh balance
                "counter": counter,           # ✅ Current counter
                "status": user_data.get("status", "ACTIVE"),
                "dev_token": f"dev_{wallet_id}" if dev_mode else None,
                "qr_data": json.dumps(qr_data),
                "qr_name": name,
                # ---- Cryptographic keys ----
                "private_key": private_key,
                "public_key": public_key,
                "aes_key": aes_key,
                "server_public_key": server_public_key_bytes.hex(),  # ✅ Fresh public key
                "server_signature": server_signature.hex(),  # ✅ FRESH SIGNATURE!
                "message": "Login successful!",
                "keys_provided": bool(private_key and public_key and aes_key)
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@app.post("/api/v1/auth/firebase-login")
async def firebase_login(request: FirebaseLoginRequest) -> Dict[str, Any]:
    """Login using Firebase authentication (phone + token)."""
    try:
        decoded_token = await auth_manager.verify_token(request.firebase_token)
        
        # Check if in dev mode
        if decoded_token.get("dev_mode"):
            wallet_id = decoded_token.get("wallet_id")
            user_data = db.get_user(wallet_id)
            if not user_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            bucket = db.get_bucket(wallet_id)
            return {
                "status": "success",
                "data": {
                    "wallet_id": wallet_id,
                    "email": user_data.get("email"),
                    "phone": request.phone,
                    "wallet_name": user_data.get("wallet_name"),
                    "balance": bucket.get("balance", 0) if bucket else 0,
                    "status": user_data.get("status", "ACTIVE"),
                    "dev_mode": True,
                    "message": "Development login successful!",
                },
            }
        
        firebase_uid = decoded_token.get("uid")
        wallet_id = f"user_{firebase_uid[:8]}"
        
        user_data = db.get_user(wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in system. Please register first."
            )
        
        bucket = db.get_bucket(wallet_id)
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "email": user_data.get("email"),
                "phone": request.phone,
                "wallet_name": user_data.get("wallet_name"),
                "balance": bucket.get("balance", 0) if bucket else 0,
                "status": user_data.get("status", "ACTIVE"),
                "firebase_uid": firebase_uid,
                "message": "Firebase login successful!",
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firebase login error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Firebase login failed: {str(e)}"
        )

@app.post("/api/v1/auth/verify-token")
async def verify_token(request: VerifyTokenRequest) -> Dict[str, Any]:
    """Verify a Firebase token and return user info."""
    try:
        decoded_token = await auth_manager.verify_token(request.firebase_token)
        
        return {
            "status": "success",
            "data": {
                "uid": decoded_token.get("uid"),
                "phone": decoded_token.get("phone_number"),
                "email": decoded_token.get("email"),
                "email_verified": decoded_token.get("email_verified", False),
                "firebase_verified": True,
                "expires_at": datetime.fromtimestamp(
                    decoded_token.get("exp", 0)
                ).isoformat(),
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify token error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}"
        )

@app.post("/api/v1/auth/logout")
async def logout_user(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Logout user."""
    return {
        "status": "success",
        "message": "User is authenticated. Logout client-side.",
        "user": {
            "uid": user.get("uid"),
            "wallet_id": user.get("wallet_id"),
            "phone": user.get("phone_number"),
        },
    }

# ============ USER ENDPOINTS ============

@app.get("/api/v1/user/profile")
async def get_user_profile(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get the current user's profile."""
    try:
        # Handle dev mode
        if user.get("dev_mode"):
            wallet_id = user.get("wallet_id")
        else:
            firebase_uid = user.get("uid")
            wallet_id = f"user_{firebase_uid[:8]}"
        
        user_data = db.get_user(wallet_id)
        meta_data = db.get_user_meta(wallet_id)
        bucket = db.get_bucket(wallet_id)
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "email": user_data.get("email"),
                "phone": user_data.get("phone"),
                "full_name": user_data.get("full_name"),
                "balance": bucket.get("balance", 0) if bucket else 0,
                "counter": bucket.get("counter", 0) if bucket else 0,
                "status": user_data.get("status", "ACTIVE"),
                "currency": meta_data.get("currency", "USD") if meta_data else "USD",
                "wallet_name": meta_data.get("wallet_name") if meta_data else "My Wallet",
                "created_at": user_data.get("created_at"),
                "phone_verified": True,
                "dev_mode": user.get("dev_mode", False),
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/api/v1/user/{wallet_id}/balance")
async def get_balance(
    wallet_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get wallet balance."""
    try:
        # Handle dev mode or Firebase auth
        if user.get("dev_mode"):
            # In dev mode, user.wallet_id should match the requested wallet_id
            if user.get("wallet_id") != wallet_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            # Production: Verify Firebase UID matches
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if wallet_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        bucket = db.get_bucket(wallet_id)
        if not bucket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Wallet not found"
            )
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "balance": bucket.get("balance", 0),
                "counter": bucket.get("counter", 0),
                "status": bucket.get("status", "UNKNOWN"),
                "expires_at": bucket.get("expires_at"),
                "dev_mode": user.get("dev_mode", False),
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Balance error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
# ============ RESCUE/RETRY ENDPOINTS ============


# Initialize rescue scheduler
rescue_scheduler = AutoRescueScheduler(db)

@app.post("/api/v1/rescue/run")
async def run_rescue(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Run the auto-rescue scheduler to retry failed transactions.
    This processes failed transactions with exponential backoff.
    """
    try:
        # Verify admin access (optional - for security)
        # For now, allow any authenticated user
        
        result = rescue_scheduler.run()
        
        return {
            "status": "success",
            "data": {
                "processed": result.get("processed", 0),
                "retried": result.get("retried", 0),
                "failed": result.get("failed", 0),
                "message": f"Processed {result.get('processed', 0)} transactions"
            }
        }
        
    except Exception as e:
        logger.error(f"Rescue run error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to run rescue: {str(e)}"
        )


@app.get("/api/v1/rescue/stats")
async def get_rescue_stats(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get statistics about failed and retryable transactions.
    """
    try:
        stats = rescue_scheduler.get_stats()
        
        return {
            "status": "success",
            "data": {
                "failed_count": stats.get("failed_count", 0),
                "retryable_count": stats.get("retryable_count", 0),
                "processed_count": stats.get("processed_count", 0),
                "message": "Rescue stats retrieved"
            }
        }
        
    except Exception as e:
        logger.error(f"Rescue stats error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get rescue stats: {str(e)}"
        )


@app.delete("/api/v1/rescue/clear")
async def clear_rescue_queue(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Clear all failed transactions from the queue.
    """
    try:
        count = rescue_scheduler.clear()
        
        return {
            "status": "success",
            "data": {
                "cleared_count": count,
                "message": f"Cleared {count} transactions"
            }
        }
        
    except Exception as e:
        logger.error(f"Clear rescue error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear rescue queue: {str(e)}"
        )
# ============ WALLET STATUS ENDPOINT ============

@app.get("/api/v1/user/{wallet_id}/status")
async def get_wallet_status(
    wallet_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get wallet status (ACTIVE, FROZEN, EXPIRED)."""
    try:
        # Handle dev mode or Firebase auth
        if user.get("dev_mode"):
            # In dev mode, user.wallet_id should match the requested wallet_id
            if user.get("wallet_id") != wallet_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            # Production: Verify Firebase UID matches
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if wallet_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        # Get bucket data
        bucket = db.get_bucket(wallet_id)
        if not bucket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Wallet not found"
            )
        
        # Get user data for additional info
        user_data = db.get_user(wallet_id)
        
        # Check if expired
        current_time = int(time.time())
        expires_at = bucket.get("expires_at", 0)
        is_expired = expires_at < current_time
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "status": bucket.get("status", "UNKNOWN"),
                "is_expired": is_expired,
                "expires_at": expires_at,
                "balance": bucket.get("balance", 0),
                "counter": bucket.get("counter", 0),
                "created_at": bucket.get("created_at", 0),
                "last_synced": bucket.get("last_synced", 0),
                "user_status": user_data.get("status", "ACTIVE") if user_data else "UNKNOWN",
                "dev_mode": user.get("dev_mode", False),
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Wallet status error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
# ============ WALLET ENDPOINTS ============

@app.post("/api/v1/wallet/add-funds")
async def add_funds(
    request: AddFundsRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Add funds to wallet."""
    try:
        # Handle dev mode or Firebase auth
        if user.get("dev_mode"):
            # In dev mode, user.wallet_id should match the requested wallet_id
            if user.get("wallet_id") != request.wallet_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            # Production: Verify Firebase UID matches
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if request.wallet_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        # Get user data
        user_data = db.get_user(request.wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        aes_key = bytes.fromhex(user_data.get("aes_key", ""))
        if not aes_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AES key not found"
            )
        
        # Generate server signature
        server_private_key, server_public_key = KeyManager.generate_key_pair()
        server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)
        server_public_key_bytes = KeyManager.public_key_to_bytes(server_public_key)
        
        # Add funds - get current balance first
        bucket = db.get_bucket(request.wallet_id)
        current_balance = bucket.get("balance", 0) if bucket else 0
        new_balance = current_balance + request.amount
        
        # Create server signature for the new balance
        bucket_data = f"{request.wallet_id}:{new_balance}:{bucket.get('counter', 0)}".encode()
        server_signature = Signer.sign_with_bytes(server_private_key_bytes, bucket_data)
        
        # Update bucket
        success = bucket_manager.add_funds(
            wallet_id=request.wallet_id,
            amount=request.amount,
            aes_key=aes_key,
            server_public_key=server_public_key_bytes,
            server_signature=server_signature,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to add funds"
            )
        
        # Get updated balance
        updated_bucket = db.get_bucket(request.wallet_id)
        
        return {
            "status": "success",
            "data": {
                "wallet_id": request.wallet_id,
                "amount_added": request.amount,
                "new_balance": updated_bucket.get("balance", 0) if updated_bucket else 0,
                "message": f"Successfully added ${request.amount/100:.2f}",
                "dev_mode": user.get("dev_mode", False),
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Add funds error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# ============ PAYMENT ENDPOINTS ============

@app.post("/api/v1/wallet/send-payment")
async def send_payment(
    request: SendPaymentRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Send payment from one wallet to another."""
    try:
        # Handle dev mode or Firebase auth
        if user.get("dev_mode"):
            if user.get("wallet_id") != request.payer_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if request.payer_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        # Get payer data
        payer_data = db.get_user(request.payer_id)
        if not payer_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payer not found"
            )
        
        # ---- Identify payee ----
        payee_id = request.payee_id
        
        # If payee_id looks like an email
        if "@" in payee_id:
            lookup_user = db.get_user_by_email(payee_id)
            if lookup_user:
                payee_id = lookup_user.get("wallet_id")
        
        # If payee_id looks like a phone number
        elif payee_id.startswith("+"):
            lookup_user = db.get_user_by_phone(payee_id)
            if lookup_user:
                payee_id = lookup_user.get("wallet_id")
        
        # Validate payee exists
        payee_data = db.get_user(payee_id)
        if not payee_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Payee not found: {request.payee_id}"
            )
        
        # Override the payee_id in the request
        request.payee_id = payee_id
        
        aes_key = bytes.fromhex(payer_data.get("aes_key", ""))
        if not aes_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AES key not found"
            )
        
        # Check if payee exists
        payee_data = db.get_user(request.payee_id)
        if not payee_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payee not found"
            )
        
        # Get bucket and check balance
        bucket = db.get_bucket(request.payer_id)
        if not bucket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Wallet not found"
            )
        
        if bucket.get("balance", 0) < request.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Insufficient balance"
            )
        
        if bucket.get("status") == "FROZEN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is frozen"
            )
        
        # Update payer balance
        new_payer_balance = bucket.get("balance", 0) - request.amount
        new_counter = bucket.get("counter", 0) + 1
        
        # ---- FIX: Use dictionary format ----
        payer_update_data = {
            "balance": new_payer_balance,
            "counter": new_counter,
            "last_synced": int(time.time())
        }
        payer_updated = db.update_bucket(request.payer_id, payer_update_data)
        
        if not payer_updated:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update payer balance"
            )
        
        # Update payee balance
        payee_bucket = db.get_bucket(request.payee_id)
        payee_balance = payee_bucket.get("balance", 0) if payee_bucket else 0
        new_payee_balance = payee_balance + request.amount
        
        # ---- FIX: Use dictionary format ----
        payee_update_data = {
            "balance": new_payee_balance,
            "last_synced": int(time.time())
        }
        payee_updated = db.update_bucket(request.payee_id, payee_update_data)
        
        if not payee_updated:
            # Rollback payer update - use dictionary format
            rollback_data = {
                "balance": bucket.get("balance", 0),
                "counter": bucket.get("counter", 0)
            }
            db.update_bucket(request.payer_id, rollback_data)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update payee balance"
            )
        
        return {
            "status": "success",
            "data": {
                "local_id": f"txn_{int(time.time())}",
                "amount": request.amount,
                "payer_id": request.payer_id,
                "payee_id": request.payee_id,
                "payer_balance_after": new_payer_balance,
                "payee_balance_after": new_payee_balance,
                "message": "Payment sent successfully!",
                "dev_mode": user.get("dev_mode", False),
            },
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send payment error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    
    # ============ LITE WALLET ENDPOINTS ============

@app.post("/api/v1/wallet/topup-lite")
async def topup_lite(
    request: TopupLiteRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Top up the lite wallet from main balance."""
    try:
        # Verify user owns the wallet
        if user.get("dev_mode"):
            if user.get("wallet_id") != request.wallet_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if request.wallet_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        # Get user data
        user_data = db.get_user(request.wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        aes_key = bytes.fromhex(user_data.get("aes_key", ""))
        if not aes_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AES key not found"
            )
        
        # ✅ USE MASTER KEY
        server_private_key, server_public_key = KeyManager.get_master_server_key()
        server_private_key_bytes = KeyManager.private_key_to_bytes(server_private_key)
        server_public_key_bytes = KeyManager.public_key_to_bytes(server_public_key)
        
        # Initialize lite wallet manager
        lite_manager = LiteWalletManager(db)
        
        # Top up lite wallet
        success, error, result = lite_manager.topup_lite(
            wallet_id=request.wallet_id,
            amount=request.amount,
            aes_key=aes_key,
            server_private_key=server_private_key_bytes,
            server_public_key=server_public_key_bytes,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error
            )
        
        # Return the result directly - bucket_topup_alias will handle remapping
        return {
            "status": "success",
            "data": {
                **result,
                "server_public_key": server_public_key_bytes.hex(),
                "message": f"Successfully loaded ${request.amount/100:.2f} into Lite Wallet",
                "dev_mode": user.get("dev_mode", False),
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Topup lite error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Topup failed: {str(e)}"
        )
# Add this after the existing topup_lite function
# This makes /api/v1/bucket/topup call the same function

@app.post("/api/v1/bucket/topup")
async def bucket_topup_alias(
    request: TopupLiteRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Alias for /api/v1/wallet/topup-lite (legacy support)."""
    # Return the raw response from topup_lite without remapping keys
    # This ensures consistency with the app's BucketTopupResponse model
    return await topup_lite(request, user)
@app.get("/api/v1/wallet/lite-balance")
async def get_lite_balance(
    wallet_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get lite wallet balance."""
    try:
        # Verify user owns the wallet
        if user.get("dev_mode"):
            if user.get("wallet_id") != wallet_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        else:
            firebase_uid = user.get("uid")
            expected_wallet = f"user_{firebase_uid[:8]}"
            if wallet_id != expected_wallet:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You don't own this wallet"
                )
        
        # Get user data for AES key
        user_data = db.get_user(wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        aes_key = bytes.fromhex(user_data.get("aes_key", ""))
        if not aes_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AES key not found"
            )
        
        # Get main balance
        main_bucket = db.get_bucket(wallet_id)
        main_balance = main_bucket.get("balance", 0) if main_bucket else 0
        
        # Get lite balance
        lite_manager = LiteWalletManager(db)
        lite_data = lite_manager.get_lite_balance(wallet_id, aes_key)
        
        # ✅ FIXED: Return format the app expects
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "balance": main_balance,                        # Changed from main_balance
                "offline_balance": lite_data.get("lite_balance", 0),  # Changed from lite_balance
                "counter": lite_data.get("lite_counter", 0),           # Changed from lite_counter
                "expires_at": lite_data.get("expires_at", 0),
                "is_active": lite_data.get("is_active", False),
                "last_synced": lite_data.get("last_synced", 0),
                "dev_mode": user.get("dev_mode", False),
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get lite balance error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get lite balance: {str(e)}"
        )
# ============ QR CODE ENDPOINT ============

@app.get("/api/v1/user/qr-code")
async def get_qr_code(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Generate QR code data for the current user."""
    try:
        import json
        
        # Get wallet_id from user
        if user.get("dev_mode"):
            wallet_id = user.get("wallet_id")
        else:
            firebase_uid = user.get("uid")
            wallet_id = f"user_{firebase_uid[:8]}"
        
        user_data = db.get_user(wallet_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get user name
        name = user_data.get("full_name") or user_data.get("wallet_name") or user_data.get("email", "User")
        
        # Build QR data
        qr_data = {
            "wallet_id": wallet_id,
            "name": name,
            "type": "payment_request",
            "version": "1.0"
        }
        
        return {
            "status": "success",
            "data": {
                "wallet_id": wallet_id,
                "name": name,
                "qr_data": json.dumps(qr_data),
                "type": "payment_request"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"QR code error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ============ USER LOOKUP ENDPOINT ============

@app.get("/api/v1/user/lookup")
async def lookup_user(
    wallet_id: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Look up a user by wallet_id, email, or phone number."""
    try:
        result = None
        
        if wallet_id:
            result = db.get_user(wallet_id)
            if result:
                result["wallet_id"] = wallet_id
        elif email:
            result = db.get_user_by_email(email)
        elif phone:
            result = db.get_user_by_phone(phone)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide wallet_id, email, or phone"
            )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "status": "success",
            "data": {
                "wallet_id": result.get("wallet_id"),
                "email": result.get("email"),
                "phone": result.get("phone"),
                "full_name": result.get("full_name"),
                "wallet_name": result.get("wallet_name"),
                "status": result.get("status", "ACTIVE"),
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Lookup error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ============ OFFLINE SYNC ENDPOINT ============

class OfflineSyncRequest(BaseModel):
    """Offline sync request."""
    transactions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of transactions to sync"
    )

@app.post("/api/v1/offline/sync")
async def sync_offline_transactions(
    request: OfflineSyncRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Sync offline transactions (NFC, BLE, SMS).
    
    CRITICAL SECURITY FEATURES:
    1. Signature Verification - Uses Ed25519 public key
    2. Idempotency - Prevents double-charging
    3. Counter Validation - Prevents replay attacks
    4. Balance Check - Prevents overspending
    """
    try:
        # Get payer wallet_id
        if user.get("dev_mode"):
            payer_id = user.get("wallet_id")
        else:
            firebase_uid = user.get("uid")
            payer_id = f"user_{firebase_uid[:8]}"
        
        synced = []
        failed = []
        processed_local_ids = set()  # ✅ For idempotency
        
        # If no transactions, return early
        if not request.transactions:
            return {
                "status": "success",
                "data": {
                    "synced_count": 0,
                    "failed_count": 0,
                    "results": [],
                    "message": "No transactions to sync"
                }
            }
        
        for tx in request.transactions:
            local_id = tx.get("local_id")
            
            # Skip if no local_id
            if not local_id:
                failed.append({
                    "local_id": "unknown",
                    "status": "FAILED",
                    "reason": "Missing local_id"
                })
                continue
            
            # ✅ IDEMPOTENCY CHECK: Skip if already processed
            if local_id in processed_local_ids:
                synced.append({
                    "local_id": local_id,
                    "status": "ALREADY_SYNCED",
                    "reason": "Duplicate in this batch"
                })
                continue
            
            # ✅ IDEMPOTENCY CHECK: Check if already in database
            existing = db.get_transaction_by_local_id(local_id)
            if existing:
                processed_local_ids.add(local_id)
                synced.append({
                    "local_id": local_id,
                    "status": "ALREADY_SYNCED",
                    "balance_after": existing.get("payer_balance_after")
                })
                continue
            
            # Verify this transaction belongs to the user
            if tx.get("payer_id") != payer_id:
                failed.append({
                    "local_id": local_id,
                    "status": "UNAUTHORIZED",
                    "reason": "Transaction payer does not match authenticated user"
                })
                continue
            
            # Validate payee exists
            payee_id = tx.get("payee_id")
            if not payee_id:
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": "Missing payee_id"
                })
                continue
                
            payee_data = db.get_user(payee_id)
            if not payee_data:
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": f"Payee not found: {payee_id}"
                })
                continue
            
            # ✅ Get payer data for public key
            payer_data = db.get_user(payer_id)
            if not payer_data:
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": "Payer not found"
                })
                continue
            
            # ✅ SIGNATURE VERIFICATION
            payer_public_key_hex = payer_data.get("public_key", "")
            if not payer_public_key_hex:
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": "Payer public key not found"
                })
                continue
            
            try:
                payer_public_key = bytes.fromhex(payer_public_key_hex)
                payer_signature_hex = tx.get("payer_signature", "")
                
                if not payer_signature_hex:
                    failed.append({
                        "local_id": local_id,
                        "status": "FAILED",
                        "reason": "Missing payer signature"
                    })
                    continue
                
                payer_signature = bytes.fromhex(payer_signature_hex)
                
                # Build message that was signed
                amount = tx.get("amount", 0)
                counter = tx.get("counter", 0)
                timestamp = tx.get("timestamp", 0)
                payee_id = tx.get("payee_id", "")

                # Standardized Pipe Format: local_id|amount|payer_id|payee_id|counter|timestamp
                message = f"{local_id}|{amount}|{payer_id}|{payee_id}|{counter}|{timestamp}".encode()
                
                # ✅ Verify signature using Ed25519
                if not Signer.verify_with_bytes(payer_public_key, message, payer_signature):
                    logger.warning(f"❌ INVALID SYNC SIGNATURE for {local_id}")
                    failed.append({
                        "local_id": local_id,
                        "status": "FAILED",
                        "reason": "Invalid signature - transaction tampered"
                    })
                    continue
                
            except Exception as e:
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": f"Signature verification error: {str(e)}"
                })
                continue
            
            # Process the transaction
            try:
                # Get payer bucket
                payer_bucket = db.get_bucket(payer_id)
                if not payer_bucket:
                    failed.append({
                        "local_id": local_id,
                        "status": "FAILED",
                        "reason": "Payer wallet not found"
                    })
                    continue
                
                # ✅ COUNTER VALIDATION (Double-spend protection)
                current_counter = payer_bucket.get("counter", 0)
                if counter != current_counter + 1:
                    failed.append({
                        "local_id": local_id,
                        "status": "FRAUD_DETECTED",
                        "reason": f"Counter mismatch: expected {current_counter + 1}, got {counter}"
                    })
                    continue
                
                # Check balance
                current_balance = payer_bucket.get("balance", 0)
                if current_balance < amount:
                    failed.append({
                        "local_id": local_id,
                        "status": "FAILED",
                        "reason": f"Insufficient balance: {current_balance} < {amount}"
                    })
                    continue
                
                # Deduct from payer
                new_balance = current_balance - amount
                db.update_bucket(
                    wallet_id=payer_id,
                    balance=new_balance,
                    counter=counter,
                    last_synced=int(time.time())
                )
                
                # Credit to payee
                payee_bucket = db.get_bucket(payee_id)
                payee_new_balance = payee_bucket.get("balance", 0) + amount if payee_bucket else amount
                db.update_bucket(
                    wallet_id=payee_id,
                    balance=payee_new_balance,
                    last_synced=int(time.time())
                )
                
                # ✅ STORE TRANSACTION (for idempotency)
                db.create_transaction(local_id, {
                    "local_id": local_id,
                    "amount": amount,
                    "payer_id": payer_id,
                    "payee_id": payee_id,
                    "counter": counter,
                    "status": "SETTLED",
                    "payer_signature": payer_signature,
                    "payee_signature": tx.get("payee_signature", b""),
                    "method": tx.get("method", "OFFLINE"),
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                    "payer_balance_after": new_balance,
                    "payee_balance_after": payee_new_balance,
                    "settled_at": int(time.time())
                })
                
                # Add to processed set
                processed_local_ids.add(local_id)
                
                synced.append({
                    "local_id": local_id,
                    "status": "SYNCED",
                    "balance_after": new_balance
                })
                
            except Exception as e:
                logger.error(f"Error processing transaction {local_id}: {str(e)}")
                failed.append({
                    "local_id": local_id,
                    "status": "FAILED",
                    "reason": str(e)
                })
        
        return {
            "status": "success",
            "data": {
                "synced_count": len(synced),
                "failed_count": len(failed),
                "results": synced + failed
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Offline sync error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Offline sync failed: {str(e)}"
        )

# ============ SMS PAYMENT ENDPOINT ============

class SMSPaymentRequest(BaseModel):
    """SMS payment request."""
    payer_id: str
    payee_id: str
    amount: int
    local_id: str
    signature: str
    timestamp: int

@app.post("/api/v1/payment/sms")
async def sms_payment(
    request: SMSPaymentRequest
) -> Dict[str, Any]:
    """Handle SMS-based payments."""
    try:
        # 1. Verify payer exists
        payer_data = db.get_user(request.payer_id)
        if not payer_data:
            return {
                "status": "error",
                "message": "Payer not found",
                "local_id": request.local_id
            }
        
        # 2. Verify payee exists
        payee_data = db.get_user(request.payee_id)
        if not payee_data:
            return {
                "status": "error",
                "message": "Payee not found",
                "local_id": request.local_id
            }
        
        # 3. Get payer's public key for signature verification
        payer_public_key = bytes.fromhex(payer_data.get("public_key", ""))
        if not payer_public_key:
            return {
                "status": "error",
                "message": "Payer public key not found",
                "local_id": request.local_id
            }
        
        # 4. Verify signature
        message = f"{request.local_id}:{request.amount}:{request.payer_id}:{request.payee_id}:{request.timestamp}".encode()
        signature = bytes.fromhex(request.signature)
        
        if not Signer.verify_with_bytes(payer_public_key, message, signature):
            return {
                "status": "error",
                "message": "Invalid signature",
                "local_id": request.local_id
            }
        
        # 5. Check if already processed
        existing = db.get_transaction_by_local_id(request.local_id)
        if existing:
            return {
                "status": "success",
                "message": "Already processed",
                "local_id": request.local_id,
                "data": existing
            }
        
        # 6. Process payment
        payer_bucket = db.get_bucket(request.payer_id)
        if not payer_bucket:
            return {
                "status": "error",
                "message": "Payer wallet not found",
                "local_id": request.local_id
            }
        
        counter = payer_bucket.get("counter", 0) + 1
        current_balance = payer_bucket.get("balance", 0)
        
        if current_balance < request.amount:
            return {
                "status": "error",
                "message": "Insufficient balance",
                "local_id": request.local_id
            }
        
        # Deduct from payer
        new_balance = current_balance - request.amount
        db.update_bucket(
            wallet_id=request.payer_id,
            balance=new_balance,
            counter=counter,
            last_synced=int(time.time())
        )
        
        # Credit to payee
        payee_bucket = db.get_bucket(request.payee_id)
        payee_new_balance = payee_bucket.get("balance", 0) + request.amount
        db.update_bucket(
            wallet_id=request.payee_id,
            balance=payee_new_balance,
            last_synced=int(time.time())
        )
        
        # Store transaction
        db.create_transaction(request.local_id, {
            "local_id": request.local_id,
            "amount": request.amount,
            "payer_id": request.payer_id,
            "payee_id": request.payee_id,
            "counter": counter,
            "status": "SETTLED",
            "payer_signature": signature,
            "method": "SMS",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "payer_balance_after": new_balance,
            "payee_balance_after": payee_new_balance,
            "settled_at": int(time.time())
        })
        
        return {
            "status": "success",
            "message": "Payment processed successfully",
            "local_id": request.local_id,
            "data": {
                "payer_balance_after": new_balance,
                "payee_balance_after": payee_new_balance
            }
        }
        
    except Exception as e:
        logger.error(f"SMS payment error: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "local_id": request.local_id if hasattr(request, 'local_id') else None
        }


# ============ TRANSACTION STATUS ENDPOINT ============

@app.get("/api/v1/transaction/{local_id}/status")
async def get_transaction_status(
    local_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get transaction status."""
    try:
        transaction = db.get_transaction_by_local_id(local_id)
        if not transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found"
            )
        
        return {
            "status": "success",
            "data": {
                "local_id": local_id,
                "status": transaction.get("status"),
                "amount": transaction.get("amount"),
                "payer_id": transaction.get("payer_id"),
                "payee_id": transaction.get("payee_id"),
                "method": transaction.get("method"),
                "created_at": transaction.get("created_at"),
                "settled_at": transaction.get("settled_at"),
                "payer_balance_after": transaction.get("payer_balance_after"),
                "payee_balance_after": transaction.get("payee_balance_after")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transaction status error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
# ============ HEALTH CHECK ============

@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "firebase": "connected" if firebase_app else "not initialized",
        "dev_mode": os.getenv("ENV", "development") == "development",
        "timestamp": datetime.now().isoformat(),
    }

@app.get("/")
async def root() -> Dict[str, str]:
    return {
        "status": "ok",
        "message": "Offline Payment System API with Firebase Phone OTP",
        "version": "2.0.0",
        "dev_mode": os.getenv("ENV", "development") == "development",
        "endpoints": [
            "POST /api/v1/auth/register",
            "POST /api/v1/auth/login",
            "POST /api/v1/auth/firebase-login",
            "POST /api/v1/auth/verify-token",
            "POST /api/v1/auth/logout",
            "GET /api/v1/user/profile",
            "GET /api/v1/user/{wallet_id}/balance",
            "GET /api/v1/user/{wallet_id}/status",
            "POST /api/v1/wallet/add-funds",
            "POST /api/v1/wallet/send-payment",
            "POST /api/v1/wallet/topup-lite",      # ✅ NEW
            "GET /api/v1/wallet/lite-balance",
            "POST /api/v1/bucket/topup",           # ✅ Added legacy endpoint
            "GET /api/v1/user/qr-code",
            "GET /api/v1/user/lookup",
            "POST /api/v1/offline/sync",
            "POST /api/v1/payment/sms",
            "GET /api/v1/transaction/{local_id}/status",
            "POST /api/v1/rescue/run",
            "GET /api/v1/rescue/stats",
            "DELETE /api/v1/rescue/clear",
            "GET /health",
        ],
    }
# In main.py - ADD THIS ENDPOINT
class UploadTransactionRequest(BaseModel):
    local_id: str
    amount: int
    payer_id: str
    payee_id: str
    counter: int
    timestamp: int
    payer_signature: str
    payee_signature: str
    device_id: str
    api_key: str

@app.post("/api/v1/offline/reconcile")
async def reconcile_transaction(request: UploadTransactionRequest) -> Dict[str, Any]:
    """Reconcile an offline transaction."""
    try:
        # Check if already processed
        existing = db.get_transaction_by_local_id(request.local_id)
        if existing:
            return {
                "status": "success",
                "data": {
                    "status": "PROCESSED",
                    "local_id": request.local_id,
                    "message": "Already processed"
                }
            }
        
        # Get payer and payee
        payer_data = db.get_user(request.payer_id)
        payee_data = db.get_user(request.payee_id)
        
        if not payer_data or not payee_data:
            raise HTTPException(status_code=400, detail="Payer or payee not found")
        
        # ✅ STRICT SIGNATURE VERIFICATION
        payer_public_key_hex = payer_data.get("public_key", "")
        if not payer_public_key_hex:
            raise HTTPException(status_code=400, detail="Payer public key not found")
            
        payer_public_key = bytes.fromhex(payer_public_key_hex)
        payer_signature = bytes.fromhex(request.payer_signature)

        # Use Standardized Pipe Format: local_id|amount|payer_id|payee_id|counter|timestamp
        message = f"{request.local_id}|{request.amount}|{request.payer_id}|{request.payee_id}|{request.counter}|{request.timestamp}".encode()

        if not Signer.verify_with_bytes(payer_public_key, message, payer_signature):
            logger.warning(f"❌ INVALID SIGNATURE for {request.local_id}")
            raise HTTPException(status_code=401, detail="Invalid cryptographic signature")
        
        # Process transaction
        payer_bucket = db.get_bucket(request.payer_id)
        if not payer_bucket:
            raise HTTPException(status_code=400, detail="Payer wallet not found")
        
        # Check balance
        current_balance = payer_bucket.get("balance", 0)
        if current_balance < request.amount:
            raise HTTPException(status_code=400, detail=f"Insufficient balance: {current_balance} < {request.amount}")
        
        # Deduct from payer
        new_balance = current_balance - request.amount
        # Note: We use the counter from the signed transaction to ensure sequential integrity
        
        db.update_bucket(
            wallet_id=request.payer_id,
            balance=new_balance,
            counter=request.counter,
            last_synced=int(time.time())
        )
        
        # Credit to payee
        payee_bucket = db.get_bucket(request.payee_id)
        payee_new_balance = (payee_bucket.get("balance", 0) if payee_bucket else 0) + request.amount
        db.update_bucket(
            wallet_id=request.payee_id,
            balance=payee_new_balance,
            last_synced=int(time.time())
        )
        
        # Store transaction
        db.create_transaction(request.local_id, {
            "local_id": request.local_id,
            "amount": request.amount,
            "payer_id": request.payer_id,
            "payee_id": request.payee_id,
            "counter": request.counter,
            "status": "SETTLED",
            "payer_signature": request.payer_signature,
            "payee_signature": request.payee_signature,
            "method": "OFFLINE",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "payer_balance_after": new_balance,
            "payee_balance_after": payee_new_balance,
            "settled_at": int(time.time())
        })
        
        return {
            "status": "success",
            "data": {
                "status": "PROCESSED",
                "local_id": request.local_id,
                "payer_balance_after": new_balance,
                "payee_balance_after": payee_new_balance,
                "message": "Transaction reconciled successfully"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reconcile error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
# ============ MAIN ============

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=port,
        reload=os.getenv("ENV", "development") == "development",
    )