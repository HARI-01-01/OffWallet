import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import sys
from pathlib import Path
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Get the directory where this file is located
BASE_DIR = Path(__file__).resolve().parent

def init_firebase():
    """Initialize Firebase Admin SDK"""
    if firebase_admin._apps:
        return firebase_admin.get_app()
    
    # Look for credentials in multiple locations
    possible_paths = [
        BASE_DIR / 'firebase-adminsdk.json',  # src/firebase-adminsdk.json
        BASE_DIR.parent / 'firebase-adminsdk.json',  # root/firebase-adminsdk.json
        Path('firebase-adminsdk.json'),  # current directory
        Path('/app/firebase-adminsdk.json'),  # Docker path
        os.getenv('FIREBASE_CREDENTIALS'),
        os.getenv('GOOGLE_APPLICATION_CREDENTIALS'),
    ]
    
    cred_path = None
    for path in possible_paths:
        if path and Path(path).exists():
            cred_path = str(Path(path))
            print(f"✅ Found Firebase credentials at: {cred_path}")
            break
    
    if not cred_path:
        print(f"❌ Firebase credentials file not found")
        print(f"   Searched in: {possible_paths}")
        return None
    
    try:
        with open(cred_path, 'r') as f:
            import json
            cred_data = json.load(f)
            print(f"✅ Loaded credentials for project: {cred_data.get('project_id')}")
        
        cred = credentials.Certificate(cred_path)
        app = firebase_admin.initialize_app(cred)
        print("✅ Firebase initialized successfully!")
        return app
    except Exception as e:
        print(f"❌ Failed to initialize Firebase: {e}")
        import traceback
        traceback.print_exc()
        return None

# Initialize Firebase
init_firebase()

def verify_google_token(id_token_str):
    """
    Verify Google ID token using Firebase Admin SDK
    """
    try:
        decoded_token = auth.verify_id_token(id_token_str)
        print(f"✅ Token verified for user: {decoded_token.get('email')}")
        return decoded_token
    except Exception as e:
        print(f"❌ Token verification failed: {e}")
        
        # Try Google OAuth2 verification as fallback
        try:
            client_id = os.getenv('GOOGLE_CLIENT_ID')
            if client_id:
                id_info = id_token.verify_oauth2_token(
                    id_token_str,
                    google_requests.Request(),
                    client_id
                )
                return id_info
            else:
                print("❌ GOOGLE_CLIENT_ID not set")
                return None
        except Exception as e2:
            print(f"❌ Fallback verification failed: {e2}")
            return None

def get_firestore():
    """Get Firestore client"""
    try:
        return firestore.client()
    except Exception as e:
        print(f"❌ Failed to get Firestore client: {e}")
        return None

def get_auth():
    """Get Firebase Auth client"""
    return auth