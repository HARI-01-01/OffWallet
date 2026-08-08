"""Test Firebase Phone OTP Authentication."""

import requests
import json

BASE_URL = "http://localhost:8000"

# These should come from the frontend
TEST_FIREBASE_TOKEN = "YOUR_FIREBASE_ID_TOKEN_FROM_APP"

def test_register():
    """Test user registration."""
    url = f"{BASE_URL}/api/v1/auth/register"
    
    payload = {
        "phone": "+919876543210",
        "firebase_token": TEST_FIREBASE_TOKEN,
        "full_name": "Alice Johnson",
        "date_of_birth": "1995-06-15",
        "country": "IN",
        "currency": "USD",
        "initial_deposit": 5000,
        "device_id": "android_device_xyz",
        "public_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "wallet_name": "Alice's Wallet",
        "device_name": "Pixel 7",
        "os_version": "14",
        "app_version": "1.0.0",
        "push_token": "fcm_token_xyz"
    }
    
    response = requests.post(url, json=payload)
    print(f"Register Status: {response.status_code}")
    print(f"Register Response: {json.dumps(response.json(), indent=2)}")
    return response.json()

def test_login():
    """Test user login."""
    url = f"{BASE_URL}/api/v1/auth/login"
    
    payload = {
        "phone": "+919876543210",
        "firebase_token": TEST_FIREBASE_TOKEN
    }
    
    response = requests.post(url, json=payload)
    print(f"Login Status: {response.status_code}")
    print(f"Login Response: {json.dumps(response.json(), indent=2)}")
    return response.json()

def test_verify_token():
    """Test token verification."""
    url = f"{BASE_URL}/api/v1/auth/verify-token"
    
    payload = {
        "firebase_token": TEST_FIREBASE_TOKEN
    }
    
    response = requests.post(url, json=payload)
    print(f"Verify Token Status: {response.status_code}")
    print(f"Verify Token Response: {json.dumps(response.json(), indent=2)}")
    return response.json()

if __name__ == "__main__":
    print("=" * 50)
    print("Testing Firebase Phone OTP Authentication")
    print("=" * 50)
    
    # Uncomment these as you test
    # test_verify_token()
    # test_register()
    # test_login()