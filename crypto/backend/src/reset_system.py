"""System Reset Utility for Offline Wallet Demo."""

import os
import sys
from pathlib import Path

# Setup path to import local modules
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from offlinepay_crypto.firebase_db import FirebaseDB
from offlinepay_crypto.logging_utils import get_logger

logger = get_logger("system.reset")

def reset_system():
    print("🚀 Starting System Reset...")

    # 1. Initialize Firebase
    try:
        db = FirebaseDB()
    except Exception as e:
        print(f"❌ Failed to connect to Firebase: {e}")
        return

    # 2. Wipe Firestore
    print("🧹 Wiping Firestore collections...")
    if db.delete_all_data():
        print("✅ Firestore wiped successfully.")
    else:
        print("❌ Failed to wipe some Firestore collections.")

    # 3. Rotate Master Key (Optional but recommended for total reset)
    master_key_file = Path("server_master.key")
    if master_key_file.exists():
        print("🔑 Deleting old Master Server Key...")
        master_key_file.unlink()
        print("✅ Master Key deleted. A new one will be generated on next start.")

    # 4. Delete local SQLite artifacts if any (cleanup)
    sqlite_file = Path("offline_wallet.db")
    if sqlite_file.exists():
        sqlite_file.unlink()
        print("✅ Local SQLite database deleted.")

    print("\n✨ SYSTEM RESET COMPLETE. The backend is now in a clean state.")
    print("👉 Please clear your Android App storage before registering a new user.")

if __name__ == "__main__":
    reset_system()
