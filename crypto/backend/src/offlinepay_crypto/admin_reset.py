"""Master Reset Script for Shadow Backend - v1 Implementation."""

import firebase_admin
from firebase_admin import credentials, firestore
import os
import sys
from pathlib import Path

# Setup path
SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", str(SRC_DIR / "firebase-adminsdk.json"))

if not os.path.exists(cred_path):
    print(f"❌ Credentials not found at {cred_path}")
    exit(1)

cred = credentials.Certificate(cred_path)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()

def delete_collection(collection_name, batch_size=50):
    print(f"🧹 Wiping collection: {collection_name}...")
    collection_ref = db.collection(collection_name)
    docs = collection_ref.limit(batch_size).stream()
    deleted = 0

    for doc in docs:
        doc.reference.delete()
        deleted += 1

    if deleted >= batch_size:
        return delete_collection(collection_name, batch_size)
    else:
        print(f"✅ Finished {collection_name}. Total deleted: {deleted}")
        return deleted

if __name__ == "__main__":
    # Strictly forbid reset in production environment
    if os.getenv("ENV", "production").lower() == "production":
        print("❌ ERROR: Master reset is strictly forbidden in production environment.")
        exit(1)

    confirm = input("⚠️ WARNING: This will delete ALL v1 users and transactions. Type 'SHADOW_WIPE_V1' to confirm: ")
    if confirm == "SHADOW_WIPE_V1":
        # V1 Collections
        collections = ["users", "buckets", "settlements", "ledger", "telemetry", "nonces", "challenges"]
        for col in collections:
            delete_collection(col)
        print("\n🚀 BACKEND WIPE COMPLETE. v1 Environment is now a clean slate.")
    else:
        print("❌ Reset cancelled.")
