import sys
from pathlib import Path
import time

# Setup path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir / "src"))

from offlinepay_crypto.rate_limiter import RateLimiter

def test_rate_limiter():
    limiter = RateLimiter() # Will use local fallback
    key = "test_user_ip"

    print(f"Testing rate limit for {key}...")

    # Allow 3 requests in 10 seconds
    for i in range(3):
        allowed, remaining = limiter.check_rate_limit(key, limit=3, window=10)
        print(f"Request {i+1}: Allowed={allowed}, Remaining={remaining}")
        if not allowed:
            print(f"❌ Failed: Request {i+1} should be allowed")
            return

    # 4th request should be blocked
    allowed, remaining = limiter.check_rate_limit(key, limit=3, window=10)
    print(f"Request 4: Allowed={allowed}, Remaining={remaining}")
    if allowed:
        print("❌ Failed: Request 4 should be blocked")
        return

    print("✅ Rate limiter test passed!")

if __name__ == "__main__":
    test_rate_limiter()
