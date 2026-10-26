"""
Authentication, Administrator Identity & Cryptographic Approval Token Utilities.
Enforces:
- Strict production secret strength validation (>= 32 chars, fail closed)
- Strict cryptographic separation between internal service key and admin assertion signing secret
- Constant-time HMAC service-to-service authentication
- Cryptographically signed administrator identity assertions (preventing header forgery)
- Operation-bound, target-bound, time-limited approval tokens
- Atomic, durable, cross-process replay prevention backed by SQLite
- Model lifecycle circuit-breaker (disabled by default until Phase 4)
"""

import os
import sys
import json
import time
import hmac
import hashlib
import base64
import uuid
import secrets
import sqlite3
import threading
from typing import Tuple, Optional, Dict, Any

_CACHED_INTERNAL_KEY: Optional[str] = None
_CACHED_ASSERTION_SECRET: Optional[str] = None
_DB_LOCK = threading.Lock()
_NONCE_DB_PATH: Optional[str] = None

INSECURE_DEV_DEFAULTS = {
    "sd_internal_dev_secret_key_8000",
    "secret",
    "password",
    "admin",
    "12345678",
    "changeme",
    "sd_test_internal_key_min_32_characters_long_entropy_secure!",
    "",
}

def is_production() -> bool:
    """Returns True if runtime environment is configured as production."""
    env = os.getenv("SHIELDDESK_ENV", os.getenv("NODE_ENV", os.getenv("APP_ENV", "development"))).lower()
    return env in ("production", "prod")

def get_internal_service_key() -> str:
    """
    Retrieves and validates the service-to-service internal authentication key.
    Fails closed in production if missing, weak (< 32 chars), or matching known defaults.
    """
    global _CACHED_INTERNAL_KEY
    if _CACHED_INTERNAL_KEY is not None:
        return _CACHED_INTERNAL_KEY

    key = os.getenv("SHIELDDESK_INTERNAL_KEY", "").strip()
    is_prod = is_production()

    if is_prod:
        if not key:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_INTERNAL_KEY must be configured in production."
            )
        if len(key) < 32:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_INTERNAL_KEY is too weak (minimum 32 characters required in production)."
            )
        if key in INSECURE_DEV_DEFAULTS:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Insecure default SHIELDDESK_INTERNAL_KEY detected in production. Refusing to run."
            )
        _CACHED_INTERNAL_KEY = key
        return key

    # Development / Testing: require explicit configuration or generate unique ephemeral key
    if not key:
        print("[WARN] SHIELDDESK_INTERNAL_KEY not set. Generating unique ephemeral secret for current process.")
        key = secrets.token_urlsafe(32)

    _CACHED_INTERNAL_KEY = key
    return key

def get_admin_assertion_secret() -> str:
    """
    Retrieves and validates the cryptographic signing secret for administrator identity assertions.
    Cryptographically isolated from the internal service authentication key.
    Fails closed in production if missing, weak (< 32 chars), or matching known defaults.
    """
    global _CACHED_ASSERTION_SECRET
    if _CACHED_ASSERTION_SECRET is not None:
        return _CACHED_ASSERTION_SECRET

    sec = os.getenv("SHIELDDESK_ADMIN_ASSERTION_SECRET", "").strip()
    is_prod = is_production()

    if is_prod:
        if not sec:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET must be configured in production."
            )
        if len(sec) < 32:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET is too weak (minimum 32 characters required in production)."
            )
        if sec in INSECURE_DEV_DEFAULTS:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Insecure default SHIELDDESK_ADMIN_ASSERTION_SECRET detected in production. Refusing to run."
            )
        # Enforce key separation
        internal_key = os.getenv("SHIELDDESK_INTERNAL_KEY", "").strip()
        if sec == internal_key:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET must not be identical to SHIELDDESK_INTERNAL_KEY. Separate keys are required."
            )
        _CACHED_ASSERTION_SECRET = sec
        return sec

    # Non-production: require explicit configuration or fallback to session secret / unique ephemeral key
    if not sec:
        session_sec = os.getenv("SHIELDDESK_SESSION_SECRET", "").strip()
        if session_sec and len(session_sec) >= 32 and session_sec not in INSECURE_DEV_DEFAULTS:
            sec = session_sec
        else:
            print("[WARN] SHIELDDESK_ADMIN_ASSERTION_SECRET not set. Generating unique ephemeral secret for current process.")
            sec = secrets.token_urlsafe(32)

    _CACHED_ASSERTION_SECRET = sec
    return sec

def reset_cached_keys_for_testing():
    """Allows test fixtures to re-evaluate environment configuration and reset state."""
    global _CACHED_INTERNAL_KEY, _CACHED_ASSERTION_SECRET
    _CACHED_INTERNAL_KEY = None
    _CACHED_ASSERTION_SECRET = None

reset_cached_key_for_testing = reset_cached_keys_for_testing

def get_nonce_db_path() -> str:
    """Returns filesystem path for durable cross-process SQLite nonce store."""
    global _NONCE_DB_PATH
    if _NONCE_DB_PATH is not None:
        return _NONCE_DB_PATH
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)
    return os.path.join(models_dir, "consumed_nonces.sqlite3")

def set_nonce_db_path_for_testing(path: Optional[str]):
    """Configures custom database path for isolated replay tests."""
    global _NONCE_DB_PATH
    _NONCE_DB_PATH = path

class DurableNonceStore:
    """
    Atomic, durable, cross-process replay-prevention store backed by SQLite.
    Guarantees that nonces are consumed once across concurrent threads,
    multiple worker processes, and surviving service restarts.
    """

    @classmethod
    def _get_connection(cls) -> sqlite3.Connection:
        db_path = get_nonce_db_path()
        conn = sqlite3.connect(db_path, timeout=10.0, isolation_level="EXCLUSIVE")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                exp INTEGER NOT NULL,
                consumed_at INTEGER NOT NULL
            );
        """)
        return conn

    @classmethod
    def record_and_verify_nonce(cls, nonce: str, operation: str, operator_id: str, exp: int) -> Tuple[bool, str]:
        """
        Atomically records a nonce.
        Returns (True, '') if unique and successfully recorded.
        Returns (False, err_msg) if duplicate (replay attack detected).
        """
        now = int(time.time())
        with _DB_LOCK:
            try:
                conn = cls._get_connection()
                try:
                    # Prune expired nonces
                    conn.execute("DELETE FROM consumed_nonces WHERE exp < ?;", (now,))

                    # Atomic insert
                    conn.execute(
                        "INSERT INTO consumed_nonces (nonce, operation, operator_id, exp, consumed_at) VALUES (?, ?, ?, ?, ?);",
                        (nonce, operation, operator_id, exp, now)
                    )
                    conn.commit()
                    return True, ""
                except sqlite3.IntegrityError:
                    conn.rollback()
                    return False, "Replay attack detected: approval token nonce has already been consumed (durable check)."
                finally:
                    conn.close()
            except Exception as e:
                return False, f"Nonce store error: {str(e)}"

    @classmethod
    def clear_for_testing(cls):
        """Clears all nonces from the database for test isolation."""
        with _DB_LOCK:
            try:
                conn = cls._get_connection()
                conn.execute("DELETE FROM consumed_nonces;")
                conn.commit()
                conn.close()
            except Exception:
                pass

def verify_service_token(token: str) -> bool:
    """Verifies service-to-service internal credentials using constant-time comparison."""
    if not token or not isinstance(token, str):
        return False
    service_key = get_internal_service_key()
    return hmac.compare_digest(token.encode("utf-8"), service_key.encode("utf-8"))

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def base64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data + padding)

def create_admin_assertion_token(
    operator_id: str,
    role: str,
    operation: str,
    target_id: Optional[str] = None,
    ttl_seconds: int = 300,
    secret: Optional[str] = None,
    nonce: Optional[str] = None
) -> str:
    """
    Creates a cryptographically signed HMAC-SHA256 administrator assertion token.
    Uses SHIELDDESK_ADMIN_ASSERTION_SECRET by default (cryptographically separate from internal service key).
    Binds operator ID, role, operation, candidate target, and nonce with short TTL.
    """
    sec = secret or get_admin_assertion_secret()
    now = int(time.time())
    payload = {
        "operator_id": operator_id,
        "role": role,
        "operation": operation,
        "target_id": target_id,
        "nonce": nonce or str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl_seconds
    }
    encoded_payload = base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(sec.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_sig = base64url_encode(sig)
    return f"{encoded_payload}.{encoded_sig}"

def verify_admin_assertion_token(
    token: str,
    expected_operation: str,
    expected_target: Optional[str] = None,
    secret: Optional[str] = None,
    require_target: bool = False
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Cryptographically verifies an administrator assertion or approval token.
    Validates:
    - HMAC-SHA256 signature against SHIELDDESK_ADMIN_ASSERTION_SECRET
    - Token validity window (iat, exp)
    - Role authorization (system_admin or super_admin only)
    - Operation match
    - Target match (candidate model ID or rollback target) with mandatory binding when require_target=True
    - Atomic, cross-process, restart-safe replay check via DurableNonceStore
    """
    if not token or not isinstance(token, str):
        return False, "Missing administrator identity assertion or approval token.", {}

    parts = token.split(".")
    if len(parts) != 2:
        return False, "Malformed token: expected exactly two dot-separated segments.", {}

    encoded_payload, encoded_sig = parts
    sec = secret or get_admin_assertion_secret()

    expected_sig = base64url_encode(hmac.new(sec.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(encoded_sig.encode("utf-8"), expected_sig.encode("utf-8")):
        return False, "Cryptographic signature verification failed: invalid token signature.", {}

    try:
        payload_bytes = base64url_decode(encoded_payload)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, "Malformed token: unable to decode JSON payload.", {}

    now = int(time.time())
    iat = payload.get("iat", 0)
    exp = payload.get("exp", 0)

    # Expiration check
    if now > exp:
        return False, f"Token has expired at {exp} (current time: {now}).", {}
    if now < iat - 30:
        return False, f"Token issued in the future (iat: {iat}, current time: {now}).", {}

    # Role check
    role = str(payload.get("role", "")).strip()
    if role not in ("system_admin", "super_admin"):
        return False, f"Forbidden: Operator role '{role}' is not authorized. Requires system_admin or super_admin.", {}

    # Operation check
    op = str(payload.get("operation", "")).strip()
    if op != expected_operation:
        return False, f"Operation mismatch: token authorizes '{op}', but requested '{expected_operation}'.", {}

    # Target check
    target = payload.get("target_id")
    if require_target and (not target or not isinstance(target, str) or not target.strip()):
        return False, f"Target binding required: token for '{expected_operation}' must specify a non-empty target_id.", {}
    if expected_target is not None:
        if target != expected_target:
            return False, f"Target mismatch: token authorizes '{target}', but target is '{expected_target}'.", {}

    # Nonce replay check via durable cross-process SQLite store
    nonce = str(payload.get("nonce", "")).strip()
    if not nonce:
        return False, "Security violation: token is missing mandatory replay prevention nonce.", {}

    operator_id = str(payload.get("operator_id", "unknown"))
    recorded, err_msg = DurableNonceStore.record_and_verify_nonce(
        nonce=nonce,
        operation=op,
        operator_id=operator_id,
        exp=exp
    )
    if not recorded:
        return False, err_msg, {}

    return True, "", payload

def is_model_lifecycle_enabled() -> bool:
    """
    Returns True if model promotion and rollback endpoints are enabled.
    Disabled by default until Phase 4 release gates are verified.
    """
    return os.getenv("ENABLE_MODEL_LIFECYCLE", "false").lower() in ("true", "1", "yes")
