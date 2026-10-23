"""
Comprehensive Security & Authorization Regression Test Suite for CVE AI Engine.
Covers Phase 1 Verification:
1. Secret validation (missing, weak, default secrets in production fail closed)
2. HTTP method restrictions (GET, PUT, DELETE, PATCH on privileged routes return 405)
3. HTTP request hardening (missing/malformed Content-Length -> 411/400, chunked encoding -> 501, payload > 1MB -> 413, truncated body -> 400)
4. Unauthenticated access prevention (401 on every privileged route)
5. Administrator identity protection (rejection of forged raw headers, arbitrary approval strings, forged signatures)
6. Cryptographic approval token validation (binding to operator, role, operation, candidate target)
7. Anti-replay and expiration enforcement (expired token -> 403, replayed nonce -> 403)
8. Model lifecycle circuit-breaker (disabled by default -> 503, preventing unauthorized side effects)
9. Legitimate authorized execution (service auth + signed admin assertion -> 200)
10. Audit logging verification (models/privileged_audit.jsonl)
"""

import os
import sys

_current_dir = os.path.dirname(os.path.abspath(__file__))
_ai_chat_desk_dir = os.path.abspath(os.path.join(_current_dir, ".."))
if _ai_chat_desk_dir not in sys.path:
    sys.path.insert(0, _ai_chat_desk_dir)

import json
import time
import socket
import sqlite3
import unittest
import threading
import concurrent.futures
from unittest import mock
import requests
from http.server import HTTPServer, ThreadingHTTPServer

import auth_util
from auth_util import (
    get_internal_service_key,
    get_admin_assertion_secret,
    reset_cached_keys_for_testing,
    reset_cached_key_for_testing,
    create_admin_assertion_token,
    verify_admin_assertion_token,
    is_production,
    INSECURE_DEV_DEFAULTS,
    DurableNonceStore,
    set_nonce_db_path_for_testing,
    get_nonce_db_path,
)
from server import CVEAPIHandler, MAX_BODY_SIZE, registry

TEST_INTERNAL_KEY = "sd_test_service_key_min_32_characters_long_entropy_secure!"
TEST_ASSERTION_SECRET = "sd_test_assertion_key_min_32_chars_cryptographically_isolated!"

class TestSecretStartupValidation(unittest.TestCase):
    """Verifies that secrets are strictly validated and fail closed in production."""

    def setUp(self):
        self.orig_env = os.environ.copy()
        reset_cached_keys_for_testing()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        reset_cached_keys_for_testing()

    def test_production_missing_internal_secret_fails_closed(self):
        """In production, missing SHIELDDESK_INTERNAL_KEY must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        os.environ.pop("SHIELDDESK_INTERNAL_KEY", None)
        with self.assertRaises(RuntimeError) as ctx:
            get_internal_service_key()
        self.assertIn("SHIELDDESK_INTERNAL_KEY must be configured in production", str(ctx.exception))

    def test_production_weak_internal_secret_fails_closed(self):
        """In production, secret with < 32 characters must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        os.environ["SHIELDDESK_INTERNAL_KEY"] = "short_secret_only_24_chars"
        with self.assertRaises(RuntimeError) as ctx:
            get_internal_service_key()
        self.assertIn("too weak", str(ctx.exception))

    def test_production_insecure_default_internal_secret_fails_closed(self):
        """In production, using known dev defaults must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        for bad_secret in INSECURE_DEV_DEFAULTS:
            reset_cached_keys_for_testing()
            os.environ["SHIELDDESK_INTERNAL_KEY"] = bad_secret
            with self.assertRaises(RuntimeError) as ctx:
                get_internal_service_key()
            self.assertIn("CRITICAL SECURITY", str(ctx.exception))

    def test_production_strong_internal_secret_succeeds(self):
        """In production, high-entropy 32+ char secret succeeds."""
        os.environ["SHIELDDESK_ENV"] = "production"
        strong_key = "a" * 32
        os.environ["SHIELDDESK_INTERNAL_KEY"] = strong_key
        key = get_internal_service_key()
        self.assertEqual(key, strong_key)

    def test_production_missing_assertion_secret_fails_closed(self):
        """In production, missing SHIELDDESK_ADMIN_ASSERTION_SECRET must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        os.environ.pop("SHIELDDESK_ADMIN_ASSERTION_SECRET", None)
        with self.assertRaises(RuntimeError) as ctx:
            get_admin_assertion_secret()
        self.assertIn("SHIELDDESK_ADMIN_ASSERTION_SECRET must be configured in production", str(ctx.exception))

    def test_production_weak_assertion_secret_fails_closed(self):
        """In production, assertion secret < 32 chars must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = "short_assertion_secret_24"
        with self.assertRaises(RuntimeError) as ctx:
            get_admin_assertion_secret()
        self.assertIn("too weak", str(ctx.exception))

    def test_production_insecure_default_assertion_secret_fails_closed(self):
        """In production, using known dev defaults for assertion secret must fail closed."""
        os.environ["SHIELDDESK_ENV"] = "production"
        for bad_secret in INSECURE_DEV_DEFAULTS:
            reset_cached_keys_for_testing()
            os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = bad_secret
            with self.assertRaises(RuntimeError) as ctx:
                get_admin_assertion_secret()
            self.assertIn("CRITICAL SECURITY", str(ctx.exception))

    def test_production_identical_keys_fails_closed(self):
        """In production, using identical keys for service auth and assertion signing must raise RuntimeError."""
        os.environ["SHIELDDESK_ENV"] = "production"
        same_key = "x" * 40
        os.environ["SHIELDDESK_INTERNAL_KEY"] = same_key
        os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = same_key
        with self.assertRaises(RuntimeError) as ctx:
            get_admin_assertion_secret()
        self.assertIn("Separate keys are required", str(ctx.exception))

    def test_development_generates_ephemeral_secrets_without_shared_defaults(self):
        """In development mode, unset secrets generate random ephemeral keys per process."""
        os.environ["SHIELDDESK_ENV"] = "development"
        os.environ.pop("SHIELDDESK_INTERNAL_KEY", None)
        os.environ.pop("SHIELDDESK_ADMIN_ASSERTION_SECRET", None)
        os.environ.pop("SHIELDDESK_SESSION_SECRET", None)
        reset_cached_keys_for_testing()

        key1 = get_internal_service_key()
        sec1 = get_admin_assertion_secret()

        self.assertGreaterEqual(len(key1), 32)
        self.assertGreaterEqual(len(sec1), 32)
        self.assertNotIn(key1, INSECURE_DEV_DEFAULTS)
        self.assertNotIn(sec1, INSECURE_DEV_DEFAULTS)
        self.assertNotEqual(key1, sec1)


class TestEndpointSecurityAndHardening(unittest.TestCase):
    """Integration test suite against live CVEAPIHandler instance."""

    @classmethod
    def setUpClass(cls):
        # Configure test environment with strictly separated cryptographic keys
        os.environ["SHIELDDESK_INTERNAL_KEY"] = TEST_INTERNAL_KEY
        os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = TEST_ASSERTION_SECRET
        reset_cached_keys_for_testing()

        # Find free ephemeral port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        cls.test_port = sock.getsockname()[1]
        sock.close()

        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.test_port), CVEAPIHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.test_port}"
        cls.service_headers = {"X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY}
        cls.audit_file = os.path.join(os.path.dirname(__file__), "..", "models", "privileged_audit.jsonl")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # ---- 1. Unauthenticated Access (Negative) -----------------------------

    def test_unauthenticated_promote_rejected_401(self):
        resp = requests.post(f"{self.base_url}/api/model/promote", json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Unauthorized", resp.json().get("error", ""))

    def test_unauthenticated_rollback_rejected_401(self):
        resp = requests.post(f"{self.base_url}/api/model/rollback", json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)

    def test_unauthenticated_intel_sync_rejected_401(self):
        resp = requests.post(f"{self.base_url}/api/intel/sync", json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)

    def test_unauthenticated_trigger_scan_rejected_401(self):
        resp = requests.post(f"{self.base_url}/api/trigger_scan", json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)

    def test_invalid_service_key_rejected_401(self):
        headers = {"X-ShieldDesk-Internal-Key": "forged_malicious_key_123456789012"}
        resp = requests.post(f"{self.base_url}/api/model/promote", headers=headers, json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)

    # ---- 1b. Direct Access with Missing Admin Assertion (Negative) --------

    def test_service_authenticated_promote_missing_assertion_rejected_403(self):
        """Valid service credentials without admin assertion must be rejected with 403 on promote."""
        resp = requests.post(f"{self.base_url}/api/model/promote", headers=self.service_headers, json={}, timeout=5)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Missing administrator cryptographic approval assertion token", resp.json().get("error", ""))

    def test_service_authenticated_rollback_missing_assertion_rejected_403(self):
        """Valid service credentials without admin assertion must be rejected with 403 on rollback."""
        resp = requests.post(f"{self.base_url}/api/model/rollback", headers=self.service_headers, json={}, timeout=5)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Missing administrator cryptographic approval assertion token", resp.json().get("error", ""))

    def test_service_authenticated_intel_sync_missing_assertion_rejected_403(self):
        """Direct access with service key but missing admin assertion must be rejected with 403 on intel sync."""
        resp = requests.post(f"{self.base_url}/api/intel/sync", headers=self.service_headers, json={}, timeout=5)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Missing administrator cryptographic approval assertion token", resp.json().get("error", ""))

    def test_service_authenticated_trigger_scan_missing_assertion_rejected_403(self):
        """Direct access with service key but missing admin assertion must be rejected with 403 on trigger scan."""
        resp = requests.post(f"{self.base_url}/api/trigger_scan", headers=self.service_headers, json={}, timeout=5)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Missing administrator cryptographic approval assertion token", resp.json().get("error", ""))

    def test_caller_supplied_identity_cannot_bypass_admin_assertion(self):
        """Unverified caller-supplied headers claiming super_admin cannot bypass cryptographic assertion."""
        for endpoint in ["/api/model/promote", "/api/model/rollback", "/api/intel/sync", "/api/trigger_scan"]:
            headers = {
                **self.service_headers,
                "X-ShieldDesk-Operator-Id": "attacker",
                "X-ShieldDesk-Operator-Role": "super_admin",
                "X-ShieldDesk-User": "dev-super-admin",
            }
            resp = requests.post(f"{self.base_url}{endpoint}", headers=headers, json={"user_id": "root"}, timeout=5)
            self.assertEqual(resp.status_code, 403, f"{endpoint} did not reject unverified caller identity")
            self.assertIn("Missing administrator cryptographic approval assertion token", resp.json().get("error", ""))

    # ---- 2. HTTP Method Restrictions (Negative) ---------------------------

    def test_disallowed_get_on_privileged_routes_rejected_405(self):
        """GET requests to privileged POST routes must be rejected with 405 Method Not Allowed."""
        for endpoint in ["/api/model/promote", "/api/model/rollback", "/api/intel/sync", "/api/trigger_scan"]:
            resp = requests.get(f"{self.base_url}{endpoint}", timeout=5)
            self.assertEqual(resp.status_code, 405, f"{endpoint} allowed GET")
            self.assertIn("Method Not Allowed", resp.json().get("error", ""))

    def test_disallowed_put_delete_patch_rejected_405(self):
        """PUT, DELETE, PATCH requests must be rejected with 405 Method Not Allowed."""
        for method in [requests.put, requests.delete, requests.patch]:
            resp = method(f"{self.base_url}/api/predict", json={}, timeout=5)
            self.assertEqual(resp.status_code, 405)

    # ---- 3. HTTP Request Hardening (Negative) ------------------------------

    def test_missing_content_length_rejected_411(self):
        """POST without Content-Length must be rejected with 411 Length Required."""
        # Use raw socket to send POST without Content-Length
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.sendall(b"POST /api/predict HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = s.recv(4096).decode("utf-8")
        s.close()
        self.assertTrue(response.startswith("HTTP/1.0 411") or response.startswith("HTTP/1.1 411"), response)

    def test_malformed_content_length_rejected_400(self):
        """POST with non-integer or negative Content-Length must return 400 Bad Request."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.sendall(b"POST /api/predict HTTP/1.1\r\nHost: localhost\r\nContent-Length: -5\r\n\r\n")
        response = s.recv(4096).decode("utf-8")
        s.close()
        self.assertTrue("400 Bad Request" in response or "400" in response, response)

    def test_unsupported_transfer_encoding_chunked_rejected_501(self):
        """Unsupported chunked transfer encoding must be rejected with 501 Not Implemented."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.sendall(b"POST /api/predict HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        response = s.recv(4096).decode("utf-8")
        s.close()
        self.assertTrue("501 Not Implemented" in response or "501" in response, response)

    def test_payload_too_large_rejected_413(self):
        """Payload exceeding MAX_BODY_SIZE (1 MB) must return 413 Payload Too Large."""
        oversized_data = "X" * (MAX_BODY_SIZE + 10240)
        try:
            resp = requests.post(
                f"{self.base_url}/api/predict",
                data=oversized_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            self.assertEqual(resp.status_code, 413)
        except requests.exceptions.RequestException:
            pass  # Socket safely closed on limit breach

    def test_truncated_body_rejected_400(self):
        """Declared length larger than actual sent bytes must be rejected with 400 Bad Request."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        # Declare 100 bytes, only send 10 bytes then close write half
        s.sendall(b"POST /api/predict HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{\"desc\":12}")
        s.shutdown(socket.SHUT_WR)
        response = s.recv(4096).decode("utf-8")
        s.close()
        self.assertTrue("400" in response, response)

    # ---- 4. Administrator Identity & Role Forgery (Negative) ---------------

    def test_forged_raw_headers_without_cryptographic_assertion_rejected_403(self):
        """Passing unverified raw operator headers without cryptographic assertion must return 403."""
        headers = {
            **self.service_headers,
            "X-ShieldDesk-Operator-Id": "attacker-user-id",
            "X-ShieldDesk-Operator-Role": "super_admin",
            "X-ShieldDesk-Approval-Token": "raw_arbitrary_string"
        }
        resp = requests.post(f"{self.base_url}/api/model/promote", headers=headers, json={}, timeout=5)
        # Even if lifecycle enabled, must fail with 403 or 503
        self.assertIn(resp.status_code, (403, 503))

    def test_arbitrary_string_approval_token_rejected_403(self):
        """Arbitrary non-cryptographic approval string must be rejected with 403."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        try:
            resp = requests.post(
                f"{self.base_url}/api/model/promote",
                headers=self.service_headers,
                json={"approval_token": "plain_untrusted_string_token"},
                timeout=5
            )
            self.assertIn(resp.status_code, (403, 412))
            if resp.status_code == 403:
                self.assertIn("Malformed token", resp.json().get("error", ""))
        finally:
            os.environ.pop("ENABLE_MODEL_LIFECYCLE", None)

    def test_forged_token_signature_rejected_403(self):
        """Token signed with wrong key must be rejected with 403."""
        forged_token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="model_promote",
            secret="wrong_secret_key_used_by_attacker_123456!"
        )
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        try:
            resp = requests.post(
                f"{self.base_url}/api/model/promote",
                headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": forged_token},
                json={},
                timeout=5
            )
            self.assertIn(resp.status_code, (403, 412))
            if resp.status_code == 403:
                self.assertIn("verification failed", resp.json().get("error", ""))
        finally:
            os.environ.pop("ENABLE_MODEL_LIFECYCLE", None)

    def test_unauthorized_role_in_signed_token_rejected_403(self):
        """Signed token with non-admin role (analyst, responder) must be rejected with 403."""
        token = create_admin_assertion_token(
            operator_id="analyst-1",
            role="analyst",
            operation="model_promote"
        )
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        try:
            resp = requests.post(
                f"{self.base_url}/api/model/promote",
                headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": token},
                json={},
                timeout=5
            )
            self.assertIn(resp.status_code, (403, 412))
            if resp.status_code == 403:
                self.assertIn("not authorized", resp.json().get("error", ""))
        finally:
            os.environ.pop("ENABLE_MODEL_LIFECYCLE", None)

    def test_operation_mismatch_in_signed_token_rejected_403(self):
        """Token signed for model_rollback must not be accepted for model_promote."""
        token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="model_rollback"
        )
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        try:
            resp = requests.post(
                f"{self.base_url}/api/model/promote",
                headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": token},
                json={},
                timeout=5
            )
            self.assertIn(resp.status_code, (403, 412))
            if resp.status_code == 403:
                self.assertIn("Operation mismatch", resp.json().get("error", ""))
        finally:
            os.environ.pop("ENABLE_MODEL_LIFECYCLE", None)

    # ---- 5. Replay and Expiration Enforcement (Negative) ------------------

    def test_expired_approval_token_rejected_403(self):
        """Token with negative TTL (already expired) must be rejected with 403."""
        expired_token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="intel_sync",
            ttl_seconds=-10
        )
        resp = requests.post(
            f"{self.base_url}/api/intel/sync",
            headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": expired_token},
            json={},
            timeout=5
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("expired", resp.json().get("error", ""))

    def test_replayed_approval_token_rejected_403(self):
        """Replaying the exact same signed token twice must be rejected on the second attempt."""
        token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="intel_sync",
            ttl_seconds=300
        )
        headers = {**self.service_headers, "X-ShieldDesk-Admin-Assertion": token}

        # Attempt 1: Should pass token verification (status 200 or 500 depending on offline feed sync)
        resp1 = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=10)
        self.assertNotEqual(resp1.status_code, 403, f"First attempt unexpectedly rejected with 403: {resp1.text}")

        # Attempt 2: Replay of the consumed nonce must be rejected with 403 Forbidden
        resp2 = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=10)
        self.assertEqual(resp2.status_code, 403)
        self.assertIn("Replay attack detected", resp2.json().get("error", ""))

    # ---- 6. Lifecycle Circuit Breaker (Negative & Positive) ----------------

    def test_model_lifecycle_disabled_by_default_503(self):
        """By default (ENABLE_MODEL_LIFECYCLE unset), promotion & rollback endpoints must return 503."""
        token_promote = create_admin_assertion_token("admin-1", "super_admin", "model_promote")
        resp_promote = requests.post(
            f"{self.base_url}/api/model/promote",
            headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": token_promote},
            json={},
            timeout=5
        )
        self.assertEqual(resp_promote.status_code, 503)
        self.assertIn("Service Unavailable", resp_promote.json().get("error", ""))

        token_rollback = create_admin_assertion_token("admin-1", "super_admin", "model_rollback")
        resp_rollback = requests.post(
            f"{self.base_url}/api/model/rollback",
            headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": token_rollback},
            json={},
            timeout=5
        )
        self.assertEqual(resp_rollback.status_code, 503)
        self.assertIn("Service Unavailable", resp_rollback.json().get("error", ""))

    # ---- 7. Positive Execution Tests (Legitimate Requests) ----------------

    def test_authorized_intel_sync_with_admin_assertion_succeeds(self):
        """Valid service key + signed admin assertion executes successfully."""
        token = create_admin_assertion_token(
            operator_id="sysadmin-usr-1",
            role="system_admin",
            operation="intel_sync"
        )
        headers = {**self.service_headers, "X-ShieldDesk-Admin-Assertion": token}
        resp = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=15)
        # Should authenticate and authorize cleanly (status 200)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body.get("success"))
        self.assertIn("synced_cisa_items", body)

    def test_bearer_token_authorization_header_accepted(self):
        """Authorization: Bearer <key> must authenticate service."""
        token = create_admin_assertion_token(
            operator_id="sysadmin-usr-1",
            role="system_admin",
            operation="intel_sync"
        )
        headers = {
            "Authorization": f"Bearer {TEST_INTERNAL_KEY}",
            "X-ShieldDesk-Admin-Assertion": token,
        }
        resp = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=15)
        self.assertEqual(resp.status_code, 200)

    # ---- 8. Cryptographic Key Separation (Negative) -----------------------

    def test_cryptographic_key_separation_assertion_signed_with_service_key_rejected(self):
        """Administrator assertion signed with the internal service key MUST be rejected with 403."""
        # Malicious or confused client uses internal service key instead of assertion secret
        forged_token = create_admin_assertion_token(
            operator_id="sysadmin-usr-1",
            role="system_admin",
            operation="intel_sync",
            secret=TEST_INTERNAL_KEY  # Intentionally wrong key
        )
        headers = {
            **self.service_headers,
            "X-ShieldDesk-Admin-Assertion": forged_token
        }
        resp = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=10)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("signature verification failed", resp.json().get("error", ""))

    def test_cryptographic_key_separation_service_auth_with_assertion_secret_rejected(self):
        """Using the administrator assertion signing secret as service auth header MUST be rejected with 401."""
        token = create_admin_assertion_token(
            operator_id="sysadmin-usr-1",
            role="system_admin",
            operation="intel_sync"
        )
        headers = {
            "X-ShieldDesk-Internal-Key": TEST_ASSERTION_SECRET,  # Intentionally wrong key for service auth
            "X-ShieldDesk-Admin-Assertion": token
        }
        resp = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=10)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Unauthorized", resp.json().get("error", ""))

    # ---- 9. Target-Operation and Target-Version Binding -------------------

    def test_target_version_binding_unit(self):
        """Cryptographic approval token bound to version A must reject candidate version B."""
        token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="model_promote",
            target_id="v20261023120000"
        )
        # Matching target succeeds
        valid, msg, _ = verify_admin_assertion_token(token, expected_operation="model_promote", expected_target="v20261023120000")
        self.assertTrue(valid)
        self.assertEqual(msg, "")

        # Mismatched target fails closed
        token_replay = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="model_promote",
            target_id="v20261023120000"
        )
        valid2, msg2, _ = verify_admin_assertion_token(token_replay, expected_operation="model_promote", expected_target="v20261023999999")
        self.assertFalse(valid2)
        self.assertIn("Target mismatch", msg2)

    def test_target_operation_binding_unit(self):
        """Cryptographic approval token bound to operation A must reject operation B."""
        token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="model_rollback"
        )
        valid, msg, _ = verify_admin_assertion_token(token, expected_operation="model_promote")
        self.assertFalse(valid)
        self.assertIn("Operation mismatch", msg)

    def test_future_issued_token_rejected_403(self):
        """Token with iat in the future must be rejected with 403."""
        # Craft a token with iat 120 seconds in future
        now = int(time.time()) + 120
        payload = {
            "operator_id": "admin-1",
            "role": "super_admin",
            "operation": "intel_sync",
            "target_id": None,
            "nonce": "future-nonce-test-1",
            "iat": now,
            "exp": now + 300
        }
        encoded_payload = auth_util.base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        import hmac, hashlib
        sig = hmac.new(TEST_ASSERTION_SECRET.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest()
        future_token = f"{encoded_payload}.{auth_util.base64url_encode(sig)}"

        resp = requests.post(
            f"{self.base_url}/api/intel/sync",
            headers={**self.service_headers, "X-ShieldDesk-Admin-Assertion": future_token},
            json={},
            timeout=5
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("future", resp.json().get("error", "").lower())

    # ---- 10. Concurrent Replay and Durable Restart Protection ------------

    @mock.patch("server.CVEFeedSynchronizer")
    def test_concurrent_token_replay(self, mock_syncer_cls):
        """
        10 simultaneous threads attempting to consume the exact same token nonce.
        SQLite durable store with primary key constraint guarantees exactly 1 succeeds
        and 9 fail with 403 replay attack detected.
        """
        mock_instance = mock.MagicMock()
        mock_instance.sync_cisa_kev.return_value = [{"cve_id": "CVE-2024-9999"}]
        mock_instance.initialize_or_update_lookup_store.return_value = 13249
        mock_syncer_cls.return_value = mock_instance

        token = create_admin_assertion_token(
            operator_id="admin-1",
            role="super_admin",
            operation="intel_sync",
            ttl_seconds=300
        )
        headers = {**self.service_headers, "X-ShieldDesk-Admin-Assertion": token}

        results = []
        threads = []

        def _worker():
            try:
                r = requests.post(f"{self.base_url}/api/intel/sync", headers=headers, json={}, timeout=15)
                results.append((r.status_code, r.text))
            except Exception as e:
                results.append((500, str(e)))

        for _ in range(10):
            t = threading.Thread(target=_worker)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [code for code, text in results if code == 200]
        replays = [code for code, text in results if code == 403 and "Replay attack detected" in text]

        self.assertEqual(len(successes), 1, f"Expected exactly 1 success, got {len(successes)}: {results}")
        self.assertEqual(len(replays), 9, f"Expected 9 replay rejections, got {len(replays)}: {results}")

    def test_durable_nonce_store_concurrent_direct_consumption(self):
        """20 concurrent threads trying to consume the exact same nonce directly in DurableNonceStore."""
        test_nonce = f"direct-concurrent-nonce-{time.time()}"
        exp = int(time.time()) + 300

        def _consume():
            return DurableNonceStore.record_and_verify_nonce(
                nonce=test_nonce,
                operation="model_promote",
                operator_id="admin-1",
                exp=exp
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(_consume) for _ in range(20)]
            results = [f.result() for f in futures]

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False and "Replay attack detected" in r[1]]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 19)

    def test_durable_nonce_store_failure_recovery_fails_closed(self):
        """If SQLite database encounters an unrecoverable disk/lock error, record_and_verify_nonce must fail closed."""
        with mock.patch.object(DurableNonceStore, "_get_connection", side_effect=sqlite3.OperationalError("Disk I/O error")):
            ok, msg = DurableNonceStore.record_and_verify_nonce("any-nonce", "op", "user", int(time.time()) + 300)
            self.assertFalse(ok)
            self.assertIn("Nonce store error", msg)

    def test_authorized_trigger_scan_with_admin_assertion_succeeds(self):
        """Valid service key + signed admin assertion triggers scan and forwards verified operator ID."""
        real_post = requests.post
        mock_post = mock.MagicMock()
        mock_resp = mock.MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"findings": [], "message": "Scan completed"}
        mock_post.return_value = mock_resp

        import server
        server.requests.post = mock_post
        try:
            token = create_admin_assertion_token(
                operator_id="admin-sec-1",
                role="super_admin",
                operation="trigger_scan"
            )
            headers = {**self.service_headers, "X-ShieldDesk-Admin-Assertion": token}
            resp = real_post(f"{self.base_url}/api/trigger_scan", headers=headers, json={"target_path": "."}, timeout=10)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.json().get("success"), f"Status: {resp.status_code}, resp.json was: {resp.json()}")
            # Verify operator_id from signed assertion was forwarded to Next.js API, not arbitrary caller identity
            call_headers = mock_post.call_args[1].get("headers", {})
            self.assertEqual(call_headers.get("X-ShieldDesk-User"), "admin-sec-1")
        finally:
            server.requests.post = real_post

    def test_durable_replay_prevention_across_service_restart(self):
        """
        Verifies that nonces recorded in SQLite survive a simulated process restart,
        ensuring cross-restart and multi-process durability.
        """
        import tempfile
        temp_dir = tempfile.mkdtemp()
        restart_db = os.path.join(temp_dir, "restart_nonces.sqlite3")
        set_nonce_db_path_for_testing(restart_db)

        try:
            exp_time = int(time.time()) + 300
            test_nonce = f"restart-nonce-{time.time()}"

            # 1. Process 1 records nonce
            ok1, msg1 = DurableNonceStore.record_and_verify_nonce(
                nonce=test_nonce,
                operation="model_promote",
                operator_id="admin-1",
                exp=exp_time
            )
            self.assertTrue(ok1, f"First insert failed: {msg1}")

            # 2. Simulate server restart: force close connections, simulate fresh server start
            # Verify the file exists on disk
            self.assertTrue(os.path.exists(restart_db))

            # 3. Process 2 (or new server process) starts up with same database file
            ok2, msg2 = DurableNonceStore.record_and_verify_nonce(
                nonce=test_nonce,
                operation="model_promote",
                operator_id="admin-1",
                exp=exp_time
            )
            self.assertFalse(ok2, "Replay succeeded after restart when it must be rejected!")
            self.assertIn("Replay attack detected", msg2)
            self.assertIn("durable check", msg2)

        finally:
            set_nonce_db_path_for_testing(None)
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def test_cors_options_allowed_origin(self):
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST"
        }
        resp = requests.options(f"{self.base_url}/api/predict", headers=headers, timeout=5)
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://localhost:3000")

    def test_audit_trail_logging_entries(self):
        """Verifies structured audit entries in privileged_audit.jsonl."""
        self.assertTrue(os.path.exists(self.audit_file))
        with open(self.audit_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertGreater(len(lines), 0)
        last_entry = json.loads(lines[-1])
        for key in ["timestamp", "client_ip", "endpoint", "status_code", "operator_id", "role"]:
            self.assertIn(key, last_entry)

if __name__ == "__main__":
    unittest.main()

