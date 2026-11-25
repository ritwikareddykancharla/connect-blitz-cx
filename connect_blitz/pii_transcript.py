"""Real-Time Transcript Credit-Card/SSN/OTP Scrubber & Tamper-Evident Contact Ledger.

1. Scrubs Payment Account Numbers (PANs validated with ISO/IEC 7812 Luhn mod-10),
   US Social Security Numbers (SSNs), and authentication OTPs/CVVs/PINs BEFORE
   database storage or Amazon Bedrock transmission, while preserving non-Luhn
   tracking IDs and order numbers.
2. Appends every contact event to a SHA-256 hash-chained SQLite WAL ledger so
   unauthorized post-hoc transcript or supervisor action edits are detectable.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

GENESIS_HASH = "GENESIS_CONNECTBLITZ_LEDGER_0000"

# Candidate 13-to-19 digit PAN sequences separated by optional single spaces or hyphens
PAN_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# Hyphenated US SSN excluding SSA invalid ranges (000, 666, 900-999, 00, 0000)
SSN_HYPHEN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Contextual 9-digit unhyphenated SSN
SSN_CONTEXT_RE = re.compile(
    r"(?i)(\b(?:ssn|social\s+security(?:\s+number)?)\s*(?:is\s*)?[:#=-]?\s*)((?!000|666|9\d\d)\d{3}(?!00)\d{2}(?!0000)\d{4})\b"
)

# Contextual authentication OTP / verification code / PIN / CVV
OTP_CONTEXT_RE = re.compile(
    r"(?i)(\b(?:otp|passcode|one[- ]time\s+(?:code|password|pin)|verification\s+code|security\s+code|auth(?:entication)?\s+code|cvv2?|cvc|card\s+pin|login\s+pin)\s*(?:is\s*)?[:#=-]?\s*)(\d{3,8})\b"
)


def luhn_checksum_valid(digits_only: str) -> bool:
    """Verify ISO/IEC 7812 Luhn mod-10 checksum on a numeric string of 13..19 digits."""
    if not digits_only.isdigit() or not (13 <= len(digits_only) <= 19):
        return False
    if len(set(digits_only)) == 1 and digits_only[0] == "0":
        return False

    total = 0
    reverse_digits = digits_only[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10) == 0


def scrub_transcript_pii(
    text: str,
    pii_policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Scrub Luhn-valid PANs, SSNs, and auth OTPs in real time before persistence or LLM calls."""
    t0 = time.perf_counter()
    policy = pii_policy or {
        "scrub_pan_luhn": True,
        "scrub_ssn": True,
        "scrub_otp": True,
        "mask_style": "LAST4",
    }
    mask_style = str(policy.get("mask_style") or "LAST4").upper()
    scrub_pan = bool(policy.get("scrub_pan_luhn", True))
    scrub_ssn = bool(policy.get("scrub_ssn", True))
    scrub_otp = bool(policy.get("scrub_otp", True))

    working = str(text or "")
    detections: List[Dict[str, Any]] = []

    # 1. Scrub SSNs first so 9-digit patterns never collide with other matchers
    if scrub_ssn:
        def _repl_ssn_hyphen(match: re.Match[str]) -> str:
            raw = match.group(0)
            detections.append({
                "kind": "SSN",
                "rule_id": "CB-PII-SSN-01",
                "redacted_token": "[REDACTED_SSN]",
                "length": len(raw),
            })
            return "[REDACTED_SSN]"

        working = SSN_HYPHEN_RE.sub(_repl_ssn_hyphen, working)

        def _repl_ssn_ctx(match: re.Match[str]) -> str:
            prefix, raw_digits = match.group(1), match.group(2)
            detections.append({
                "kind": "SSN",
                "rule_id": "CB-PII-SSN-02",
                "redacted_token": "[REDACTED_SSN]",
                "length": len(raw_digits),
            })
            return f"{prefix}[REDACTED_SSN]"

        working = SSN_CONTEXT_RE.sub(_repl_ssn_ctx, working)

    # 2. Scrub Luhn-valid Payment Account Numbers (PANs) while preserving non-Luhn order/tracking IDs
    if scrub_pan:
        def _repl_pan(match: re.Match[str]) -> str:
            raw_span = match.group(0)
            # Skip order/tracking prefixes immediately preceding if hyphen-attached (handled by lookbehind)
            digits = re.sub(r"[^0-9]", "", raw_span)
            if not luhn_checksum_valid(digits):
                return raw_span
            replacement = (
                f"[REDACTED_PAN_LAST4:{digits[-4:]}]"
                if mask_style == "LAST4"
                else "[REDACTED_PAN]"
            )
            detections.append({
                "kind": "PAN_LUHN",
                "rule_id": "CB-PII-PAN-LUHN-01",
                "redacted_token": replacement,
                "last4": digits[-4:],
                "digit_count": len(digits),
            })
            return replacement

        working = PAN_CANDIDATE_RE.sub(_repl_pan, working)

    # 3. Scrub contextual OTPs, verification codes, PINs, and CVVs
    if scrub_otp:
        def _repl_otp(match: re.Match[str]) -> str:
            prefix, secret_code = match.group(1), match.group(2)
            detections.append({
                "kind": "AUTH_OTP",
                "rule_id": "CB-PII-OTP-01",
                "redacted_token": "[REDACTED_OTP]",
                "length": len(secret_code),
            })
            return f"{prefix}[REDACTED_OTP]"

        working = OTP_CONTEXT_RE.sub(_repl_otp, working)

    scrub_ms = round((time.perf_counter() - t0) * 1000.0, 4)
    return {
        "scrubbed_text": working,
        "pii_detected": len(detections) > 0,
        "redacted_count": len(detections),
        "detections": detections,
        "scrub_ms": scrub_ms,
    }


def _canonical_digest(payload: Dict[str, Any], prev_hash: str) -> str:
    envelope = {
        "prev_hash": prev_hash,
        "payload": payload,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ContactAuditLedger:
    """Append-only SQLite WAL SHA-256 hash-chained audit trail for contact-center events."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contact_audit_ledger (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        contact_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        actor_role TEXT NOT NULL,
                        visibility TEXT NOT NULL,
                        scrubbed_summary TEXT NOT NULL,
                        pii_redacted_count INTEGER NOT NULL DEFAULT 0,
                        created_at_utc TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def append_event(
        self,
        contact_id: str,
        event_type: str,
        actor_role: str,
        visibility: str,
        summary_text: str,
        pii_policy: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Scrub summary text for PII and append a cryptographically chained ledger row."""
        scrubbed = scrub_transcript_pii(summary_text, pii_policy=pii_policy)
        safe_summary = scrubbed["scrubbed_text"]
        redacted_count = int(scrubbed["redacted_count"])

        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT sha256_hash FROM contact_audit_ledger ORDER BY seq_id DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(row["sha256_hash"]) if row else GENESIS_HASH
                event_id = f"aud-{uuid.uuid4().hex[:10]}"
                created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

                payload = {
                    "event_id": event_id,
                    "contact_id": contact_id,
                    "event_type": event_type,
                    "actor_role": actor_role,
                    "visibility": visibility,
                    "scrubbed_summary": safe_summary,
                    "pii_redacted_count": redacted_count,
                    "created_at_utc": created_at,
                }
                digest = _canonical_digest(payload, prev_hash)

                conn.execute(
                    """
                    INSERT INTO contact_audit_ledger (
                        event_id, contact_id, event_type, actor_role, visibility,
                        scrubbed_summary, pii_redacted_count, created_at_utc, prev_hash, sha256_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        contact_id,
                        event_type,
                        actor_role,
                        visibility,
                        safe_summary,
                        redacted_count,
                        created_at,
                        prev_hash,
                        digest,
                    ),
                )
                conn.commit()
                return {
                    **payload,
                    "prev_hash": prev_hash,
                    "sha256_hash": digest,
                }
            finally:
                conn.close()

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Recompute every SHA-256 link from GENESIS to verify zero post-hoc tampering."""
        t0 = time.perf_counter()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM contact_audit_ledger ORDER BY seq_id ASC"
                ).fetchall()
            finally:
                conn.close()

        expected_prev = GENESIS_HASH
        head_hash = GENESIS_HASH
        for r in rows:
            payload = {
                "event_id": r["event_id"],
                "contact_id": r["contact_id"],
                "event_type": r["event_type"],
                "actor_role": r["actor_role"],
                "visibility": r["visibility"],
                "scrubbed_summary": r["scrubbed_summary"],
                "pii_redacted_count": int(r["pii_redacted_count"]),
                "created_at_utc": r["created_at_utc"],
            }
            recomputed = _canonical_digest(payload, expected_prev)
            if r["prev_hash"] != expected_prev or r["sha256_hash"] != recomputed:
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "tampered_event_id": r["event_id"],
                    "tampered_seq_id": int(r["seq_id"]),
                    "genesis_hash": GENESIS_HASH,
                    "head_hash": head_hash,
                    "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }
            expected_prev = recomputed
            head_hash = recomputed

        return {
            "valid": True,
            "checked_rows": len(rows),
            "tampered_event_id": None,
            "tampered_seq_id": None,
            "genesis_hash": GENESIS_HASH,
            "head_hash": head_hash,
            "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    def list_recent(self, limit: int = 25, contact_id: str | None = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if contact_id:
                    rows = conn.execute(
                        "SELECT * FROM contact_audit_ledger WHERE contact_id = ? ORDER BY seq_id DESC LIMIT ?",
                        (contact_id, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM contact_audit_ledger ORDER BY seq_id DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def clear_all(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM contact_audit_ledger;")
                conn.commit()
            finally:
                conn.close()
