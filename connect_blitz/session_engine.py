"""Omnichannel Session State Machine & Zero-Repeat Warm Handoff Engine.

Backed by SQLite WAL (`PRAGMA journal_mode=WAL`), enforcing:
  1. Contact lifecycle transitions:
       SELF_SERVICE_BOT -> QUEUED_WITH_CONTEXT -> AGENT_ACTIVE
       -> SUPERVISOR_WHISPER / BARGE_IN -> RESOLVED
  2. Idempotent `client_msg_id` deduplication across flaky mobile/web retries.
  3. Structured slot & verified-identity carryover so customers never repeat
     their order ID, item, or issue when escalated to a human agent.
  4. Strict persona-scoped visibility isolation: `WHISPER` and `SUPERVISOR_ONLY`
     events are physically stripped from Customer Web ECW and Mobile payloads.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .copilot_whisper import (
    POLICY_CATALOG,
    CopilotWhisperEngine,
    build_contextual_rich_card,
    evaluate_escalation_radar,
)
from .pii_transcript import ContactAuditLedger, scrub_transcript_pii
from .widget_config import (
    TENANT_PRESETS,
    adapt_rich_card_for_surface,
    render_surface_manifests,
    validate_widget_config,
)

CONTACT_STATES = (
    "SELF_SERVICE_BOT",
    "QUEUED_WITH_CONTEXT",
    "AGENT_ACTIVE",
    "SUPERVISOR_WHISPER",
    "BARGE_IN",
    "RESOLVED",
)

ORDER_ID_RE = re.compile(r"\b(ORD-\d{4,6}|TXN-\d{4,6}|FLT-\d{3,5})\b", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def extract_context_slots(
    current_slots: Dict[str, Any],
    scrubbed_text: str,
    tenant_id: str,
    selected_card_value: str | None = None,
) -> Dict[str, Any]:
    """Extract and carry forward structured customer context slots without re-prompting."""
    slots = copy.deepcopy(current_slots)
    kb = POLICY_CATALOG.get(tenant_id, POLICY_CATALOG["nordpeak-gear"])
    orders_catalog = kb.get("orders", {})
    low = scrubbed_text.lower()

    # Check explicit card selection first
    if selected_card_value:
        val = str(selected_card_value).strip()
        if val.upper() in orders_catalog:
            oid = val.upper()
            meta = orders_catalog[oid]
            slots["order_id"] = oid
            slots["item_name"] = meta["item_name"]
            slots["order_total_usd"] = meta["order_total_usd"]
        elif val in ("instant_express_replacement", "refund_original_payment", "speak_with_specialist"):
            slots["preferred_resolution"] = val
        elif any(day in val for day in ("Today", "Tomorrow", "Saturday")):
            slots["selected_time_slot"] = val

    # Check natural language order/transaction/flight IDs
    match = ORDER_ID_RE.search(scrubbed_text)
    if match:
        oid = match.group(1).upper()
        slots["order_id"] = oid
        if oid in orders_catalog:
            slots["item_name"] = orders_catalog[oid]["item_name"]
            slots["order_total_usd"] = orders_catalog[oid]["order_total_usd"]

    # Infer issue category from natural language
    if any(w in low for w in ("broken", "shattered", "cracked", "damaged", "leaking", "dent")):
        slots["issue_category"] = "damaged_item"
    elif any(w in low for w in ("unauthorized", "fraud", "stolen", "unrecognized")):
        slots["issue_category"] = "unauthorized_charge"
    elif any(w in low for w in ("flight", "delayed", "rebook", "gate", "connection")):
        slots["issue_category"] = "flight_rebooking"
    elif any(w in low for w in ("refund", "return", "money back")):
        slots.setdefault("issue_category", "refund_request")

    if "replace" in low and not slots.get("preferred_resolution"):
        slots["preferred_resolution"] = "instant_express_replacement"
    elif "refund" in low and not slots.get("preferred_resolution"):
        slots["preferred_resolution"] = "refund_original_payment"

    return slots


class ConnectBlitzSessionEngine:
    """SQLite WAL omnichannel session store, warm-handoff compiler, and 4-surface projector."""

    def __init__(
        self,
        data_dir: str | Path | None = None,
        copilot: CopilotWhisperEngine | None = None,
        seed_demo: bool = True,
    ) -> None:
        base = Path(data_dir or os.environ.get("CONNECTBLITZ_DATA_DIR", "/tmp/connectblitz-runtime"))
        base.mkdir(parents=True, exist_ok=True)
        self.data_dir = base
        self.db_path = base / "connectblitz_sessions.db"
        self.ledger = ContactAuditLedger(base / "connectblitz_audit.db")
        self.copilot = copilot or CopilotWhisperEngine()
        self._lock = threading.Lock()
        self._msg_cache: Dict[str, Dict[str, Any]] = {}
        self.active_configs: Dict[str, Dict[str, Any]] = copy.deepcopy(TENANT_PRESETS)
        self._init_schema()
        if seed_demo:
            self.ensure_demo_contacts_seeded()

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
                    CREATE TABLE IF NOT EXISTS contacts (
                        contact_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        assigned_agent TEXT NOT NULL,
                        context_slots_json TEXT NOT NULL,
                        state_history_json TEXT NOT NULL,
                        handoff_packet_json TEXT,
                        latest_copilot_json TEXT,
                        latest_radar_json TEXT,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contact_messages (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        msg_id TEXT NOT NULL UNIQUE,
                        contact_id TEXT NOT NULL,
                        client_msg_id TEXT NOT NULL,
                        sender_role TEXT NOT NULL,
                        sender_label TEXT NOT NULL,
                        visibility TEXT NOT NULL,
                        content TEXT NOT NULL,
                        rich_card_json TEXT,
                        pii_meta_json TEXT NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        UNIQUE(contact_id, client_msg_id)
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def ensure_demo_contacts_seeded(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT contact_id FROM contacts WHERE contact_id = 'cnt-blitz-demo-01'"
                ).fetchone()
            finally:
                conn.close()
        if not row:
            self.seed_demo_contacts()

    def seed_demo_contacts(self) -> None:
        """Reset and seed clean realistic omnichannel contacts for immediate 4-pane inspection."""
        with self._lock:
            self._msg_cache.clear()
            self.active_configs = copy.deepcopy(TENANT_PRESETS)
            conn = self._connect()
            try:
                conn.execute("DELETE FROM contact_messages;")
                conn.execute("DELETE FROM contacts;")
                conn.commit()
            finally:
                conn.close()
        self.ledger.clear_all()

        # Primary Demo Contact: NordPeak E-Commerce Damaged Espresso Machine
        cid = "cnt-blitz-demo-01"
        tenant_id = "nordpeak-gear"
        cfg = self.active_configs[tenant_id]
        now = _utc_now()
        initial_slots = {
            "customer_name": "Maya Lin",
            "customer_tier": "Prime VIP",
            "identity_verified": True,
            "auth_method": "Passkey + Biometric Session",
            "order_id": "ORD-88412",
            "item_name": "Alpine Pro Dual-Boiler Espresso Machine",
            "order_total_usd": 349.00,
            "issue_category": "damaged_item",
            "preferred_resolution": None,
            "selected_time_slot": None,
            "attempted_bot_steps": ["verified_passkey_session", "loaded_order_ORD-88412"],
        }
        initial_history = [{"state": "SELF_SERVICE_BOT", "at": now, "reason": "contact_initiated"}]

        msg1 = "Hi, my ORD-88412 Alpine Pro Espresso Machine arrived with a cracked water reservoir. Can I get an instant replacement?"
        radar = evaluate_escalation_radar(
            [{"sender_role": "CUSTOMER", "content": msg1}],
            initial_slots,
            cfg["sla_thresholds"],
            elapsed_wait_sec=6.0,
        )
        copilot_pack = self.copilot._deterministic_policy_pack(tenant_id, initial_slots, radar)
        card = build_contextual_rich_card(tenant_id, initial_slots, cfg["allowed_rich_cards"])
        copilot_pack["recommended_rich_card"] = card
        copilot_pack["llm_engine"] = "amazon-bedrock-ready"
        copilot_pack["model_id"] = self.copilot.model_id
        copilot_pack["bedrock_latency_ms"] = 0.0
        copilot_pack["bedrock_tokens"] = 0

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO contacts (
                        contact_id, tenant_id, state, assigned_agent,
                        context_slots_json, state_history_json, handoff_packet_json,
                        latest_copilot_json, latest_radar_json, created_at_utc, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cid,
                        tenant_id,
                        "SELF_SERVICE_BOT",
                        "AI Concierge (Unassigned)",
                        json.dumps(initial_slots),
                        json.dumps(initial_history),
                        None,
                        json.dumps(copilot_pack),
                        json.dumps(radar),
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        self._insert_raw_message(
            contact_id=cid,
            client_msg_id="seed-welcome-01",
            sender_role="AI_BOT",
            sender_label="NordPeak AI Concierge",
            visibility="PUBLIC",
            content=cfg["welcome_greeting"],
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )
        self._insert_raw_message(
            contact_id=cid,
            client_msg_id="seed-cust-01",
            sender_role="CUSTOMER",
            sender_label="Maya Lin (Prime VIP)",
            visibility="PUBLIC",
            content=msg1,
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )
        self._insert_raw_message(
            contact_id=cid,
            client_msg_id="seed-bot-card-01",
            sender_role="AI_BOT",
            sender_label="NordPeak AI Concierge",
            visibility="PUBLIC",
            content=copilot_pack["bot_public_reply"],
            rich_card=card,
            pii_policy=cfg["pii_policy"],
        )
        self._insert_raw_message(
            contact_id=cid,
            client_msg_id="seed-whisper-01",
            sender_role="COPILOT",
            sender_label="Bedrock Whisper Copilot",
            visibility="WHISPER",
            content=copilot_pack["agent_whisper_coaching"],
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )

    def create_contact(
        self,
        contact_id: str | None = None,
        tenant_id: str = "nordpeak-gear",
        customer_name: str = "Alex Rivera",
        customer_tier: str = "Prime VIP",
        identity_verified: bool = True,
    ) -> Dict[str, Any]:
        """Create a fresh contact session in `SELF_SERVICE_BOT` state."""
        cid = contact_id or f"cnt-{uuid.uuid4().hex[:8]}"
        if tenant_id not in self.active_configs:
            raise ValueError(f"Unknown tenant_id: {tenant_id}")
        cfg = self.active_configs[tenant_id]
        now = _utc_now()
        slots = {
            "customer_name": customer_name,
            "customer_tier": customer_tier,
            "identity_verified": identity_verified,
            "auth_method": "Passkey Session" if identity_verified else "Pending",
            "order_id": None,
            "item_name": None,
            "order_total_usd": 0.0,
            "issue_category": None,
            "preferred_resolution": None,
            "selected_time_slot": None,
            "attempted_bot_steps": ["session_started"],
        }
        radar = evaluate_escalation_radar([], slots, cfg["sla_thresholds"], elapsed_wait_sec=2.0)
        copilot_pack = self.copilot._deterministic_policy_pack(tenant_id, slots, radar)
        history = [{"state": "SELF_SERVICE_BOT", "at": now, "reason": "contact_created"}]

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO contacts (
                        contact_id, tenant_id, state, assigned_agent,
                        context_slots_json, state_history_json, handoff_packet_json,
                        latest_copilot_json, latest_radar_json, created_at_utc, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cid,
                        tenant_id,
                        "SELF_SERVICE_BOT",
                        "AI Concierge (Unassigned)",
                        json.dumps(slots),
                        json.dumps(history),
                        None,
                        json.dumps(copilot_pack),
                        json.dumps(radar),
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        card = build_contextual_rich_card(tenant_id, slots, cfg["allowed_rich_cards"])
        self._insert_raw_message(
            contact_id=cid,
            client_msg_id=f"{cid}-welcome",
            sender_role="AI_BOT",
            sender_label=f"{cfg['brand_name']} AI",
            visibility="PUBLIC",
            content=cfg["welcome_greeting"],
            rich_card=card,
            pii_policy=cfg["pii_policy"],
        )
        return self.render_contact_bundle(cid)

    def _insert_raw_message(
        self,
        contact_id: str,
        client_msg_id: str,
        sender_role: str,
        sender_label: str,
        visibility: str,
        content: str,
        rich_card: Dict[str, Any] | None,
        pii_policy: Dict[str, Any] | None,
    ) -> Tuple[Dict[str, Any], bool]:
        """Scrub PII, enforce `(contact_id, client_msg_id)` idempotency, and append audit hash."""
        scrub_res = scrub_transcript_pii(content, pii_policy=pii_policy)
        safe_text = scrub_res["scrubbed_text"]
        msg_id = f"msg-{uuid.uuid4().hex[:10]}"
        now = _utc_now()
        pii_meta = {
            "pii_detected": scrub_res["pii_detected"],
            "redacted_count": scrub_res["redacted_count"],
            "detections": scrub_res["detections"],
            "scrub_ms": scrub_res["scrub_ms"],
        }

        with self._lock:
            conn = self._connect()
            try:
                existing = conn.execute(
                    "SELECT * FROM contact_messages WHERE contact_id = ? AND client_msg_id = ?",
                    (contact_id, client_msg_id),
                ).fetchone()
                if existing:
                    return self._row_to_msg_dict(existing), True

                conn.execute(
                    """
                    INSERT INTO contact_messages (
                        msg_id, contact_id, client_msg_id, sender_role, sender_label,
                        visibility, content, rich_card_json, pii_meta_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        msg_id,
                        contact_id,
                        client_msg_id,
                        sender_role,
                        sender_label,
                        visibility,
                        safe_text,
                        json.dumps(rich_card) if rich_card else None,
                        json.dumps(pii_meta),
                        now,
                    ),
                )
                conn.commit()
                saved = conn.execute(
                    "SELECT * FROM contact_messages WHERE msg_id = ?", (msg_id,)
                ).fetchone()
            finally:
                conn.close()

        self.ledger.append_event(
            contact_id=contact_id,
            event_type=f"MESSAGE_{sender_role}_{visibility}",
            actor_role=sender_role,
            visibility=visibility,
            summary_text=safe_text,
            pii_policy=pii_policy,
        )
        return self._row_to_msg_dict(saved), False

    @staticmethod
    def _row_to_msg_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "seq_id": int(row["seq_id"]),
            "msg_id": row["msg_id"],
            "contact_id": row["contact_id"],
            "client_msg_id": row["client_msg_id"],
            "sender_role": row["sender_role"],
            "sender_label": row["sender_label"],
            "visibility": row["visibility"],
            "content": row["content"],
            "rich_card": json.loads(row["rich_card_json"]) if row["rich_card_json"] else None,
            "pii_meta": json.loads(row["pii_meta_json"]) if row["pii_meta_json"] else {},
            "created_at_utc": row["created_at_utc"],
        }

    def _compile_warm_handoff_packet(
        self,
        contact_id: str,
        tenant_id: str,
        slots: Dict[str, Any],
        radar: Dict[str, Any],
        copilot_res: Dict[str, Any],
        handoff_reason: str,
    ) -> Dict[str, Any]:
        kb = POLICY_CATALOG.get(tenant_id, POLICY_CATALOG["nordpeak-gear"])
        return {
            "handoff_id": f"wh-{uuid.uuid4().hex[:8]}",
            "contact_id": contact_id,
            "compiled_at_utc": _utc_now(),
            "handoff_reason": handoff_reason,
            "zero_repeat_guaranteed": True,
            "customer_repeat_prompts_required": 0,
            "verified_identity": {
                "customer_name": slots.get("customer_name") or "Verified Customer",
                "customer_tier": slots.get("customer_tier") or "Standard",
                "identity_verified": bool(slots.get("identity_verified", True)),
                "auth_method": slots.get("auth_method") or "Passkey Session",
            },
            "carried_context_slots": {
                "order_id": slots.get("order_id"),
                "item_name": slots.get("item_name"),
                "order_total_usd": slots.get("order_total_usd"),
                "issue_category": slots.get("issue_category"),
                "preferred_resolution": slots.get("preferred_resolution"),
                "selected_time_slot": slots.get("selected_time_slot"),
                "attempted_bot_steps": slots.get("attempted_bot_steps", []),
            },
            "sentiment_and_sla": {
                "frustration_score": radar["frustration_score"],
                "sentiment_label": radar["sentiment_label"],
                "escalation_triggers": radar["escalation_triggers"],
            },
            "policy_guidance": {
                "policy_id": kb["policy_id"],
                "policy_title": kb["policy_title"],
                "agent_whisper_coaching": copilot_res.get("agent_whisper_coaching"),
                "suggested_one_click_reply": copilot_res.get("suggested_agent_reply"),
            },
        }

    def post_message(
        self,
        contact_id: str,
        sender_role: str,
        content: str,
        client_msg_id: str | None = None,
        selected_card_value: str | None = None,
        visibility: str = "PUBLIC",
        use_bedrock: bool = True,
    ) -> Dict[str, Any]:
        """Process a customer or agent turn with idempotency, PII scrubbing, and Bedrock Whisper."""
        t0 = time.perf_counter()
        role = str(sender_role or "CUSTOMER").upper()
        if role not in ("CUSTOMER", "AGENT"):
            raise ValueError("sender_role for /api/contact/message must be 'CUSTOMER' or 'AGENT'.")
        vis = str(visibility or "PUBLIC").upper()
        if role == "CUSTOMER":
            vis = "PUBLIC"
        elif vis not in ("PUBLIC", "WHISPER"):
            raise ValueError("Agent message visibility must be 'PUBLIC' or 'WHISPER'.")

        c_msg_id = str(client_msg_id or f"cmsg-{uuid.uuid4().hex[:12]}").strip()
        cache_key = f"{contact_id}::{c_msg_id}"
        if cache_key in self._msg_cache:
            cached_bundle = self.render_contact_bundle(contact_id)
            cached_bundle["deduplicated"] = True
            cached_bundle["client_msg_id"] = c_msg_id
            cached_bundle["turn_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            return cached_bundle

        contact = self._get_contact_row(contact_id)
        tenant_id = contact["tenant_id"]
        cfg = self.active_configs[tenant_id]
        slots = json.loads(contact["context_slots_json"])
        history = json.loads(contact["state_history_json"])
        state = contact["state"]

        sender_label = (
            f"{slots.get('customer_name', 'Customer')} ({slots.get('customer_tier', 'Customer')})"
            if role == "CUSTOMER"
            else ("Agent Jordan (Internal Note)" if vis == "WHISPER" else "Specialist Jordan")
        )

        msg_record, was_dup = self._insert_raw_message(
            contact_id=contact_id,
            client_msg_id=c_msg_id,
            sender_role=role,
            sender_label=sender_label,
            visibility=vis,
            content=content,
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )
        if was_dup:
            bundle = self.render_contact_bundle(contact_id)
            bundle["deduplicated"] = True
            bundle["client_msg_id"] = c_msg_id
            bundle["turn_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            return bundle

        if role == "CUSTOMER":
            slots = extract_context_slots(
                current_slots=slots,
                scrubbed_text=msg_record["content"],
                tenant_id=tenant_id,
                selected_card_value=selected_card_value,
            )
            if selected_card_value:
                steps = list(slots.get("attempted_bot_steps") or [])
                steps.append(f"selected_card:{selected_card_value}")
                slots["attempted_bot_steps"] = steps[-8:]

        all_msgs = self._list_messages(contact_id)
        public_msgs = [m for m in all_msgs if m["visibility"] == "PUBLIC"]
        radar = evaluate_escalation_radar(
            public_messages=public_msgs,
            context_slots=slots,
            sla_thresholds=cfg["sla_thresholds"],
            elapsed_wait_sec=11.0,
        )

        copilot_res = json.loads(contact["latest_copilot_json"] or "{}")
        handoff_packet = json.loads(contact["handoff_packet_json"]) if contact["handoff_packet_json"] else None
        assigned_agent = contact["assigned_agent"]

        if role == "CUSTOMER":
            copilot_res = self.copilot.generate_whisper_and_reply(
                tenant_config=cfg,
                public_messages=public_msgs,
                context_slots=slots,
                radar=radar,
                use_bedrock=use_bedrock,
            )

            should_escalate = (
                state == "SELF_SERVICE_BOT"
                and (
                    radar["recommend_warm_handoff"]
                    or selected_card_value == "speak_with_specialist"
                )
            )

            if should_escalate:
                now_q = _utc_now()
                history.append({
                    "state": "QUEUED_WITH_CONTEXT",
                    "at": now_q,
                    "reason": ",".join(radar["escalation_triggers"]) or "warm_handoff_requested",
                })
                self.ledger.append_event(
                    contact_id=contact_id,
                    event_type="STATE_TRANSITION_QUEUED_WITH_CONTEXT",
                    actor_role="SYSTEM",
                    visibility="PUBLIC",
                    summary_text=f"Queued with verified context ({slots.get('order_id') or 'account_verified'})",
                    pii_policy=cfg["pii_policy"],
                )

                now_a = _utc_now()
                state = "AGENT_ACTIVE"
                assigned_agent = "Specialist Jordan"
                history.append({
                    "state": "AGENT_ACTIVE",
                    "at": now_a,
                    "reason": "specialist_accepted_warm_handoff",
                })
                handoff_packet = self._compile_warm_handoff_packet(
                    contact_id=contact_id,
                    tenant_id=tenant_id,
                    slots=slots,
                    radar=radar,
                    copilot_res=copilot_res,
                    handoff_reason=",".join(radar["escalation_triggers"]) or "customer_escalation",
                )
                order_tag = f" for {slots['order_id']}" if slots.get("order_id") else ""
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-handoff-pub",
                    sender_role="AI_BOT",
                    sender_label=f"{cfg['brand_name']} Router",
                    visibility="PUBLIC",
                    content=(
                        f"Connecting you with {assigned_agent}. Your verified identity and details"
                        f"{order_tag} are already shared so you will not need to repeat anything."
                    ),
                    rich_card=None,
                    pii_policy=cfg["pii_policy"],
                )
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-handoff-whisper",
                    sender_role="COPILOT",
                    sender_label="Bedrock Whisper Copilot",
                    visibility="WHISPER",
                    content=copilot_res["agent_whisper_coaching"],
                    rich_card=None,
                    pii_policy=cfg["pii_policy"],
                )
            elif state == "SELF_SERVICE_BOT":
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-bot-reply",
                    sender_role="AI_BOT",
                    sender_label=f"{cfg['brand_name']} AI",
                    visibility="PUBLIC",
                    content=copilot_res["bot_public_reply"],
                    rich_card=copilot_res.get("recommended_rich_card"),
                    pii_policy=cfg["pii_policy"],
                )
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-bot-whisper",
                    sender_role="COPILOT",
                    sender_label="Bedrock Whisper Copilot",
                    visibility="WHISPER",
                    content=copilot_res["agent_whisper_coaching"],
                    rich_card=None,
                    pii_policy=cfg["pii_policy"],
                )
            else:
                # Contact is already with Agent or Supervisor: push private Copilot Whisper only
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-live-whisper",
                    sender_role="COPILOT",
                    sender_label="Bedrock Whisper Copilot",
                    visibility="WHISPER",
                    content=copilot_res["agent_whisper_coaching"],
                    rich_card=None,
                    pii_policy=cfg["pii_policy"],
                )

            if radar["auto_supervisor_alert"]:
                self._insert_raw_message(
                    contact_id=contact_id,
                    client_msg_id=f"{c_msg_id}-sup-alert",
                    sender_role="COPILOT",
                    sender_label="SLA & Sentiment Radar",
                    visibility="SUPERVISOR_ONLY",
                    content=copilot_res["supervisor_alert_reason"],
                    rich_card=None,
                    pii_policy=cfg["pii_policy"],
                )

        self._save_contact_state(
            contact_id=contact_id,
            state=state,
            assigned_agent=assigned_agent,
            slots=slots,
            history=history,
            handoff_packet=handoff_packet,
            copilot_res=copilot_res,
            radar=radar,
        )

        bundle = self.render_contact_bundle(contact_id)
        bundle["deduplicated"] = False
        bundle["client_msg_id"] = c_msg_id
        bundle["pii_scrub_report"] = msg_record["pii_meta"]
        bundle["turn_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        self._msg_cache[cache_key] = {"msg_id": msg_record["msg_id"]}
        return bundle

    def trigger_warm_handoff(
        self,
        contact_id: str,
        reason: str = "zero_repeat_warm_escalation",
        use_bedrock: bool = True,
    ) -> Dict[str, Any]:
        """Execute `SELF_SERVICE_BOT -> QUEUED_WITH_CONTEXT -> AGENT_ACTIVE` with full context packet."""
        t0 = time.perf_counter()
        contact = self._get_contact_row(contact_id)
        tenant_id = contact["tenant_id"]
        cfg = self.active_configs[tenant_id]
        slots = json.loads(contact["context_slots_json"])
        history = json.loads(contact["state_history_json"])

        all_msgs = self._list_messages(contact_id)
        public_msgs = [m for m in all_msgs if m["visibility"] == "PUBLIC"]
        radar = evaluate_escalation_radar(
            public_messages=public_msgs,
            context_slots=slots,
            sla_thresholds=cfg["sla_thresholds"],
            elapsed_wait_sec=14.0,
        )
        existing_cop = json.loads(contact["latest_copilot_json"] or "{}")
        if not use_bedrock and existing_cop.get("llm_engine") == "amazon-bedrock":
            copilot_res = existing_cop
        else:
            copilot_res = self.copilot.generate_whisper_and_reply(
                tenant_config=cfg,
                public_messages=public_msgs,
                context_slots=slots,
                radar=radar,
                use_bedrock=use_bedrock,
            )

        now_q = _utc_now()
        history.append({"state": "QUEUED_WITH_CONTEXT", "at": now_q, "reason": reason})
        self.ledger.append_event(
            contact_id=contact_id,
            event_type="STATE_TRANSITION_QUEUED_WITH_CONTEXT",
            actor_role="SYSTEM",
            visibility="PUBLIC",
            summary_text=f"Warm handoff queued for {contact_id} ({reason})",
            pii_policy=cfg["pii_policy"],
        )

        now_a = _utc_now()
        state = "AGENT_ACTIVE"
        assigned_agent = "Specialist Jordan"
        history.append({"state": "AGENT_ACTIVE", "at": now_a, "reason": "agent_desk_connected"})

        handoff_packet = self._compile_warm_handoff_packet(
            contact_id=contact_id,
            tenant_id=tenant_id,
            slots=slots,
            radar=radar,
            copilot_res=copilot_res,
            handoff_reason=reason,
        )

        uid = uuid.uuid4().hex[:8]
        order_ref = f" ({slots['order_id']})" if slots.get("order_id") else ""
        self._insert_raw_message(
            contact_id=contact_id,
            client_msg_id=f"wh-pub-{uid}",
            sender_role="AI_BOT",
            sender_label=f"{cfg['brand_name']} Warm Handoff",
            visibility="PUBLIC",
            content=(
                f"Specialist Jordan joined the conversation with your verified profile and order context"
                f"{order_ref} pre-loaded. You do not need to repeat any details."
            ),
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )
        self._insert_raw_message(
            contact_id=contact_id,
            client_msg_id=f"wh-whisper-{uid}",
            sender_role="COPILOT",
            sender_label="Bedrock Whisper Copilot",
            visibility="WHISPER",
            content=copilot_res["agent_whisper_coaching"],
            rich_card=None,
            pii_policy=cfg["pii_policy"],
        )

        self._save_contact_state(
            contact_id=contact_id,
            state=state,
            assigned_agent=assigned_agent,
            slots=slots,
            history=history,
            handoff_packet=handoff_packet,
            copilot_res=copilot_res,
            radar=radar,
        )
        bundle = self.render_contact_bundle(contact_id)
        bundle["handoff_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return bundle

    def execute_supervisor_action(
        self,
        contact_id: str,
        action_type: str,
        message_text: str = "",
        supervisor_name: str = "Supervisor Elena",
        client_msg_id: str | None = None,
    ) -> Dict[str, Any]:
        """Execute Supervisor `WHISPER` (agent-only), `BARGE_IN` (public takeover), or `RESOLVE`."""
        t0 = time.perf_counter()
        act = str(action_type or "").upper().strip()
        if act not in ("WHISPER", "BARGE_IN", "RESOLVE"):
            raise ValueError("action_type must be 'WHISPER', 'BARGE_IN', or 'RESOLVE'.")

        contact = self._get_contact_row(contact_id)
        tenant_id = contact["tenant_id"]
        cfg = self.active_configs[tenant_id]
        slots = json.loads(contact["context_slots_json"])
        history = json.loads(contact["state_history_json"])
        handoff_packet = json.loads(contact["handoff_packet_json"]) if contact["handoff_packet_json"] else None
        copilot_res = json.loads(contact["latest_copilot_json"] or "{}")
        radar = json.loads(contact["latest_radar_json"] or "{}")
        assigned_agent = contact["assigned_agent"]
        c_msg_id = str(client_msg_id or f"sup-{act.lower()}-{uuid.uuid4().hex[:8]}")

        if act == "WHISPER":
            new_state = "SUPERVISOR_WHISPER"
            if assigned_agent.startswith("AI Concierge"):
                assigned_agent = "Specialist Jordan"
            note = message_text.strip() or (
                f"Private Whisper: Approve immediate express replacement on {slots.get('order_id') or 'this order'} "
                f"plus a $25 VIP credit under {POLICY_CATALOG.get(tenant_id, POLICY_CATALOG['nordpeak-gear'])['policy_id']}."
            )
            self._insert_raw_message(
                contact_id=contact_id,
                client_msg_id=c_msg_id,
                sender_role="SUPERVISOR",
                sender_label=f"{supervisor_name} (Whisper to Agent)",
                visibility="WHISPER",
                content=note,
                rich_card=None,
                pii_policy=cfg["pii_policy"],
            )
            history.append({"state": new_state, "at": _utc_now(), "reason": "supervisor_private_whisper"})

        elif act == "BARGE_IN":
            new_state = "BARGE_IN"
            assigned_agent = f"{supervisor_name} (Lead Escalation)"
            pub_text = message_text.strip() or (
                f"Hi {slots.get('customer_name') or 'there'}, this is {supervisor_name}, Floor Lead. "
                f"I reviewed your verified order {slots.get('order_id') or ''} directly and authorized "
                f"priority express replacement shipping today plus a $25.00 courtesy credit."
            )
            self._insert_raw_message(
                contact_id=contact_id,
                client_msg_id=c_msg_id,
                sender_role="SUPERVISOR",
                sender_label=f"{supervisor_name} (Supervisor Barge-In)",
                visibility="PUBLIC",
                content=pub_text,
                rich_card=None,
                pii_policy=cfg["pii_policy"],
            )
            history.append({"state": new_state, "at": _utc_now(), "reason": "supervisor_public_barge_in"})

        else:  # RESOLVE
            new_state = "RESOLVED"
            slots["resolution_confirmed"] = True
            confirm_card = None
            if "REPLACEMENT_CONFIRM" in cfg.get("allowed_rich_cards", []):
                confirm_card = {
                    "card_type": "REPLACEMENT_CONFIRM",
                    "title": "Express Replacement & Courtesy Credit Confirmed",
                    "order_id": slots.get("order_id") or "ORD-88412",
                    "replacement_sku": f"{slots.get('item_name') or 'Verified Order'} (Priority Unit)",
                    "eta_window": slots.get("selected_time_slot") or "Today 5:00 PM - 7:00 PM",
                    "options": [],
                }
            res_text = message_text.strip() or (
                f"Your replacement for {slots.get('order_id') or 'your order'} and $25.00 VIP credit are confirmed. "
                f"Thank you for chatting with {cfg['brand_name']}!"
            )
            self._insert_raw_message(
                contact_id=contact_id,
                client_msg_id=c_msg_id,
                sender_role="SUPERVISOR",
                sender_label=supervisor_name,
                visibility="PUBLIC",
                content=res_text,
                rich_card=confirm_card,
                pii_policy=cfg["pii_policy"],
            )
            history.append({"state": new_state, "at": _utc_now(), "reason": "contact_resolved"})

        self._save_contact_state(
            contact_id=contact_id,
            state=new_state,
            assigned_agent=assigned_agent,
            slots=slots,
            history=history,
            handoff_packet=handoff_packet,
            copilot_res=copilot_res,
            radar=radar,
        )
        bundle = self.render_contact_bundle(contact_id)
        bundle["action_type"] = act
        bundle["action_latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return bundle

    def validate_and_apply_config(
        self,
        raw_config: Dict[str, Any],
        apply_live: bool = True,
        contact_id: str = "cnt-blitz-demo-01",
    ) -> Dict[str, Any]:
        """Validate a declarative tenant widget config and optionally hot-apply it across all 4 surfaces."""
        validation = validate_widget_config(raw_config)
        if validation["valid"] and apply_live and validation["normalized_config"]:
            norm = validation["normalized_config"]
            tid = norm["tenant_id"]
            self.active_configs[tid] = norm
            # If the target contact exists, align its tenant_id if matching or re-render live
            try:
                contact = self._get_contact_row(contact_id)
                if contact["tenant_id"] != tid and tid in self.active_configs:
                    with self._lock:
                        conn = self._connect()
                        try:
                            conn.execute(
                                "UPDATE contacts SET tenant_id = ?, updated_at_utc = ? WHERE contact_id = ?",
                                (tid, _utc_now(), contact_id),
                            )
                            conn.commit()
                        finally:
                            conn.close()
                self.ledger.append_event(
                    contact_id=contact_id,
                    event_type="WIDGET_CONFIG_APPLIED",
                    actor_role="ADMIN",
                    visibility="SUPERVISOR_ONLY",
                    summary_text=(
                        f"Applied widget schema for {tid} (primary={norm['theme']['primary_hex']}, "
                        f"mask={norm['pii_policy']['mask_style']}, cards={len(norm['allowed_rich_cards'])})"
                    ),
                    pii_policy=norm["pii_policy"],
                )
                validation["live_bundle"] = self.render_contact_bundle(contact_id)
            except KeyError:
                pass
        return validation

    def render_contact_bundle(self, contact_id: str) -> Dict[str, Any]:
        """Project a single contact log into 4 strictly role-scoped surface payloads."""
        t0 = time.perf_counter()
        contact = self._get_contact_row(contact_id)
        tenant_id = contact["tenant_id"]
        cfg = self.active_configs.get(tenant_id, TENANT_PRESETS["nordpeak-gear"])
        manifests = render_surface_manifests(cfg)
        slots = json.loads(contact["context_slots_json"])
        history = json.loads(contact["state_history_json"])
        handoff_packet = json.loads(contact["handoff_packet_json"]) if contact["handoff_packet_json"] else None
        copilot_res = json.loads(contact["latest_copilot_json"] or "{}")
        radar = json.loads(contact["latest_radar_json"] or "{}")
        all_msgs = self._list_messages(contact_id)

        def _project_messages_for_surface(surface_key: str) -> List[Dict[str, Any]]:
            manifest = manifests[surface_key]
            allowed_vis = set(manifest["allowed_visibilities"])
            projected: List[Dict[str, Any]] = []
            for m in all_msgs:
                if m["visibility"] not in allowed_vis:
                    continue
                item: Dict[str, Any] = {
                    "msg_id": m["msg_id"],
                    "sender_role": m["sender_role"],
                    "sender_label": m["sender_label"],
                    "visibility": m["visibility"],
                    "content": m["content"],
                    "created_at_utc": m["created_at_utc"],
                    "rich_card": adapt_rich_card_for_surface(m["rich_card"], manifest),
                }
                if surface_key in ("agent_desk", "supervisor_console"):
                    item["pii_meta"] = m["pii_meta"]
                    item["client_msg_id"] = m["client_msg_id"]
                projected.append(item)
            return projected

        web_msgs = _project_messages_for_surface("customer_web_ecw")
        mob_msgs = _project_messages_for_surface("customer_mobile_compact")
        agent_msgs = _project_messages_for_surface("agent_desk")
        sup_msgs = _project_messages_for_surface("supervisor_console")

        chain_status = self.ledger.verify_chain_integrity()
        render_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        return {
            "contact_id": contact_id,
            "tenant_id": tenant_id,
            "state": contact["state"],
            "assigned_agent": contact["assigned_agent"],
            "state_history": history,
            "active_config": cfg,
            "render_ms": render_ms,
            "surfaces": {
                # 1. Customer Web ECW: Strictly PUBLIC messages only, ZERO whisper/internal metadata!
                "customer_web_ecw": {
                    "surface_id": "customer_web_ecw",
                    "manifest": manifests["customer_web_ecw"],
                    "contact_state": contact["state"],
                    "assigned_responder": contact["assigned_agent"],
                    "visible_message_count": len(web_msgs),
                    "messages": web_msgs,
                },
                # 2. Customer Mobile Compact: Strictly PUBLIC messages + condensed bottom-sheet cards!
                "customer_mobile_compact": {
                    "surface_id": "customer_mobile_compact",
                    "manifest": manifests["customer_mobile_compact"],
                    "contact_state": contact["state"],
                    "assigned_responder": contact["assigned_agent"],
                    "visible_message_count": len(mob_msgs),
                    "messages": mob_msgs,
                },
                # 3. Contact-Center Agent Desk: PUBLIC + WHISPER + Zero-Repeat Context + 1-Click Reply
                "agent_desk": {
                    "surface_id": "agent_desk",
                    "manifest": manifests["agent_desk"],
                    "contact_state": contact["state"],
                    "assigned_agent": contact["assigned_agent"],
                    "context_slots": slots,
                    "warm_handoff_packet": handoff_packet,
                    "copilot_whisper": {
                        "policy_id": copilot_res.get("policy_id"),
                        "agent_whisper_coaching": copilot_res.get("agent_whisper_coaching"),
                        "suggested_agent_reply": copilot_res.get("suggested_agent_reply"),
                        "llm_engine": copilot_res.get("llm_engine"),
                        "model_id": copilot_res.get("model_id"),
                        "bedrock_latency_ms": copilot_res.get("bedrock_latency_ms", 0.0),
                        "bedrock_tokens": copilot_res.get("bedrock_tokens", 0),
                    },
                    "visible_message_count": len(agent_msgs),
                    "messages": agent_msgs,
                },
                # 4. Supervisor Oversight Console: PUBLIC + WHISPER + SUPERVISOR_ONLY + SLA Radar + Ledger
                "supervisor_console": {
                    "surface_id": "supervisor_console",
                    "manifest": manifests["supervisor_console"],
                    "contact_state": contact["state"],
                    "assigned_agent": contact["assigned_agent"],
                    "sla_radar": radar,
                    "context_slots": slots,
                    "warm_handoff_packet": handoff_packet,
                    "audit_chain": chain_status,
                    "visible_message_count": len(sup_msgs),
                    "messages": sup_msgs,
                },
            },
            "audit_events": self.ledger.list_recent(limit=20),
            "audit_chain": chain_status,
        }

    def _get_contact_row(self, contact_id: str) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM contacts WHERE contact_id = ?", (contact_id,)
                ).fetchone()
                if not row:
                    raise KeyError(f"Unknown contact_id: {contact_id}")
                return dict(row)
            finally:
                conn.close()

    def _list_messages(self, contact_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM contact_messages WHERE contact_id = ? ORDER BY seq_id ASC",
                    (contact_id,),
                ).fetchall()
                return [self._row_to_msg_dict(r) for r in rows]
            finally:
                conn.close()

    def _save_contact_state(
        self,
        contact_id: str,
        state: str,
        assigned_agent: str,
        slots: Dict[str, Any],
        history: List[Dict[str, Any]],
        handoff_packet: Dict[str, Any] | None,
        copilot_res: Dict[str, Any],
        radar: Dict[str, Any],
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE contacts
                    SET state = ?,
                        assigned_agent = ?,
                        context_slots_json = ?,
                        state_history_json = ?,
                        handoff_packet_json = ?,
                        latest_copilot_json = ?,
                        latest_radar_json = ?,
                        updated_at_utc = ?
                    WHERE contact_id = ?
                    """,
                    (
                        state,
                        assigned_agent,
                        json.dumps(slots),
                        json.dumps(history),
                        json.dumps(handoff_packet) if handoff_packet else None,
                        json.dumps(copilot_res),
                        json.dumps(radar),
                        _utc_now(),
                        contact_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
