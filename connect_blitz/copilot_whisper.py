"""Live Amazon Bedrock Agent Whisper Copilot & Sentiment/SLA Escalation Radar.

1. Computes deterministic customer frustration & SLA breach scores in < 0.5 ms.
2. Grounds replies in tenant business policies and order/account lookup catalogs.
3. Calls Amazon Bedrock (`us.amazon.nova-lite-v1:0`) via the Converse API on
   PII-scrubbed transcripts to generate self-service replies, private Agent
   Whisper coaching, and 1-click zero-repeat agent responses.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List

from .pii_transcript import scrub_transcript_pii

DEFAULT_BEDROCK_MODEL = os.environ.get("CONNECTBLITZ_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0")
DEFAULT_AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"

FRUSTRATION_LEXICON: Dict[str, float] = {
    "broken": 0.22,
    "shattered": 0.28,
    "cracked": 0.24,
    "damaged": 0.22,
    "leaking": 0.25,
    "unacceptable": 0.30,
    "ridiculous": 0.30,
    "terrible": 0.26,
    "furious": 0.34,
    "angry": 0.28,
    "upset": 0.22,
    "frustrated": 0.28,
    "supervisor": 0.32,
    "manager": 0.28,
    "human": 0.20,
    "person": 0.16,
    "agent": 0.18,
    "escalate": 0.32,
    "cancel": 0.24,
    "fraud": 0.34,
    "unauthorized": 0.30,
    "stolen": 0.32,
    "stranded": 0.34,
    "missed": 0.22,
    "urgent": 0.22,
    "immediately": 0.18,
    "again": 0.16,
    "repeat": 0.22,
    "already told": 0.28,
    "third time": 0.32,
}

EXPLICIT_ESCALATION_RE = re.compile(
    r"(?i)\b(human\s+agent|real\s+person|speak\s+to\s+(?:an?\s+)?(?:agent|representative|manager|supervisor)|escalate|transfer\s+me)\b"
)

POLICY_CATALOG: Dict[str, Dict[str, Any]] = {
    "nordpeak-gear": {
        "policy_id": "POL-NP-DAMAGED-24H",
        "policy_title": "Damaged High-Value Appliance Express Replacement",
        "rule_summary": (
            "Self-service bot auto-approves refunds/replacements up to $250.00. "
            "Orders above $250.00 arriving damaged qualify for Agent-approved Instant Express "
            "Replacement (ships before return pickup) plus a $25.00 Prime VIP courtesy credit."
        ),
        "orders": {
            "ORD-88412": {
                "order_id": "ORD-88412",
                "item_name": "Alpine Pro Dual-Boiler Espresso Machine",
                "order_total_usd": 349.00,
                "delivered_date": "Yesterday, 4:18 PM",
                "warranty_tier": "Prime VIP 2-Year Protection",
            },
            "ORD-90219": {
                "order_id": "ORD-90219",
                "item_name": "Conical Steel Burr Grinder",
                "order_total_usd": 129.00,
                "delivered_date": "3 days ago",
                "warranty_tier": "Standard Coverage",
            },
        },
    },
    "harbor-bank": {
        "policy_id": "POL-HB-DISPUTE-ZERO",
        "policy_title": "Zero-Liability Card Freeze & Provisional Dispute Credit",
        "rule_summary": (
            "Unauthorized card transactions above $150.00 require instant digital card freeze, "
            "replacement virtual card issuance, and Agent-confirmed 24-hour provisional credit."
        ),
        "orders": {
            "TXN-44109": {
                "order_id": "TXN-44109",
                "item_name": "Card Charge: EuroTech Duty-Free Milan",
                "order_total_usd": 412.80,
                "delivered_date": "Today, 02:14 AM UTC",
                "warranty_tier": "Zero-Liability Platinum Protection",
            },
        },
    },
    "skyline-air": {
        "policy_id": "POL-SA-IRROPS-WAIVER",
        "policy_title": "Irregular Operations Same-Day Fare-Difference Waiver",
        "rule_summary": (
            "Delays or cancellations exceeding 90 minutes waive all fare differences on "
            "same-day Skyline or partner departures plus a $30 meal voucher."
        ),
        "orders": {
            "FLT-204": {
                "order_id": "FLT-204",
                "item_name": "Flight SA-204 (Seattle SEA to New York JFK)",
                "order_total_usd": 468.00,
                "delivered_date": "Delayed 135 mins (Gate B14)",
                "warranty_tier": "Skyline Gold Medallion",
            },
        },
    },
}


def _sanitize_prose(text: str) -> str:
    """Ensure clean punctuation without em-dashes in generated suggestions."""
    return str(text or "").replace("\u2014", ", ").replace("\u2013", "-").strip()


def evaluate_escalation_radar(
    public_messages: List[Dict[str, Any]],
    context_slots: Dict[str, Any],
    sla_thresholds: Dict[str, Any],
    elapsed_wait_sec: float = 8.0,
) -> Dict[str, Any]:
    """Deterministically score customer frustration, policy-cap exceptions, and SLA breach risk."""
    t0 = time.perf_counter()
    customer_msgs = [
        str(m.get("content") or "")
        for m in public_messages
        if m.get("sender_role") == "CUSTOMER"
    ]
    latest_text = customer_msgs[-1] if customer_msgs else ""
    combined_lower = " ".join(customer_msgs[-3:]).lower()

    score = 0.12
    triggers: List[str] = []

    matched_terms: List[str] = []
    for phrase, weight in FRUSTRATION_LEXICON.items():
        if phrase in combined_lower:
            score += weight
            matched_terms.append(phrase)
    if matched_terms:
        triggers.append(f"sentiment_signals({','.join(matched_terms[:3])})")

    if latest_text.count("!") >= 2:
        score += 0.08
        triggers.append("punctuation_intensity")

    alpha_chars = [c for c in latest_text if c.isalpha()]
    if len(alpha_chars) >= 12:
        upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if upper_ratio >= 0.45:
            score += 0.12
            triggers.append("caps_emphasis")

    explicit_human = bool(EXPLICIT_ESCALATION_RE.search(latest_text))
    if explicit_human:
        score = max(score, 0.78)
        triggers.append("explicit_agent_request")

    order_total = float(context_slots.get("order_total_usd") or 0.0)
    max_auto_refund = float(sla_thresholds.get("max_auto_refund_usd") or 250.0)
    issue_cat = str(context_slots.get("issue_category") or "")
    policy_cap_exceeded = order_total > max_auto_refund and issue_cat in (
        "damaged_item",
        "unauthorized_charge",
        "flight_rebooking",
        "refund_request",
    )
    if policy_cap_exceeded:
        score = max(score + 0.14, 0.64)
        triggers.append(f"exceeds_auto_cap(${order_total:.0f}>${max_auto_refund:.0f})")

    turn_count = len(customer_msgs)
    max_turns = max(1, int(sla_thresholds.get("max_self_service_turns") or 5))
    if turn_count >= max_turns:
        score = max(score + 0.15, 0.74)
        triggers.append(f"max_bot_turns({turn_count}/{max_turns})")

    frustration_score = round(min(0.99, max(0.05, score)), 3)

    first_resp_sla = max(5.0, float(sla_thresholds.get("first_response_sec") or 25.0))
    wait_ratio = min(1.0, elapsed_wait_sec / first_resp_sla)
    turn_ratio = min(1.0, turn_count / float(max_turns))
    sla_risk_score = round(min(0.99, 0.45 * wait_ratio + 0.30 * turn_ratio + 0.25 * frustration_score), 3)

    whisper_th = float(sla_thresholds.get("frustration_whisper_threshold") or 0.58)
    escalate_th = float(sla_thresholds.get("auto_escalate_threshold") or 0.72)

    if frustration_score >= 0.75:
        sentiment_label = "CRITICAL_ESCALATION"
    elif frustration_score >= whisper_th:
        sentiment_label = "FRUSTRATED"
    elif frustration_score >= 0.35:
        sentiment_label = "CONCERNED"
    else:
        sentiment_label = "CALM"

    auto_supervisor_alert = bool(frustration_score >= whisper_th or sla_risk_score >= 0.82)
    recommend_warm_handoff = bool(
        frustration_score >= escalate_th or explicit_human or policy_cap_exceeded
    )

    return {
        "frustration_score": frustration_score,
        "sla_risk_score": sla_risk_score,
        "sentiment_label": sentiment_label,
        "auto_supervisor_alert": auto_supervisor_alert,
        "recommend_warm_handoff": recommend_warm_handoff,
        "policy_cap_exceeded": policy_cap_exceeded,
        "escalation_triggers": triggers,
        "customer_turn_count": turn_count,
        "radar_eval_ms": round((time.perf_counter() - t0) * 1000.0, 4),
    }


def build_contextual_rich_card(
    tenant_id: str,
    context_slots: Dict[str, Any],
    allowed_cards: List[str],
) -> Dict[str, Any] | None:
    """Build a schema-valid interactive rich card for missing customer workflow slots."""
    kb = POLICY_CATALOG.get(tenant_id, POLICY_CATALOG["nordpeak-gear"])
    orders_map = kb["orders"]
    order_id = context_slots.get("order_id")

    if not order_id and "ORDER_PICKER" in allowed_cards:
        opts = []
        for oid, meta in orders_map.items():
            opts.append({
                "value": oid,
                "label": f"{oid} · {meta['item_name']}",
                "sublabel": f"${meta['order_total_usd']:.2f} · {meta['delivered_date']}",
            })
        return {
            "card_type": "ORDER_PICKER",
            "title": "Select the Order or Transaction",
            "prompt": "Tap an item below so you do not have to type order numbers:",
            "options": opts,
        }

    if order_id and not context_slots.get("preferred_resolution") and "REFUND_ESTIMATOR" in allowed_cards:
        amount = float(context_slots.get("order_total_usd") or 349.00)
        return {
            "card_type": "REFUND_ESTIMATOR",
            "title": f"Resolution Options for {order_id}",
            "order_id": order_id,
            "amount_usd": amount,
            "prompt": f"Verified item value: ${amount:.2f}. Choose your preferred outcome:",
            "options": [
                {
                    "value": "instant_express_replacement",
                    "label": "Express Replacement + $25 VIP Credit",
                    "sublabel": "Ships today before courier pickup ($0.00 charge)",
                },
                {
                    "value": "refund_original_payment",
                    "label": f"Full Refund (${amount:.2f}) to Original Card",
                    "sublabel": "Posts within 2 to 3 business days after scan",
                },
                {
                    "value": "speak_with_specialist",
                    "label": "Warm Handoff to Specialist (Zero Repeat)",
                    "sublabel": "Transfers verified order + photos immediately",
                },
            ],
        }

    if (
        order_id
        and context_slots.get("preferred_resolution")
        and not context_slots.get("selected_time_slot")
        and "TIME_SLOT_SELECTOR" in allowed_cards
    ):
        return {
            "card_type": "TIME_SLOT_SELECTOR",
            "title": "Choose Doorstep Exchange Window",
            "prompt": "Select your preferred courier pickup / delivery slot:",
            "options": [
                {"value": "Today 5:00 PM - 7:00 PM", "label": "Today · 5:00 PM - 7:00 PM", "sublabel": "Priority evening courier"},
                {"value": "Tomorrow 9:00 AM - 11:00 AM", "label": "Tomorrow · 9:00 AM - 11:00 AM", "sublabel": "Morning doorstep swap"},
                {"value": "Tomorrow 1:00 PM - 3:00 PM", "label": "Tomorrow · 1:00 PM - 3:00 PM", "sublabel": "Afternoon doorstep swap"},
                {"value": "Saturday 10:00 AM - 12:00 PM", "label": "Saturday · 10:00 AM - 12:00 PM", "sublabel": "Weekend window"},
            ],
        }

    return None


class CopilotWhisperEngine:
    """Invokes Amazon Bedrock (`us.amazon.nova-lite-v1:0`) for policy-grounded Agent Whisper & Bot Assist."""

    def __init__(
        self,
        model_id: str = DEFAULT_BEDROCK_MODEL,
        region_name: str = DEFAULT_AWS_REGION,
    ) -> None:
        self.model_id = model_id
        self.region_name = region_name
        self._client: Any = None

    def _get_bedrock_client(self) -> Any:
        if self._client is None:
            import shutil
            import subprocess
            import boto3
            from botocore.config import Config

            cfg = Config(
                region_name=self.region_name,
                connect_timeout=8,
                read_timeout=22,
                retries={"max_attempts": 2, "mode": "standard"},
            )
            if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("AWS_ACCESS_KEY_ID"):
                self._client = boto3.client("bedrock-runtime", config=cfg)
            else:
                profile = os.environ.get("AWS_PROFILE", "portfolio")
                aws_bin = shutil.which("aws")
                if aws_bin:
                    proc = subprocess.run(
                        [aws_bin, "configure", "export-credentials", "--profile", profile, "--format", "process"],
                        capture_output=True,
                        text=True,
                        timeout=6.0,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        creds = json.loads(proc.stdout)
                        self._client = boto3.client(
                            "bedrock-runtime",
                            config=cfg,
                            aws_access_key_id=creds["AccessKeyId"],
                            aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds.get("SessionToken"),
                        )
                if self._client is None:
                    self._client = boto3.client("bedrock-runtime", config=cfg)
        return self._client

    def _deterministic_policy_pack(
        self,
        tenant_id: str,
        context_slots: Dict[str, Any],
        radar: Dict[str, Any],
    ) -> Dict[str, str]:
        kb = POLICY_CATALOG.get(tenant_id, POLICY_CATALOG["nordpeak-gear"])
        policy_id = kb["policy_id"]
        customer_name = str(context_slots.get("customer_name") or "Customer")
        order_id = str(context_slots.get("order_id") or "ORD-88412")
        item_name = str(context_slots.get("item_name") or "Alpine Pro Dual-Boiler Espresso Machine")
        amount = float(context_slots.get("order_total_usd") or 349.00)
        pref = str(context_slots.get("preferred_resolution") or "instant_express_replacement").replace("_", " ")
        slot = str(context_slots.get("selected_time_slot") or "Today 5:00 PM - 7:00 PM")

        bot_reply = (
            f"I have your verified details for {order_id} ({item_name}, ${amount:.2f}). "
            f"Under policy {policy_id}, I prepared your {pref} options below so you never need to repeat your order number."
        )
        whisper = (
            f"[{policy_id}] Verified {customer_name} on {order_id} (${amount:.2f}). "
            f"Frustration={radar['frustration_score']:.2f} ({radar['sentiment_label']}). "
            f"Approve express replacement + $25 courtesy credit without asking customer to repeat order ID or issue."
        )
        agent_reply = (
            f"Hi {customer_name}, I already have your verified order {order_id} for the {item_name} (${amount:.2f}) "
            f"and your {pref} request open on my screen. Under {policy_id}, I have approved an immediate replacement "
            f"for {slot} plus a $25.00 courtesy credit with zero upfront return wait."
        )
        supervisor_alert = (
            f"SLA & Sentiment Radar alert on {order_id}: frustration reached {radar['frustration_score']:.2f} "
            f"({', '.join(radar['escalation_triggers']) or 'policy exception'}). Coach agent to apply {policy_id} immediately."
        )
        return {
            "policy_id": policy_id,
            "bot_public_reply": _sanitize_prose(bot_reply),
            "agent_whisper_coaching": _sanitize_prose(whisper),
            "suggested_agent_reply": _sanitize_prose(agent_reply),
            "supervisor_alert_reason": _sanitize_prose(supervisor_alert),
        }

    def generate_whisper_and_reply(
        self,
        tenant_config: Dict[str, Any],
        public_messages: List[Dict[str, Any]],
        context_slots: Dict[str, Any],
        radar: Dict[str, Any],
        use_bedrock: bool = True,
    ) -> Dict[str, Any]:
        """Generate policy-grounded self-service reply + private Agent Whisper via Amazon Bedrock."""
        tenant_id = str(tenant_config.get("tenant_id") or "nordpeak-gear")
        pii_policy = tenant_config.get("pii_policy")
        kb = POLICY_CATALOG.get(tenant_id, POLICY_CATALOG["nordpeak-gear"])
        fallback = self._deterministic_policy_pack(tenant_id, context_slots, radar)
        rich_card = build_contextual_rich_card(
            tenant_id=tenant_id,
            context_slots=context_slots,
            allowed_cards=list(tenant_config.get("allowed_rich_cards") or []),
        )

        if not use_bedrock:
            return {
                **fallback,
                "recommended_rich_card": rich_card,
                "llm_engine": "deterministic-policy-engine",
                "model_id": "policy-local",
                "bedrock_invoked": False,
                "bedrock_latency_ms": 0.0,
                "bedrock_tokens": 0,
            }

        # Scrub every transcript line again defensively before constructing LLM prompt
        safe_lines: List[str] = []
        for msg in public_messages[-6:]:
            role = str(msg.get("sender_role") or "CUSTOMER")
            clean_txt = scrub_transcript_pii(str(msg.get("content") or ""), pii_policy=pii_policy)["scrubbed_text"]
            safe_lines.append(f"{role}: {clean_txt}")

        system_prompt = (
            "You are ConnectBlitz Copilot for Amazon Connect contact centers. "
            "Respond ONLY with valid JSON matching keys: "
            "bot_public_reply, agent_whisper_coaching, suggested_agent_reply, supervisor_alert_reason. "
            "Rules: (1) Never ask the customer to repeat verified slots (order_id, item_name, issue). "
            "(2) Cite the exact policy_id in agent_whisper_coaching. "
            "(3) Keep each field concise (1 to 2 sentences) and never use em-dashes."
        )
        user_prompt = json.dumps(
            {
                "tenant_brand": tenant_config.get("brand_name"),
                "policy_id": kb["policy_id"],
                "policy_rule": kb["rule_summary"],
                "verified_context_slots": context_slots,
                "escalation_radar": {
                    "frustration_score": radar["frustration_score"],
                    "sentiment_label": radar["sentiment_label"],
                    "triggers": radar["escalation_triggers"],
                },
                "scrubbed_recent_transcript": safe_lines,
            },
            ensure_ascii=True,
        )

        t0 = time.perf_counter()
        try:
            client = self._get_bedrock_client()
            resp = client.converse(
                modelId=self.model_id,
                system=[{"text": system_prompt}],
                messages=[{"role": "user", "content": [{"text": user_prompt}]}],
                inferenceConfig={"maxTokens": 360, "temperature": 0.15},
            )
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            usage = resp.get("usage") or {}
            total_tokens = int(usage.get("totalTokens") or (int(usage.get("inputTokens") or 0) + int(usage.get("outputTokens") or 0)))
            content_blocks = ((resp.get("output") or {}).get("message") or {}).get("content") or []
            raw_text = "".join(str(b.get("text") or "") for b in content_blocks).strip()

            cleaned = raw_text
            if "```" in cleaned:
                match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
                if match:
                    cleaned = match.group(0)
            elif not cleaned.startswith("{"):
                match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
                if match:
                    cleaned = match.group(0)

            parsed = json.loads(cleaned)
            return {
                "policy_id": kb["policy_id"],
                "bot_public_reply": _sanitize_prose(parsed.get("bot_public_reply") or fallback["bot_public_reply"]),
                "agent_whisper_coaching": _sanitize_prose(
                    parsed.get("agent_whisper_coaching") or fallback["agent_whisper_coaching"]
                ),
                "suggested_agent_reply": _sanitize_prose(
                    parsed.get("suggested_agent_reply") or fallback["suggested_agent_reply"]
                ),
                "supervisor_alert_reason": _sanitize_prose(
                    parsed.get("supervisor_alert_reason") or fallback["supervisor_alert_reason"]
                ),
                "recommended_rich_card": rich_card,
                "llm_engine": "amazon-bedrock",
                "model_id": self.model_id,
                "bedrock_invoked": True,
                "bedrock_latency_ms": latency_ms,
                "bedrock_tokens": total_tokens,
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                **fallback,
                "recommended_rich_card": rich_card,
                "llm_engine": "policy-fallback",
                "model_id": self.model_id,
                "bedrock_invoked": False,
                "bedrock_error": str(exc)[:180],
                "bedrock_latency_ms": latency_ms,
                "bedrock_tokens": 0,
            }
