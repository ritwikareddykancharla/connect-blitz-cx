"""Unified JSON Widget Schema & Multi-Surface Renderer Contract for ConnectBlitz.

Validates a single declarative tenant widget configuration and compiles four
persona-adapted surface manifests:
  1. customer_web_ecw       (Hosted Embedded Communications Widget on Web)
  2. customer_mobile_compact (Compact Mobile Viewport with bottom-sheet cards)
  3. agent_desk             (Contact-Center Agent Workspace with Whisper rail)
  4. supervisor_console     (Supervisor Live SLA Radar, Whisper & Barge-In)
"""
from __future__ import annotations

import copy
import re
import time
from typing import Any, Dict, List, Tuple

HEX_COLOR_RE = re.compile(r"^#([0-9A-Fa-f]{6})$")

SUPPORTED_VERTICALS = {
    "ecommerce_returns",
    "retail_banking",
    "airline_rebooking",
}

ALLOWED_RICH_CARD_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "ORDER_PICKER": {
        "card_type": "ORDER_PICKER",
        "title": "Order & Item Picker",
        "required_fields": ["prompt", "options"],
        "supports_customer_selection": True,
        "slot_target": "order_id",
    },
    "REFUND_ESTIMATOR": {
        "card_type": "REFUND_ESTIMATOR",
        "title": "Instant Refund & Replacement Estimator",
        "required_fields": ["order_id", "amount_usd", "options"],
        "supports_customer_selection": True,
        "slot_target": "preferred_resolution",
    },
    "TIME_SLOT_SELECTOR": {
        "card_type": "TIME_SLOT_SELECTOR",
        "title": "Courier Pickup & Delivery Time-Slot Selector",
        "required_fields": ["prompt", "options"],
        "supports_customer_selection": True,
        "slot_target": "selected_time_slot",
    },
    "IDENTITY_VERIFIER": {
        "card_type": "IDENTITY_VERIFIER",
        "title": "Step-Up Customer Verification Badge",
        "required_fields": ["verification_method", "status"],
        "supports_customer_selection": True,
        "slot_target": "identity_verified",
    },
    "REPLACEMENT_CONFIRM": {
        "card_type": "REPLACEMENT_CONFIRM",
        "title": "Zero-Cost Express Replacement Confirmation",
        "required_fields": ["order_id", "replacement_sku", "eta_window"],
        "supports_customer_selection": False,
        "slot_target": "resolution_confirmed",
    },
}

TENANT_PRESETS: Dict[str, Dict[str, Any]] = {
    "nordpeak-gear": {
        "tenant_id": "nordpeak-gear",
        "brand_name": "NordPeak Home & Espresso",
        "vertical": "ecommerce_returns",
        "welcome_greeting": "Hi Maya! I already pulled up your verified Prime VIP account. How can I help with your recent NordPeak order today?",
        "theme": {
            "primary_hex": "#0369A1",
            "background_hex": "#FFFFFF",
            "text_hex": "#141413",
            "button_text_hex": "#FFFFFF",
            "agent_accent_hex": "#0F766E",
            "border_radius_px": 6,
            "compact_density": False,
        },
        "pii_policy": {
            "scrub_pan_luhn": True,
            "scrub_ssn": True,
            "scrub_otp": True,
            "mask_style": "LAST4",
            "block_raw_unscrubbed": True,
        },
        "allowed_rich_cards": [
            "ORDER_PICKER",
            "REFUND_ESTIMATOR",
            "TIME_SLOT_SELECTOR",
            "REPLACEMENT_CONFIRM",
        ],
        "sla_thresholds": {
            "first_response_sec": 25,
            "frustration_whisper_threshold": 0.58,
            "auto_escalate_threshold": 0.72,
            "max_self_service_turns": 5,
            "max_auto_refund_usd": 250.0,
        },
        "features": {
            "enable_ai_self_service": True,
            "enable_zero_repeat_handoff": True,
            "enable_agent_whisper_copilot": True,
            "enable_supervisor_barge_in": True,
        },
    },
    "harbor-bank": {
        "tenant_id": "harbor-bank",
        "brand_name": "Harborstone Retail Banking",
        "vertical": "retail_banking",
        "welcome_greeting": "Welcome to Harborstone Card Protection. Never share full card numbers or passcodes in chat; our real-time scrubber redacts them automatically.",
        "theme": {
            "primary_hex": "#1E3A8A",
            "background_hex": "#F8FAFC",
            "text_hex": "#0F172A",
            "button_text_hex": "#FFFFFF",
            "agent_accent_hex": "#0369A1",
            "border_radius_px": 4,
            "compact_density": True,
        },
        "pii_policy": {
            "scrub_pan_luhn": True,
            "scrub_ssn": True,
            "scrub_otp": True,
            "mask_style": "FULL",
            "block_raw_unscrubbed": True,
        },
        "allowed_rich_cards": [
            "IDENTITY_VERIFIER",
            "ORDER_PICKER",
            "REFUND_ESTIMATOR",
        ],
        "sla_thresholds": {
            "first_response_sec": 15,
            "frustration_whisper_threshold": 0.50,
            "auto_escalate_threshold": 0.65,
            "max_self_service_turns": 4,
            "max_auto_refund_usd": 150.0,
        },
        "features": {
            "enable_ai_self_service": True,
            "enable_zero_repeat_handoff": True,
            "enable_agent_whisper_copilot": True,
            "enable_supervisor_barge_in": True,
        },
    },
    "skyline-air": {
        "tenant_id": "skyline-air",
        "brand_name": "Skyline Airways Priority Desk",
        "vertical": "airline_rebooking",
        "welcome_greeting": "Skyline Priority Desk connected. Select an alternate departure slot or request instant agent rebooking.",
        "theme": {
            "primary_hex": "#0F766E",
            "background_hex": "#FFFFFF",
            "text_hex": "#18181B",
            "button_text_hex": "#FFFFFF",
            "agent_accent_hex": "#1D4ED8",
            "border_radius_px": 8,
            "compact_density": False,
        },
        "pii_policy": {
            "scrub_pan_luhn": True,
            "scrub_ssn": True,
            "scrub_otp": True,
            "mask_style": "LAST4",
            "block_raw_unscrubbed": True,
        },
        "allowed_rich_cards": [
            "ORDER_PICKER",
            "TIME_SLOT_SELECTOR",
            "REFUND_ESTIMATOR",
        ],
        "sla_thresholds": {
            "first_response_sec": 20,
            "frustration_whisper_threshold": 0.55,
            "auto_escalate_threshold": 0.70,
            "max_self_service_turns": 4,
            "max_auto_refund_usd": 400.0,
        },
        "features": {
            "enable_ai_self_service": True,
            "enable_zero_repeat_handoff": True,
            "enable_agent_whisper_copilot": True,
            "enable_supervisor_barge_in": True,
        },
    },
}


def _hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    match = HEX_COLOR_RE.match(str(hex_str or "").strip())
    if not match:
        raise ValueError(f"Invalid 6-digit hex color: {hex_str!r}")
    raw = match.group(1)
    return int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)


def _relative_luminance(rgb: Tuple[int, int, int]) -> float:
    channels: List[float] = []
    for val in rgb:
        s = val / 255.0
        channels.append(s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def compute_wcag_contrast_ratio(foreground_hex: str, background_hex: str) -> float:
    """Compute exact WCAG 2.1 contrast ratio between two #RRGGBB colors (1.0 to 21.0)."""
    lum_fg = _relative_luminance(_hex_to_rgb(foreground_hex))
    lum_bg = _relative_luminance(_hex_to_rgb(background_hex))
    lighter = max(lum_fg, lum_bg)
    darker = min(lum_fg, lum_bg)
    return round((lighter + 0.05) / (darker + 0.05), 2)


def render_surface_manifests(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Compile one validated tenant schema into four persona-scoped surface contracts."""
    theme = config["theme"]
    cards = list(config["allowed_rich_cards"])
    features = config.get("features", {})
    sla = config["sla_thresholds"]
    pii = config["pii_policy"]

    common_tokens = {
        "tenant_id": config["tenant_id"],
        "brand_name": config["brand_name"],
        "vertical": config["vertical"],
        "primary_hex": theme["primary_hex"],
        "background_hex": theme["background_hex"],
        "text_hex": theme["text_hex"],
        "button_text_hex": theme.get("button_text_hex", "#FFFFFF"),
        "border_radius_px": theme["border_radius_px"],
        "pii_mask_style": pii["mask_style"],
    }

    return {
        "customer_web_ecw": {
            **common_tokens,
            "surface_id": "customer_web_ecw",
            "persona": "END_CUSTOMER",
            "viewport_mode": "hosted_ecw_desktop",
            "allowed_visibilities": ["PUBLIC"],
            "whisper_channel_visible": False,
            "supervisor_controls_visible": False,
            "card_layout": "inline_interactive_grid",
            "max_visible_card_options": 5,
            "enabled_rich_cards": cards,
            "composer_capabilities": [
                "send_text",
                "select_rich_card",
                "request_human_handoff",
            ],
        },
        "customer_mobile_compact": {
            **common_tokens,
            "surface_id": "customer_mobile_compact",
            "persona": "END_CUSTOMER",
            "viewport_mode": "mobile_compact_sheet",
            "allowed_visibilities": ["PUBLIC"],
            "whisper_channel_visible": False,
            "supervisor_controls_visible": False,
            "card_layout": "bottom_sheet_condensed",
            "max_visible_card_options": 3,
            "enabled_rich_cards": cards,
            "composer_capabilities": [
                "send_text",
                "select_rich_card_sheet",
                "request_human_handoff",
            ],
        },
        "agent_desk": {
            **common_tokens,
            "surface_id": "agent_desk",
            "persona": "CONTACT_AGENT",
            "viewport_mode": "agent_workspace_split",
            "agent_accent_hex": theme.get("agent_accent_hex", "#0F766E"),
            "allowed_visibilities": ["PUBLIC", "WHISPER"],
            "whisper_channel_visible": True,
            "supervisor_controls_visible": False,
            "zero_repeat_context_ribbon": bool(features.get("enable_zero_repeat_handoff", True)),
            "bedrock_whisper_copilot": bool(features.get("enable_agent_whisper_copilot", True)),
            "enabled_rich_cards": cards,
            "auto_refund_authority_usd": sla["max_auto_refund_usd"],
            "composer_capabilities": [
                "send_public_reply",
                "insert_bedrock_suggestion",
                "push_rich_card",
                "mark_resolved",
            ],
        },
        "supervisor_console": {
            **common_tokens,
            "surface_id": "supervisor_console",
            "persona": "SUPERVISOR",
            "viewport_mode": "live_oversight_matrix",
            "allowed_visibilities": ["PUBLIC", "WHISPER", "SUPERVISOR_ONLY"],
            "whisper_channel_visible": True,
            "supervisor_controls_visible": bool(features.get("enable_supervisor_barge_in", True)),
            "frustration_whisper_threshold": sla["frustration_whisper_threshold"],
            "auto_escalate_threshold": sla["auto_escalate_threshold"],
            "first_response_sla_sec": sla["first_response_sec"],
            "composer_capabilities": [
                "send_private_whisper_to_agent",
                "barge_in_public_takeover",
                "verify_audit_ledger",
                "force_resolve",
            ],
        },
    }


def validate_widget_config(raw_config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate declarative widget JSON config, WCAG AA contrast, PII rules, and SLA bounds."""
    t0 = time.perf_counter()
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(raw_config, dict):
        return {
            "valid": False,
            "errors": ["Configuration payload must be a JSON object."],
            "warnings": [],
            "contrast_audit": {},
            "surface_manifests": {},
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    cfg = copy.deepcopy(raw_config)
    tenant_id = str(cfg.get("tenant_id") or "").strip()
    brand_name = str(cfg.get("brand_name") or "").strip()
    vertical = str(cfg.get("vertical") or "").strip()

    if not tenant_id or not re.match(r"^[a-z0-9][a-z0-9_-]{2,40}$", tenant_id):
        errors.append("tenant_id must be 3-41 lowercase alphanumeric, hyphen, or underscore characters.")
    if len(brand_name) < 2:
        errors.append("brand_name must contain at least 2 characters.")
    if vertical not in SUPPORTED_VERTICALS:
        errors.append(f"vertical must be one of {sorted(SUPPORTED_VERTICALS)}.")

    theme = cfg.get("theme") if isinstance(cfg.get("theme"), dict) else {}
    primary_hex = str(theme.get("primary_hex") or "")
    bg_hex = str(theme.get("background_hex") or "")
    text_hex = str(theme.get("text_hex") or "")
    btn_text_hex = str(theme.get("button_text_hex") or "#FFFFFF")
    agent_hex = str(theme.get("agent_accent_hex") or "#0F766E")
    radius = theme.get("border_radius_px", 6)

    contrast_audit: Dict[str, Any] = {
        "body_text_ratio": 0.0,
        "primary_button_ratio": 0.0,
        "wcag_aa_body_pass": False,
        "wcag_aa_button_pass": False,
    }

    for field_name, color_val in (
        ("theme.primary_hex", primary_hex),
        ("theme.background_hex", bg_hex),
        ("theme.text_hex", text_hex),
        ("theme.button_text_hex", btn_text_hex),
        ("theme.agent_accent_hex", agent_hex),
    ):
        if not HEX_COLOR_RE.match(color_val):
            errors.append(f"{field_name} ({color_val!r}) must be a valid 6-digit #RRGGBB color.")

    if not isinstance(radius, int) or not (0 <= radius <= 28):
        errors.append("theme.border_radius_px must be an integer between 0 and 28.")

    if HEX_COLOR_RE.match(text_hex) and HEX_COLOR_RE.match(bg_hex):
        body_ratio = compute_wcag_contrast_ratio(text_hex, bg_hex)
        contrast_audit["body_text_ratio"] = body_ratio
        contrast_audit["wcag_aa_body_pass"] = body_ratio >= 4.5
        if body_ratio < 4.5:
            errors.append(
                f"WCAG 2.1 AA violation: theme.text_hex ({text_hex}) on theme.background_hex ({bg_hex}) "
                f"has contrast {body_ratio}:1 (minimum 4.5:1 required)."
            )

    if HEX_COLOR_RE.match(btn_text_hex) and HEX_COLOR_RE.match(primary_hex):
        btn_ratio = compute_wcag_contrast_ratio(btn_text_hex, primary_hex)
        contrast_audit["primary_button_ratio"] = btn_ratio
        contrast_audit["wcag_aa_button_pass"] = btn_ratio >= 4.5
        if btn_ratio < 4.5:
            errors.append(
                f"WCAG 2.1 AA violation: theme.button_text_hex ({btn_text_hex}) on theme.primary_hex ({primary_hex}) "
                f"has contrast {btn_ratio}:1 (minimum 4.5:1 required)."
            )

    pii = cfg.get("pii_policy") if isinstance(cfg.get("pii_policy"), dict) else {}
    if not bool(pii.get("scrub_pan_luhn", False)):
        errors.append("pii_policy.scrub_pan_luhn must be enabled (True) for PCI-safe contact storage.")
    if not bool(pii.get("scrub_ssn", False)):
        errors.append("pii_policy.scrub_ssn must be enabled (True) for customer transcript protection.")
    if not bool(pii.get("scrub_otp", False)):
        warnings.append("pii_policy.scrub_otp is disabled; authentication passcodes will not be masked.")
    mask_style = str(pii.get("mask_style") or "LAST4")
    if mask_style not in ("LAST4", "FULL"):
        errors.append("pii_policy.mask_style must be 'LAST4' or 'FULL'.")

    cards = cfg.get("allowed_rich_cards")
    if not isinstance(cards, list) or len(cards) == 0:
        errors.append("allowed_rich_cards must be a non-empty list of supported card schemas.")
    else:
        unknown = [c for c in cards if c not in ALLOWED_RICH_CARD_SCHEMAS]
        if unknown:
            errors.append(
                f"Unsupported rich card types {unknown}. Allowed: {sorted(ALLOWED_RICH_CARD_SCHEMAS)}."
            )

    sla = cfg.get("sla_thresholds") if isinstance(cfg.get("sla_thresholds"), dict) else {}
    first_resp = sla.get("first_response_sec")
    whisper_th = sla.get("frustration_whisper_threshold")
    esc_th = sla.get("auto_escalate_threshold")
    max_turns = sla.get("max_self_service_turns")
    max_refund = sla.get("max_auto_refund_usd")

    if not isinstance(first_resp, (int, float)) or not (5 <= first_resp <= 300):
        errors.append("sla_thresholds.first_response_sec must be between 5 and 300 seconds.")
    if not isinstance(whisper_th, (int, float)) or not (0.25 <= float(whisper_th) <= 0.95):
        errors.append("sla_thresholds.frustration_whisper_threshold must be between 0.25 and 0.95.")
    if not isinstance(esc_th, (int, float)) or not (0.35 <= float(esc_th) <= 0.99):
        errors.append("sla_thresholds.auto_escalate_threshold must be between 0.35 and 0.99.")
    if (
        isinstance(whisper_th, (int, float))
        and isinstance(esc_th, (int, float))
        and float(esc_th) < float(whisper_th)
    ):
        errors.append(
            "sla_thresholds.auto_escalate_threshold must be greater than or equal to frustration_whisper_threshold."
        )
    if not isinstance(max_turns, int) or not (1 <= max_turns <= 15):
        errors.append("sla_thresholds.max_self_service_turns must be an integer between 1 and 15.")
    if not isinstance(max_refund, (int, float)) or not (0.0 <= float(max_refund) <= 1000.0):
        errors.append("sla_thresholds.max_auto_refund_usd must be between 0.0 and 1000.0.")

    valid = len(errors) == 0
    normalized = cfg if valid else None
    manifests = render_surface_manifests(cfg) if valid else {}
    eval_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "contrast_audit": contrast_audit,
        "normalized_config": normalized,
        "surface_manifests": manifests,
        "eval_ms": eval_ms,
    }


def adapt_rich_card_for_surface(
    rich_card: Dict[str, Any] | None,
    surface_manifest: Dict[str, Any],
) -> Dict[str, Any] | None:
    """Project an interactive rich card onto Web ECW, Mobile Compact, Agent, or Supervisor."""
    if not rich_card or not isinstance(rich_card, dict):
        return None

    card_type = str(rich_card.get("card_type") or "")
    if card_type and card_type not in surface_manifest.get("enabled_rich_cards", [card_type]):
        return None

    projected = copy.deepcopy(rich_card)
    max_opts = int(surface_manifest.get("max_visible_card_options", 5))
    options = projected.get("options")
    if isinstance(options, list) and len(options) > max_opts:
        projected["overflow_option_count"] = len(options) - max_opts
        projected["options"] = options[:max_opts]
    else:
        projected["overflow_option_count"] = 0

    projected["render_layout"] = surface_manifest.get("card_layout", "inline_interactive_grid")
    projected["accent_hex"] = surface_manifest.get("primary_hex", "#0369A1")
    return projected
