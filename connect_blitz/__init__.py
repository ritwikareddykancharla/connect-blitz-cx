"""ConnectBlitz: Config-driven omnichannel contact-center experience engine."""
from __future__ import annotations

__version__ = "1.0.0"

from .copilot_whisper import CopilotWhisperEngine, evaluate_escalation_radar
from .pii_transcript import ContactAuditLedger, luhn_checksum_valid, scrub_transcript_pii
from .session_engine import ConnectBlitzSessionEngine
from .widget_config import (
    ALLOWED_RICH_CARD_SCHEMAS,
    TENANT_PRESETS,
    compute_wcag_contrast_ratio,
    render_surface_manifests,
    validate_widget_config,
)

__all__ = [
    "__version__",
    "ALLOWED_RICH_CARD_SCHEMAS",
    "TENANT_PRESETS",
    "compute_wcag_contrast_ratio",
    "render_surface_manifests",
    "validate_widget_config",
    "luhn_checksum_valid",
    "scrub_transcript_pii",
    "ContactAuditLedger",
    "evaluate_escalation_radar",
    "CopilotWhisperEngine",
    "ConnectBlitzSessionEngine",
]
