"""Comprehensive Unit Test Suite for ConnectBlitz (12 tests)."""
from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from connect_blitz.copilot_whisper import evaluate_escalation_radar
from connect_blitz.pii_transcript import (
    ContactAuditLedger,
    luhn_checksum_valid,
    scrub_transcript_pii,
)
from connect_blitz.server import lambda_handler
from connect_blitz.session_engine import ConnectBlitzSessionEngine
from connect_blitz.widget_config import (
    TENANT_PRESETS,
    compute_wcag_contrast_ratio,
    validate_widget_config,
)


class ConnectBlitzTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.engine = ConnectBlitzSessionEngine(data_dir=self.tmp_dir.name, seed_demo=True)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_widget_config_valid_and_four_surface_manifests(self) -> None:
        res = validate_widget_config(TENANT_PRESETS["nordpeak-gear"])
        self.assertTrue(res["valid"], msg=res["errors"])
        self.assertGreaterEqual(res["contrast_audit"]["body_text_ratio"], 15.0)
        self.assertGreaterEqual(res["contrast_audit"]["primary_button_ratio"], 4.5)

        manifests = res["surface_manifests"]
        self.assertEqual(
            set(manifests.keys()),
            {"customer_web_ecw", "customer_mobile_compact", "agent_desk", "supervisor_console"},
        )
        self.assertFalse(manifests["customer_web_ecw"]["whisper_channel_visible"])
        self.assertFalse(manifests["customer_mobile_compact"]["whisper_channel_visible"])
        self.assertEqual(manifests["customer_web_ecw"]["max_visible_card_options"], 5)
        self.assertEqual(manifests["customer_mobile_compact"]["max_visible_card_options"], 3)
        self.assertTrue(manifests["agent_desk"]["whisper_channel_visible"])
        self.assertTrue(manifests["supervisor_console"]["supervisor_controls_visible"])

    def test_02_wcag_aa_contrast_and_pii_schema_rejection(self) -> None:
        bad_cfg = copy.deepcopy(TENANT_PRESETS["nordpeak-gear"])
        bad_cfg["theme"]["text_hex"] = "#A3A3A3"
        bad_cfg["theme"]["background_hex"] = "#FFFFFF"
        bad_cfg["pii_policy"]["scrub_pan_luhn"] = False
        bad_cfg["allowed_rich_cards"] = ["ORDER_PICKER", "UNSAFE_RAW_HTML"]
        bad_cfg["sla_thresholds"]["frustration_whisper_threshold"] = 0.80
        bad_cfg["sla_thresholds"]["auto_escalate_threshold"] = 0.55

        ratio = compute_wcag_contrast_ratio("#A3A3A3", "#FFFFFF")
        self.assertLess(ratio, 4.5)

        res = validate_widget_config(bad_cfg)
        self.assertFalse(res["valid"])
        joined_errors = " | ".join(res["errors"])
        self.assertIn("WCAG 2.1 AA violation", joined_errors)
        self.assertIn("scrub_pan_luhn", joined_errors)
        self.assertIn("UNSAFE_RAW_HTML", joined_errors)
        self.assertIn("auto_escalate_threshold", joined_errors)

    def test_03_luhn_pan_scrubber_vs_non_luhn_tracking_numbers(self) -> None:
        self.assertTrue(luhn_checksum_valid("4532015112830366"))
        self.assertTrue(luhn_checksum_valid("4111111111111111"))
        self.assertFalse(luhn_checksum_valid("1234567890123451"))

        sample = (
            "Please refund card 4532-0151-1283-0366 for order ORD-88412; "
            "carrier tracking is 1234-5678-9012-3451."
        )
        out = scrub_transcript_pii(sample, {"scrub_pan_luhn": True, "scrub_ssn": True, "scrub_otp": True, "mask_style": "LAST4"})
        self.assertTrue(out["pii_detected"])
        self.assertEqual(out["redacted_count"], 1)
        self.assertIn("[REDACTED_PAN_LAST4:0366]", out["scrubbed_text"])
        self.assertNotIn("4532-0151-1283", out["scrubbed_text"])
        self.assertIn("ORD-88412", out["scrubbed_text"])
        self.assertIn("1234-5678-9012-3451", out["scrubbed_text"])

    def test_04_ssn_and_auth_otp_scrubbing(self) -> None:
        sample = "My SSN is 123-45-6789, verification code: 849201, and CVV 739. Invalid prefix 000-12-3456 stays."
        out = scrub_transcript_pii(sample)
        self.assertEqual(out["redacted_count"], 3)
        self.assertNotIn("123-45-6789", out["scrubbed_text"])
        self.assertNotIn("849201", out["scrubbed_text"])
        self.assertNotIn("739", out["scrubbed_text"])
        self.assertIn("[REDACTED_SSN]", out["scrubbed_text"])
        self.assertIn("[REDACTED_OTP]", out["scrubbed_text"])
        self.assertIn("000-12-3456", out["scrubbed_text"])

    def test_05_tamper_evident_sqlite_ledger_detects_single_row_mutation(self) -> None:
        db_file = Path(self.tmp_dir.name) / "tamper_test.db"
        ledger = ContactAuditLedger(db_file)
        events = []
        for idx in range(6):
            ev = ledger.append_event(
                contact_id="cnt-audit-01",
                event_type="MESSAGE_CUSTOMER_PUBLIC",
                actor_role="CUSTOMER",
                visibility="PUBLIC",
                summary_text=f"Turn {idx} card 4111 1111 1111 1111",
            )
            self.assertNotIn("4111 1111", ev["scrubbed_summary"])
            events.append(ev)

        clean_check = ledger.verify_chain_integrity()
        self.assertTrue(clean_check["valid"])
        self.assertEqual(clean_check["checked_rows"], 6)

        # Directly mutate row #3 in SQLite to simulate insider log tampering
        conn = sqlite3.connect(str(db_file))
        conn.execute(
            "UPDATE contact_audit_ledger SET scrubbed_summary = 'Forged clean summary' WHERE event_id = ?",
            (events[2]["event_id"],),
        )
        conn.commit()
        conn.close()

        tampered_check = ledger.verify_chain_integrity()
        self.assertFalse(tampered_check["valid"])
        self.assertEqual(tampered_check["tampered_event_id"], events[2]["event_id"])

    def test_06_idempotent_client_msg_id_deduplication(self) -> None:
        first = self.engine.post_message(
            contact_id="cnt-blitz-demo-01",
            sender_role="CUSTOMER",
            content="I prefer the instant express replacement option.",
            client_msg_id="idem-mobile-retry-001",
            selected_card_value="instant_express_replacement",
            use_bedrock=False,
        )
        self.assertFalse(first["deduplicated"])
        count_after_first = first["surfaces"]["customer_web_ecw"]["visible_message_count"]

        for _ in range(3):
            dup = self.engine.post_message(
                contact_id="cnt-blitz-demo-01",
                sender_role="CUSTOMER",
                content="I prefer the instant express replacement option.",
                client_msg_id="idem-mobile-retry-001",
                selected_card_value="instant_express_replacement",
                use_bedrock=False,
            )
            self.assertTrue(dup["deduplicated"])
            self.assertEqual(dup["surfaces"]["customer_web_ecw"]["visible_message_count"], count_after_first)

    def test_07_zero_repeat_warm_handoff_context_carryover(self) -> None:
        self.engine.post_message(
            contact_id="cnt-blitz-demo-01",
            sender_role="CUSTOMER",
            content="Select express replacement for Today 5:00 PM - 7:00 PM.",
            client_msg_id="slot-fill-01",
            selected_card_value="Today 5:00 PM - 7:00 PM",
            use_bedrock=False,
        )
        bundle = self.engine.trigger_warm_handoff(
            contact_id="cnt-blitz-demo-01",
            reason="customer_requested_specialist",
            use_bedrock=False,
        )
        self.assertEqual(bundle["state"], "AGENT_ACTIVE")
        states_seen = [s["state"] for s in bundle["state_history"]]
        self.assertIn("QUEUED_WITH_CONTEXT", states_seen)
        self.assertIn("AGENT_ACTIVE", states_seen)

        packet = bundle["surfaces"]["agent_desk"]["warm_handoff_packet"]
        self.assertIsNotNone(packet)
        self.assertTrue(packet["zero_repeat_guaranteed"])
        self.assertEqual(packet["customer_repeat_prompts_required"], 0)
        self.assertEqual(packet["carried_context_slots"]["order_id"], "ORD-88412")
        self.assertEqual(packet["carried_context_slots"]["selected_time_slot"], "Today 5:00 PM - 7:00 PM")

    def test_08_strict_whisper_isolation_never_leaks_to_customer_surfaces(self) -> None:
        secret_whisper = "INTERNAL_COACHING_CANARY_9981: Offer $25 VIP credit under POL-NP-DAMAGED-24H."
        res = self.engine.execute_supervisor_action(
            contact_id="cnt-blitz-demo-01",
            action_type="WHISPER",
            message_text=secret_whisper,
        )
        self.assertEqual(res["state"], "SUPERVISOR_WHISPER")

        web_json = json.dumps(res["surfaces"]["customer_web_ecw"])
        mob_json = json.dumps(res["surfaces"]["customer_mobile_compact"])
        agent_json = json.dumps(res["surfaces"]["agent_desk"])
        sup_json = json.dumps(res["surfaces"]["supervisor_console"])

        self.assertNotIn("INTERNAL_COACHING_CANARY_9981", web_json)
        self.assertNotIn("INTERNAL_COACHING_CANARY_9981", mob_json)
        self.assertNotIn('"WHISPER"', web_json)
        self.assertNotIn('"WHISPER"', mob_json)
        self.assertIn("INTERNAL_COACHING_CANARY_9981", agent_json)
        self.assertIn("INTERNAL_COACHING_CANARY_9981", sup_json)

    def test_09_supervisor_barge_in_and_resolve_transitions(self) -> None:
        barge = self.engine.execute_supervisor_action(
            contact_id="cnt-blitz-demo-01",
            action_type="BARGE_IN",
            message_text="Floor Lead Elena stepping in: your priority courier unit is approved now.",
        )
        self.assertEqual(barge["state"], "BARGE_IN")
        self.assertIn("Floor Lead Elena stepping in", json.dumps(barge["surfaces"]["customer_web_ecw"]))
        self.assertIn("Floor Lead Elena stepping in", json.dumps(barge["surfaces"]["customer_mobile_compact"]))

        resolved = self.engine.execute_supervisor_action(
            contact_id="cnt-blitz-demo-01",
            action_type="RESOLVE",
        )
        self.assertEqual(resolved["state"], "RESOLVED")
        last_web_msg = resolved["surfaces"]["customer_web_ecw"]["messages"][-1]
        self.assertEqual(last_web_msg["rich_card"]["card_type"], "REPLACEMENT_CONFIRM")

    def test_10_sentiment_and_sla_radar_thresholds(self) -> None:
        sla = TENANT_PRESETS["nordpeak-gear"]["sla_thresholds"]
        calm = evaluate_escalation_radar(
            [{"sender_role": "CUSTOMER", "content": "Where can I check standard coffee filter sizes?"}],
            {"order_total_usd": 24.0, "issue_category": "general_question"},
            sla,
            elapsed_wait_sec=4.0,
        )
        self.assertEqual(calm["sentiment_label"], "CALM")
        self.assertFalse(calm["auto_supervisor_alert"])

        angry = evaluate_escalation_radar(
            [{"sender_role": "CUSTOMER", "content": "This is unacceptable!! My $349 espresso boiler arrived shattered and leaking, get me a supervisor!"}],
            {"order_total_usd": 349.0, "issue_category": "damaged_item"},
            sla,
            elapsed_wait_sec=22.0,
        )
        self.assertEqual(angry["sentiment_label"], "CRITICAL_ESCALATION")
        self.assertTrue(angry["auto_supervisor_alert"])
        self.assertTrue(angry["recommend_warm_handoff"])

    def test_11_live_hot_reload_widget_config_updates_surfaces(self) -> None:
        res = self.engine.validate_and_apply_config(
            raw_config=TENANT_PRESETS["harbor-bank"],
            apply_live=True,
            contact_id="cnt-blitz-demo-01",
        )
        self.assertTrue(res["valid"])
        bundle = res["live_bundle"]
        self.assertEqual(bundle["surfaces"]["customer_web_ecw"]["manifest"]["primary_hex"], "#1E3A8A")
        self.assertEqual(bundle["surfaces"]["customer_web_ecw"]["manifest"]["pii_mask_style"], "FULL")

        turn = self.engine.post_message(
            contact_id="cnt-blitz-demo-01",
            sender_role="CUSTOMER",
            content="Card number 4532-0151-1283-0366 shows unauthorized charge TXN-44109.",
            client_msg_id="bank-pan-test-01",
            use_bedrock=False,
        )
        last_customer_msgs = [
            m for m in turn["surfaces"]["customer_web_ecw"]["messages"] if m["sender_role"] == "CUSTOMER"
        ]
        self.assertIn("[REDACTED_PAN]", last_customer_msgs[-1]["content"])
        self.assertNotIn("0366", last_customer_msgs[-1]["content"])

    def test_12_lambda_handler_routes_and_cors(self) -> None:
        opt = lambda_handler({"requestContext": {"http": {"method": "OPTIONS"}}, "rawPath": "/api/health"})
        self.assertEqual(opt["statusCode"], 204)

        health = lambda_handler({"requestContext": {"http": {"method": "GET"}}, "rawPath": "/api/health"})
        self.assertEqual(health["statusCode"], 200)
        h_body = json.loads(health["body"])
        self.assertEqual(h_body["service"], "connect-blitz-cx")
        self.assertTrue(h_body["audit_chain_valid"])

        msg_resp = lambda_handler({
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/api/contact/message",
            "body": json.dumps({
                "contact_id": "cnt-blitz-demo-01",
                "sender_role": "CUSTOMER",
                "content": "Testing order ORD-88412 with OTP: 551902",
                "client_msg_id": "lambda-test-msg-01",
                "use_bedrock": False,
            }),
        })
        self.assertEqual(msg_resp["statusCode"], 200)
        m_body = json.loads(msg_resp["body"])
        self.assertIn("surfaces", m_body)
        self.assertNotIn("551902", json.dumps(m_body["surfaces"]["customer_web_ecw"]))


if __name__ == "__main__":
    unittest.main()
