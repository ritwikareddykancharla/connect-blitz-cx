"""HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for ConnectBlitz."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from .session_engine import ConnectBlitzSessionEngine
from .widget_config import TENANT_PRESETS

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCHMARK_FILE = ROOT_DIR / "benchmarks" / "latest_results.json"

ENGINE = ConnectBlitzSessionEngine()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _load_benchmarks() -> Dict[str, Any]:
    if BENCHMARK_FILE.is_file():
        try:
            return json.loads(BENCHMARK_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Shared API router for local HTTP dev server and AWS Lambda Function URL behind CloudFront."""
    try:
        if method == "GET" and path == "/api/health":
            chain = ENGINE.ledger.verify_chain_integrity()
            return 200, {
                "status": "ok",
                "service": "connect-blitz-cx",
                "delivery": os.environ.get(
                    "CONNECTBLITZ_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"
                ),
                "aws_region": os.environ.get("AWS_REGION", "us-west-2"),
                "bedrock_model": os.environ.get(
                    "CONNECTBLITZ_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"
                ),
                "python_version": platform.python_version(),
                "request_id": request_id,
                "active_tenants": sorted(ENGINE.active_configs.keys()),
                "audit_chain_valid": chain["valid"],
                "audit_chain_rows": chain["checked_rows"],
            }

        if method == "GET" and path == "/api/state":
            contact_id = str(query.get("contact_id") or "cnt-blitz-demo-01").strip()
            bundle = ENGINE.render_contact_bundle(contact_id)
            bundle["tenant_presets"] = TENANT_PRESETS
            bundle["benchmarks"] = _load_benchmarks()
            bundle["request_id"] = request_id
            return 200, bundle

        if method == "GET" and path == "/api/benchmarks":
            chain = ENGINE.ledger.verify_chain_integrity()
            return 200, {
                "status": "ok",
                "benchmarks": _load_benchmarks(),
                "live_audit_chain": chain,
                "request_id": request_id,
            }

        if method == "POST" and path == "/api/contact/message":
            contact_id = str(body.get("contact_id") or "cnt-blitz-demo-01").strip()
            sender_role = str(body.get("sender_role") or "CUSTOMER").strip().upper()
            content = str(body.get("content") or body.get("message") or "").strip()
            selected_card_value = body.get("selected_card_value")
            if not content and selected_card_value:
                content = f"Selected card option: {selected_card_value}"
            if not content:
                return 400, {"error": "content (or message) is required"}
            client_msg_id = body.get("client_msg_id")
            visibility = str(body.get("visibility") or "PUBLIC").strip().upper()
            use_bedrock = bool(body.get("use_bedrock", True))

            out = ENGINE.post_message(
                contact_id=contact_id,
                sender_role=sender_role,
                content=content,
                client_msg_id=str(client_msg_id).strip() if client_msg_id else None,
                selected_card_value=str(selected_card_value).strip() if selected_card_value else None,
                visibility=visibility,
                use_bedrock=use_bedrock,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/contact/handoff":
            contact_id = str(body.get("contact_id") or "cnt-blitz-demo-01").strip()
            reason = str(body.get("reason") or "zero_repeat_warm_escalation").strip()
            use_bedrock = bool(body.get("use_bedrock", True))
            out = ENGINE.trigger_warm_handoff(
                contact_id=contact_id,
                reason=reason,
                use_bedrock=use_bedrock,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/supervisor/action":
            contact_id = str(body.get("contact_id") or "cnt-blitz-demo-01").strip()
            action_type = str(body.get("action_type") or "WHISPER").strip().upper()
            message_text = str(body.get("message_text") or body.get("content") or "").strip()
            supervisor_name = str(body.get("supervisor_name") or "Supervisor Elena").strip()
            client_msg_id = body.get("client_msg_id")
            out = ENGINE.execute_supervisor_action(
                contact_id=contact_id,
                action_type=action_type,
                message_text=message_text,
                supervisor_name=supervisor_name,
                client_msg_id=str(client_msg_id).strip() if client_msg_id else None,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/config/validate":
            raw_cfg = body.get("config") if isinstance(body.get("config"), dict) else body
            apply_live = bool(body.get("apply_live", True))
            contact_id = str(body.get("contact_id") or "cnt-blitz-demo-01").strip()
            out = ENGINE.validate_and_apply_config(
                raw_config=raw_cfg,
                apply_live=apply_live,
                contact_id=contact_id,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/reset":
            tenant_id = str(body.get("tenant_id") or "").strip()
            ENGINE.seed_demo_contacts()
            if tenant_id and tenant_id in TENANT_PRESETS and tenant_id != "nordpeak-gear":
                ENGINE.create_contact(
                    contact_id="cnt-blitz-demo-01",
                    tenant_id=tenant_id,
                    customer_name="Maya Lin",
                    customer_tier="Prime VIP",
                    identity_verified=True,
                )
            bundle = ENGINE.render_contact_bundle("cnt-blitz-demo-01")
            bundle["status"] = "reset_complete"
            bundle["request_id"] = request_id
            return 200, bundle

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except KeyError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {
        k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None
    }
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalConnectBlitzHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3099) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalConnectBlitzHandler)
    print(f"ConnectBlitz Contact Center Studio running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3099"))
    run_local_server(port=port_num)
