from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from services.enricher import connectors as shared


def int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def now_iso() -> str:
    # We keep it simple; Java/DB can also timestamp at insert time.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def process_event(tool: str, event_type: str, severity: str, message: str, detail: dict | None = None) -> dict:
    return {
        "tool": tool,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "detail": detail or {},
        "created_at": now_iso(),
    }


def run_tool(tool: str, seed: str, timeout_sec: int) -> dict:
    started = time.time()
    events: list[dict] = [process_event(tool, "tool_started", "info", f"{tool} started")]
    evidence: list[dict] = []

    try:
        normalized = seed.strip()
        usernames = shared.extract_usernames(normalized)
        targets = shared.extract_targets(normalized, usernames)
        emails = shared.extract_emails(normalized)
        domains = shared.extract_domains(normalized, emails)
        phones = shared.extract_phone_numbers(normalized)

        if tool == "holehe":
            evidence = [asdict(r) for r in shared.run_holehe(emails[: shared.int_env("OSINT_HOLEHE_MAX_EMAILS", 2, 1, 6)], timeout_sec)]
        elif tool == "sherlock":
            evidence = [asdict(r) for r in shared.run_sherlock(usernames, timeout_sec)]
        elif tool == "social-analyzer":
            evidence = [asdict(r) for r in shared.run_social_analyzer(usernames, timeout_sec)]
        elif tool == "maigret":
            evidence = [asdict(r) for r in shared.run_maigret(usernames, timeout_sec)]
        elif tool == "phoneinfoga":
            evidence = [asdict(r) for r in shared.run_phoneinfoga(phones, timeout_sec)]
        elif tool == "theharvester":
            evidence = [asdict(r) for r in shared.run_theharvester(domains, timeout_sec)]
        elif tool == "amass":
            evidence = [asdict(r) for r in shared.run_amass(domains, timeout_sec)]
        elif tool == "ghunt":
            evidence = [asdict(r) for r in shared.run_ghunt(emails, timeout_sec)]
        elif tool == "spiderfoot":
            evidence = [asdict(r) for r in shared.run_spiderfoot(targets, timeout_sec)]
        elif tool == "catalog":
            # No outbound traffic; just a notice that this agent is present.
            evidence = [asdict(shared.notice("catalog", "Catalog agent is available; UI uses /api/tools for OSINT Framework search."))]
        else:
            evidence = [asdict(shared.notice(tool, f"Unknown agent tool '{tool}'."))]
            events.append(process_event(tool, "tool_unknown", "warn", "Unknown tool"))

        elapsed_ms = int((time.time() - started) * 1000)
        events.append(process_event(tool, "tool_completed", "info", f"{tool} completed in {elapsed_ms}ms", {"elapsed_ms": elapsed_ms}))
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        events.append(process_event(tool, "tool_failed", "warn", f"{tool} failed: {exc}", {"elapsed_ms": elapsed_ms}))
        evidence = [asdict(shared.notice(tool, f"{tool} failed: {exc}"))]

    return {"evidence": evidence, "process_events": events, "searches": [], "coverage": []}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/run":
            self.send_error(404, "Not found")
            return

        tool = os.getenv("OSINT_AGENT_TOOL", "").strip()
        if not tool:
            self.send_json(500, {"error": "OSINT_AGENT_TOOL is not set"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body) if body else {}
            seed = str(payload.get("seed", "")).strip()
            if not seed:
                raise ValueError("seed is required")
            timeout_sec = int(payload.get("timeout_sec") or int_env("OSINT_CONNECTOR_TIMEOUT_SEC", 25, 5, 300))
            self.send_json(200, run_tool(tool, seed, timeout_sec))
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def send_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    host = os.getenv("OSINT_AGENT_HOST", "127.0.0.1")
    port = int_env("OSINT_AGENT_PORT", 8111, 1024, 65535)
    tool = os.getenv("OSINT_AGENT_TOOL", "unknown")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"{tool} agent listening on http://{host}:{port}/run")
    server.serve_forever()


if __name__ == "__main__":
    main()

