from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass(frozen=True)
class AgentSpec:
    name: str
    url: str
    enabled_env: str


def bool_env(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def agent_specs() -> list[AgentSpec]:
    # Tool-per-agent. Default ports are a predictable range so startup can launch them.
    base = os.getenv("OSINT_AGENT_BASE_URL", "http://127.0.0.1")
    ports = {
        "holehe": int_env("OSINT_AGENT_PORT_HOLEHE", 8111, 1024, 65535),
        "sherlock": int_env("OSINT_AGENT_PORT_SHERLOCK", 8112, 1024, 65535),
        "social_analyzer": int_env("OSINT_AGENT_PORT_SOCIAL_ANALYZER", 8113, 1024, 65535),
        "maigret": int_env("OSINT_AGENT_PORT_MAIGRET", 8114, 1024, 65535),
        "phoneinfoga": int_env("OSINT_AGENT_PORT_PHONEINFOGA", 8115, 1024, 65535),
        "theharvester": int_env("OSINT_AGENT_PORT_THEHARVESTER", 8116, 1024, 65535),
        "amass": int_env("OSINT_AGENT_PORT_AMASS", 8117, 1024, 65535),
        "ghunt": int_env("OSINT_AGENT_PORT_GHUNT", 8118, 1024, 65535),
        "spiderfoot": int_env("OSINT_AGENT_PORT_SPIDERFOOT", 8119, 1024, 65535),
        "catalog": int_env("OSINT_AGENT_PORT_CATALOG", 8120, 1024, 65535),
    }
    return [
        AgentSpec("holehe", f"{base}:{ports['holehe']}/run", "OSINT_ENABLE_HOLEHE"),
        AgentSpec("sherlock", f"{base}:{ports['sherlock']}/run", "OSINT_ENABLE_SHERLOCK"),
        AgentSpec("social-analyzer", f"{base}:{ports['social_analyzer']}/run", "OSINT_ENABLE_SOCIAL_ANALYZER"),
        AgentSpec("maigret", f"{base}:{ports['maigret']}/run", "OSINT_ENABLE_MAIGRET"),
        AgentSpec("phoneinfoga", f"{base}:{ports['phoneinfoga']}/run", "OSINT_ENABLE_PHONEINFOGA"),
        AgentSpec("theharvester", f"{base}:{ports['theharvester']}/run", "OSINT_ENABLE_THEHARVESTER"),
        AgentSpec("amass", f"{base}:{ports['amass']}/run", "OSINT_ENABLE_AMASS"),
        AgentSpec("ghunt", f"{base}:{ports['ghunt']}/run", "OSINT_ENABLE_GHUNT"),
        AgentSpec("spiderfoot", f"{base}:{ports['spiderfoot']}/run", "OSINT_ENABLE_SPIDERFOOT"),
        AgentSpec("catalog", f"{base}:{ports['catalog']}/run", "OSINT_ENABLE_CATALOG"),
    ]


def post_json(url: str, payload: dict, timeout_sec: int) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200) or 200), json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
        try:
            payload = json.loads(raw) if raw else {"error": f"HTTP {exc.code}"}
        except Exception:
            payload = {"error": raw or f"HTTP {exc.code}"}
        return int(exc.code), payload
    except Exception as exc:
        return 599, {"error": str(exc)}


def merge_lists(*lists: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for items in lists:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("source_type", "")), str(item.get("source_uri", "")), str(item.get("title", "")))
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged


def enrich(seed: str, profile_id: str | None) -> dict:
    timeout = int_env("OSINT_CONNECTOR_TIMEOUT_SEC", 25, 5, 300)
    enabled = []
    evidence: list[dict] = []
    searches: list[dict] = []
    coverage: list[dict] = []
    process_events: list[dict] = []

    for spec in agent_specs():
        if spec.enabled_env and not bool_env(spec.enabled_env, default=True):
            continue
        enabled.append(spec.name)
        started = time.time()
        status, payload = post_json(
            spec.url,
            {"seed": seed, "profile_id": profile_id or "", "timeout_sec": timeout},
            timeout_sec=max(8, timeout + 10),
        )
        elapsed_ms = int((time.time() - started) * 1000)
        if status >= 200 and status < 300 and isinstance(payload, dict):
            evidence = merge_lists(evidence, payload.get("evidence", []))
            searches.extend(payload.get("searches", []) or [])
            coverage.extend(payload.get("coverage", []) or [])
            process_events.extend(payload.get("process_events", []) or [])
            process_events.append(
                {
                    "tool": spec.name,
                    "event_type": "agent_completed",
                    "severity": "info",
                    "message": f"Agent completed in {elapsed_ms}ms",
                    "detail": {"status": status, "elapsed_ms": elapsed_ms},
                }
            )
        else:
            process_events.append(
                {
                    "tool": spec.name,
                    "event_type": "agent_failed",
                    "severity": "warn",
                    "message": f"Agent call failed (HTTP {status})",
                    "detail": {"status": status, "elapsed_ms": elapsed_ms, "error": payload.get("error", "") if isinstance(payload, dict) else ""},
                }
            )

    # Identifiers remain "verified links only". Evidence holds everything else.
    from services.enricher.enricher import extract_identifiers, link_identifiers, build_suggested_searches, build_correlation_keys

    extracted = extract_identifiers(seed)
    identifiers = link_identifiers(extracted, evidence)
    searches = build_suggested_searches(extracted) + (searches or [])
    correlation_keys = build_correlation_keys(seed, extracted)

    summary = f"Created from seed with {len(identifiers)} verified link finding(s)."
    return {
        "displayName": seed.strip()[:120],
        "summary": summary,
        "confidence": 0.62 if identifiers else 0.28,
        "identifiers": identifiers,
        "evidence": evidence,
        "suggestedSearches": searches,
        "correlationKeys": correlation_keys,
        "process": {
            "enabledTools": enabled,
            "events": process_events,
        },
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/enrich":
            self.send_error(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body) if body else {}
            seed = str(payload.get("seed", "")).strip()
            if not seed:
                raise ValueError("seed is required")
            profile_id = str(payload.get("profile_id", "")).strip() or None
            self.send_json(200, enrich(seed, profile_id))
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


if __name__ == "__main__":
    host = os.getenv("OSINT_ORCH_HOST", "127.0.0.1")
    port = int_env("OSINT_ORCH_PORT", 8091, 1024, 65535)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Orchestrator listening on http://{host}:{port}/enrich")
    server.serve_forever()

