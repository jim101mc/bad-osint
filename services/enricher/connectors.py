from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from uuid import uuid4


@dataclass(frozen=True)
class ConnectorResult:
    source_type: str
    source_uri: str
    title: str
    snippet: str
    confidence: float


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool


@dataclass(frozen=True)
class UrlCheck:
    ok: bool
    final_url: str
    status_code: int | None
    reason: str


EMAIL_RE = re.compile(r"\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
HANDLE_RE = re.compile(r"(?<!\w)@([A-Z0-9_]{3,30})\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d .()/-]{7,}\d)(?!\d)")
USERNAME_RE = re.compile(r"^[A-Z0-9](?:[A-Z0-9._-]{1,62}[A-Z0-9])?$", re.IGNORECASE)
SOCIAL_HOSTS = {
    "facebook.com",
    "github.com",
    "instagram.com",
    "linkedin.com",
    "reddit.com",
    "tiktok.com",
    "twitter.com",
    "x.com",
    "youtube.com",
}
PROFILE_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
USERNAME_IN_PATH_RE = re.compile(r"/([A-Z0-9._@-]{2,64})/?$", re.IGNORECASE)
NEGATIVE_PAGE_TEXT = (
    "not found",
    "page isn't available",
    "page not available",
    "this page doesn't exist",
    "this account doesn't exist",
    "user not found",
    "sorry, this page",
    "profile unavailable",
)
NON_PROFILE_SEGMENTS = {
    "",
    "about",
    "accounts",
    "auth",
    "directory",
    "explore",
    "help",
    "home",
    "login",
    "privacy",
    "search",
    "settings",
    "signup",
    "terms",
}
HOLEHE_LINE_RE = re.compile(r"^\[(?P<marker>[+\-xX!])\]\s*(?P<site>[^\s:]+)")


def run_public_connectors(seed: str) -> list[ConnectorResult]:
    normalized = seed.strip()
    if not normalized:
        return []

    results: list[ConnectorResult] = [
        ConnectorResult(
            source_type="seed",
            source_uri="",
            title="Initial seed",
            snippet=f"Profile created from analyst-provided seed: {normalized}",
            confidence=0.50,
        )
    ]

    usernames = extract_usernames(normalized)
    targets = extract_targets(normalized, usernames)
    emails = extract_emails(normalized)
    domains = extract_domains(normalized, emails)
    phones = extract_phone_numbers(normalized)
    tool_timeout = int_env("OSINT_CONNECTOR_TIMEOUT_SEC", 25, 5, 300)
    holehe_emails = emails[:int_env("OSINT_HOLEHE_MAX_EMAILS", 2, 1, 6)]

    if bool_env("OSINT_ENABLE_HOLEHE"):
        results.extend(run_holehe(holehe_emails, tool_timeout))

    if bool_env("OSINT_ENABLE_SHERLOCK"):
        results.extend(run_sherlock(usernames, tool_timeout))
    if bool_env("OSINT_ENABLE_SOCIAL_ANALYZER"):
        results.extend(run_social_analyzer(usernames, tool_timeout))
    if bool_env("OSINT_ENABLE_MAIGRET"):
        results.extend(run_maigret(usernames, tool_timeout))
    if bool_env("OSINT_ENABLE_PHONEINFOGA"):
        results.extend(run_phoneinfoga(phones, tool_timeout))
    if bool_env("OSINT_ENABLE_THEHARVESTER"):
        results.extend(run_theharvester(domains, tool_timeout))
    if bool_env("OSINT_ENABLE_AMASS"):
        results.extend(run_amass(domains, tool_timeout))
    if bool_env("OSINT_ENABLE_GHUNT"):
        results.extend(run_ghunt(emails, tool_timeout))
    if bool_env("OSINT_ENABLE_SPIDERFOOT"):
        results.extend(run_spiderfoot(targets, tool_timeout))

    return dedupe(results)


def run_holehe(emails: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not emails:
        return []

    command_base = resolve_command(
        "OSINT_HOLEHE_CMD",
        fallback=[
            ["holehe"],
            [sys.executable, "-m", "holehe"],
        ],
    )
    if not command_base:
        return [notice("holehe", "Holehe command not found in PATH or OSINT_HOLEHE_CMD.")]

    max_emails = int_env("OSINT_HOLEHE_MAX_EMAILS", 2, 1, 6)
    command_timeout = int_env("OSINT_HOLEHE_TIMEOUT_SEC", max(30, timeout_seconds * 2), 10, 600)
    max_sites_per_email = 120
    findings: list[ConnectorResult] = []
    exists_count = 0
    not_found_count = 0
    rate_limited_count = 0
    checked_emails = 0

    for email in emails[:max_emails]:
        checked_emails += 1
        commands = [
            command_base + ["--only-used", "--no-color", "--timeout", str(max(5, timeout_seconds)), "--json", email],
            command_base + ["--only-used", "--no-color", "--timeout", str(max(5, timeout_seconds)), email],
            command_base + [email],
        ]
        result = run_command_variants(commands, timeout_seconds=max(8, command_timeout))
        if result.timed_out:
            findings.append(notice("holehe", f'Holehe timed out for "{email}".'))
            continue

        statuses = parse_holehe_statuses(result.stdout, result.stderr)
        if not statuses:
            snippet = f'Holehe produced no parseable website states for "{email}".'
            if result.returncode not in (0, 1, None):
                snippet += f" Exit code: {result.returncode}."
            findings.append(notice("holehe", snippet))
            continue

        sites_added = 0
        for site, status in statuses.items():
            if sites_added >= max_sites_per_email:
                break
            sites_added += 1
            if status == "exists":
                exists_count += 1
                findings.append(
                    ConnectorResult(
                        source_type="holehe",
                        source_uri="",
                        title=f"Holehe account existence on {site}",
                        snippet=f'Email "{email}" appears to exist on {site}.',
                        confidence=0.82,
                    )
                )
                continue
            if status == "not_found":
                not_found_count += 1
                findings.append(
                    ConnectorResult(
                        source_type="holehe",
                        source_uri="",
                        title=f"Holehe no account on {site}",
                        snippet=f'Email "{email}" was not found on {site}.',
                        confidence=0.30,
                    )
                )
                continue
            rate_limited_count += 1
            findings.append(
                ConnectorResult(
                    source_type="holehe",
                    source_uri="",
                    title=f"Holehe limited/unknown on {site}",
                    snippet=f'Email "{email}" check on {site} was limited or inconclusive.',
                    confidence=0.22,
                )
            )

    findings.append(
        ConnectorResult(
            source_type="holehe",
            source_uri="",
            title="Holehe scan summary",
            snippet=(
                f"Checked {checked_emails} email(s): "
                f"{exists_count} exists, {not_found_count} not-found, {rate_limited_count} rate-limited/inconclusive."
            ),
            confidence=0.42,
        )
    )
    return findings


def run_sherlock(usernames: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not usernames:
        return []

    command_base = resolve_command(
        "OSINT_SHERLOCK_CMD",
        fallback=[
            ["sherlock"],
            [sys.executable, "-m", "sherlock_project"],
            [sys.executable, "-m", "sherlock_project.sherlock"],
        ],
    )
    if not command_base:
        return [notice("sherlock", "Sherlock command not found in PATH or OSINT_SHERLOCK_CMD.")]

    max_users = int_env("OSINT_SHERLOCK_MAX_USERNAMES", 2, 1, 8)
    findings: list[ConnectorResult] = []
    found_count = 0
    checked_count = 0
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)

    for username in usernames[:max_users]:
        command = command_base + [
            "--print-found",
            "--no-color",
            "--timeout",
            str(max(1, timeout_seconds)),
            "--local",
            username,
        ]
        result = run_command(command, timeout_seconds=max(5, timeout_seconds))
        if result.timed_out:
            findings.append(notice("sherlock", f'Sherlock timed out for username "{username}".'))
            continue

        urls = extract_profile_urls(result.stdout)
        user_hits = 0
        for url in urls:
            if not is_social_profile(url):
                continue
            checked_count += 1
            check = validate_profile_link(url, username=username, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            user_hits += 1
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="sherlock",
                    source_uri=check.final_url,
                    title=f"Sherlock hit for {username}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}; username '{username}'.",
                    confidence=0.72,
                )
            )

        if user_hits == 0 and result.returncode not in (0, 1):
            snippet = f'Sherlock exited with code {result.returncode} for "{username}".'
            if result.stderr.strip():
                snippet += f" {truncate(result.stderr.strip(), 220)}"
            findings.append(notice("sherlock", snippet))

    findings.append(
        ConnectorResult(
            source_type="sherlock",
            source_uri="",
            title="Sherlock scan summary",
            snippet=(
                f"Checked {min(len(usernames), max_users)} username candidate(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.38,
        )
    )
    return findings


def run_social_analyzer(usernames: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not usernames:
        return []

    max_users = int_env("OSINT_SOCIAL_ANALYZER_MAX_USERNAMES", 2, 1, 8)
    findings: list[ConnectorResult] = []
    found_count = 0
    checked_count = 0
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)

    for username in usernames[:max_users]:
        payload = run_social_analyzer_object(username, timeout_seconds)
        if payload is None:
            findings.append(notice("social_analyzer", f'Social Analyzer unavailable for username "{username}".'))
            continue

        detected = payload.get("detected", [])
        if not isinstance(detected, list):
            detected = []

        for row in detected:
            if not isinstance(row, dict):
                continue
            link = str(row.get("link", "")).strip()
            if not link:
                continue
            rate = parse_rate(row.get("rate"))
            status = str(row.get("status", "unknown"))
            checked_count += 1
            check = validate_profile_link(link, username=username, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="social_analyzer",
                    source_uri=check.final_url,
                    title=f"Social Analyzer hit for {username}",
                    snippet=f"Status={status}; rate={rate:.0f}%; verified ({check.reason}); HTTP {check.status_code or '-'}.",
                    confidence=clamp(rate / 100.0, 0.45, 0.93),
                )
            )

    findings.append(
        ConnectorResult(
            source_type="social_analyzer",
            source_uri="",
            title="Social Analyzer scan summary",
            snippet=(
                f"Checked {min(len(usernames), max_users)} username candidate(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.38,
        )
    )
    return findings


def run_social_analyzer_object(username: str, timeout_seconds: int) -> dict | None:
    script = """
import importlib
import json
import sys

username = sys.argv[1]
module = None
for name in ("social_analyzer", "social-analyzer"):
    try:
        module = importlib.import_module(name)
        break
    except Exception:
        pass

if module is None:
    raise RuntimeError("social-analyzer module not importable")

runner = module.SocialAnalyzer(silent=True)
result = runner.run_as_object(
    username=username,
    mode="fast",
    output="json",
    method="find",
    profiles="detected",
    filter="good",
    silent=True
)
print(json.dumps(result))
"""
    command = [sys.executable, "-c", script, username]
    result = run_command(command, timeout_seconds=max(6, timeout_seconds))
    if result.timed_out or result.returncode not in (0,):
        return None
    return parse_json_payload(result.stdout)


def run_spiderfoot(targets: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not targets:
        return []

    base_url = os.getenv("OSINT_SPIDERFOOT_BASE_URL", "http://127.0.0.1:5001").rstrip("/")
    scan_timeout = int_env("OSINT_SPIDERFOOT_SCAN_TIMEOUT_SEC", 90, 10, 900)
    max_events = int_env("OSINT_SPIDERFOOT_MAX_EVENTS", 40, 1, 400)
    usecase = os.getenv("OSINT_SPIDERFOOT_USECASE", "passive").strip() or "passive"
    target = targets[0]

    start_payload = {
        "scanname": f"osint-correlator-{uuid4().hex[:8]}",
        "scantarget": target,
        "modulelist": "",
        "typelist": "",
        "usecase": usecase,
    }
    start = http_request_json(
        f"{base_url}/startscan",
        method="POST",
        form=start_payload,
        timeout=max(5, timeout_seconds),
    )
    if not isinstance(start, list) or len(start) < 2 or str(start[0]).upper() != "SUCCESS":
        return [notice("spiderfoot", f"Could not start SpiderFoot scan at {base_url}.")]

    scan_id = str(start[1])
    status = "UNKNOWN"
    deadline = time.time() + scan_timeout
    while time.time() < deadline:
        status_data = http_request_json(
            f"{base_url}/scanstatus?id={urllib.parse.quote(scan_id)}",
            method="GET",
            timeout=max(5, timeout_seconds),
        )
        if isinstance(status_data, list) and len(status_data) >= 6:
            status = str(status_data[5])
            if status in {"FINISHED", "ABORTED", "ERROR-FAILED"}:
                break
        time.sleep(1.5)

    if status not in {"FINISHED", "ABORTED", "ERROR-FAILED"}:
        http_request_json(
            f"{base_url}/stopscan?id={urllib.parse.quote(scan_id)}",
            method="GET",
            timeout=max(4, timeout_seconds),
        )
        return [notice("spiderfoot", f"SpiderFoot scan timed out for target '{target}' and was asked to stop.")]

    rows = http_request_json(
        f"{base_url}/scaneventresults?id={urllib.parse.quote(scan_id)}&eventType=ALL&filterfp=false",
        method="GET",
        timeout=max(5, timeout_seconds),
    )
    if not isinstance(rows, list):
        return [notice("spiderfoot", f"SpiderFoot scan finished with status {status}, but no event data was returned.")]

    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    expected_username = extract_usernames(target)[0] if extract_usernames(target) else None
    for row in rows[:max_events]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        value = strip_html(str(row[1])).strip()
        if not value or value == "ROOT":
            continue
        event_type = str(row[10]) if len(row) > 10 else "EVENT"
        source_name = str(row[3]) if len(row) > 3 else "module"
        uri = value if value.startswith("http://") or value.startswith("https://") else ""
        if not uri or not is_social_profile(uri):
            continue
        checked_count += 1
        check = validate_profile_link(uri, username=expected_username, timeout_seconds=check_timeout)
        if not check.ok:
            continue
        found_count += 1
        findings.append(
            ConnectorResult(
                source_type="spiderfoot",
                source_uri=check.final_url,
                title=f"SpiderFoot {event_type}",
                snippet=f"{source_name}: verified ({check.reason}); HTTP {check.status_code or '-'}",
                confidence=0.64,
            )
        )

    findings.append(
        ConnectorResult(
            source_type="spiderfoot",
            source_uri="",
            title="SpiderFoot scan summary",
            snippet=(
                f"Target '{target}' completed with status {status}; "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.42,
        )
    )
    return findings


def run_maigret(usernames: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not usernames:
        return []

    command_base = resolve_command(
        "OSINT_MAIGRET_CMD",
        fallback=[
            ["maigret"],
            [sys.executable, "-m", "maigret"],
        ],
    )
    if not command_base:
        return [notice("maigret", "Maigret command not found in PATH or OSINT_MAIGRET_CMD.")]

    max_users = int_env("OSINT_MAIGRET_MAX_USERNAMES", 2, 1, 8)
    top_sites = int_env("OSINT_MAIGRET_TOP_SITES", 200, 20, 3000)
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    max_urls = int_env("OSINT_MAIGRET_MAX_URLS", 120, 10, 2000)
    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0

    for username in usernames[:max_users]:
        commands = [
            command_base
            + [
                username,
                "--top-sites",
                str(top_sites),
                "--timeout",
                str(max(1, timeout_seconds)),
                "--no-recursion",
                "--print-found",
            ],
            command_base
            + [
                username,
                "--top-sites",
                str(top_sites),
                "--timeout",
                str(max(1, timeout_seconds)),
                "--no-recursion",
            ],
        ]
        result = run_command_variants(commands, timeout_seconds=max(8, timeout_seconds))
        if result.timed_out:
            findings.append(notice("maigret", f'Maigret timed out for username "{username}".'))
            continue

        output = "\n".join([result.stdout, result.stderr]).strip()
        urls = [url for url in extract_profile_urls(output) if is_social_profile(url)]
        user_hits = 0

        for url in urls[:max_urls]:
            checked_count += 1
            check = validate_profile_link(url, username=username, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            user_hits += 1
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="maigret",
                    source_uri=check.final_url,
                    title=f"Maigret hit for {username}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}; username '{username}'.",
                    confidence=0.74,
                )
            )

        if user_hits == 0 and result.returncode not in (0, 1):
            details = truncate(output, 220) if output else f"Maigret exited with code {result.returncode}."
            findings.append(notice("maigret", f'No usable output for "{username}". {details}'))

    findings.append(
        ConnectorResult(
            source_type="maigret",
            source_uri="",
            title="Maigret scan summary",
            snippet=(
                f"Checked {min(len(usernames), max_users)} username candidate(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.40,
        )
    )
    return findings


def run_phoneinfoga(phone_numbers: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not phone_numbers:
        return []

    command_base = resolve_command(
        "OSINT_PHONEINFOGA_CMD",
        fallback=[
            ["phoneinfoga"],
            ["phoneinfoga.exe"],
        ],
    )
    if not command_base:
        return [notice("phoneinfoga", "PhoneInfoga command not found in PATH or OSINT_PHONEINFOGA_CMD.")]

    max_numbers = int_env("OSINT_PHONEINFOGA_MAX_NUMBERS", 1, 1, 3)
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    max_urls = int_env("OSINT_PHONEINFOGA_MAX_URLS", 80, 5, 1000)
    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0

    for number in phone_numbers[:max_numbers]:
        commands = [
            command_base + ["scan", "-n", number, "-o", "json"],
            command_base + ["scan", "-n", number],
        ]
        result = run_command_variants(commands, timeout_seconds=max(10, timeout_seconds))
        if result.timed_out:
            findings.append(notice("phoneinfoga", f'PhoneInfoga timed out for "{number}".'))
            continue

        output = "\n".join([result.stdout, result.stderr]).strip()
        payload = parse_json_payload(output)
        urls = [url for url in extract_profile_urls(output) if is_social_profile(url)]
        if isinstance(payload, (dict, list)):
            urls.extend([url for url in extract_urls_from_object(payload) if is_social_profile(url)])

        seen_urls: set[str] = set()
        for url in urls:
            lowered = normalize_url(url)
            if lowered in seen_urls:
                continue
            seen_urls.add(lowered)
            if len(seen_urls) > max_urls:
                break
            checked_count += 1
            check = validate_profile_link(url, username=None, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="phoneinfoga",
                    source_uri=check.final_url,
                    title=f"PhoneInfoga profile lead for {number}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}",
                    confidence=0.66,
                )
            )

        summary = "PhoneInfoga scan finished."
        if output:
            summary = truncate(" ".join(output.split()), 220)
        findings.append(
            ConnectorResult(
                source_type="phoneinfoga",
                source_uri="",
                title=f"PhoneInfoga summary for {number}",
                snippet=summary,
                confidence=0.35,
            )
        )

    findings.append(
        ConnectorResult(
            source_type="phoneinfoga",
            source_uri="",
            title="PhoneInfoga scan summary",
            snippet=(
                f"Checked {min(len(phone_numbers), max_numbers)} phone number(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.35,
        )
    )
    return findings


def run_theharvester(domains: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not domains:
        return []

    command_base = resolve_command(
        "OSINT_THEHARVESTER_CMD",
        fallback=[
            ["theHarvester"],
            ["theharvester"],
            [sys.executable, "-m", "theHarvester"],
        ],
    )
    if not command_base:
        return [notice("theharvester", "theHarvester command not found in PATH or OSINT_THEHARVESTER_CMD.")]

    max_domains = int_env("OSINT_THEHARVESTER_MAX_DOMAINS", 1, 1, 3)
    limit = int_env("OSINT_THEHARVESTER_LIMIT", 100, 10, 1000)
    source = os.getenv("OSINT_THEHARVESTER_SOURCE", "all").strip() or "all"
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    max_urls = int_env("OSINT_THEHARVESTER_MAX_URLS", 80, 5, 1000)
    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0

    for domain in domains[:max_domains]:
        command = command_base + ["-d", domain, "-b", source, "-l", str(limit)]
        result = run_command(command, timeout_seconds=max(10, timeout_seconds))
        if result.timed_out:
            findings.append(notice("theharvester", f'theHarvester timed out for "{domain}".'))
            continue

        output = "\n".join([result.stdout, result.stderr]).strip()
        emails = sorted({f"{local}@{host}".lower() for local, host in EMAIL_RE.findall(output)})[:8]
        subdomains = extract_subdomains(output, domain, limit=30)
        summary = (
            f"Domain {domain}: discovered {len(subdomains)} subdomain candidate(s) and "
            f"{len(emails)} email candidate(s)."
        )
        if result.returncode not in (0,):
            summary += f" Exit code {result.returncode}."
        findings.append(
            ConnectorResult(
                source_type="theharvester",
                source_uri="",
                title=f"theHarvester summary for {domain}",
                snippet=truncate(summary, 230),
                confidence=0.40,
            )
        )

        for candidate in subdomains[:5]:
            findings.append(
                ConnectorResult(
                    source_type="theharvester",
                    source_uri="",
                    title=f"theHarvester subdomain candidate ({domain})",
                    snippet=candidate,
                    confidence=0.30,
                )
            )
        for candidate in emails[:5]:
            findings.append(
                ConnectorResult(
                    source_type="theharvester",
                    source_uri="",
                    title=f"theHarvester email candidate ({domain})",
                    snippet=candidate,
                    confidence=0.30,
                )
            )

        urls = [url for url in extract_profile_urls(output) if is_social_profile(url)]
        for url in urls[:max_urls]:
            checked_count += 1
            check = validate_profile_link(url, username=None, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="theharvester",
                    source_uri=check.final_url,
                    title=f"theHarvester profile lead for {domain}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}",
                    confidence=0.63,
                )
            )

    findings.append(
        ConnectorResult(
            source_type="theharvester",
            source_uri="",
            title="theHarvester scan summary",
            snippet=(
                f"Checked {min(len(domains), max_domains)} domain(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.34,
        )
    )
    return findings


def run_amass(domains: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not domains:
        return []

    command_base = resolve_command(
        "OSINT_AMASS_CMD",
        fallback=[
            ["amass"],
            ["amass.exe"],
        ],
    )
    if not command_base:
        return [notice("amass", "Amass command not found in PATH or OSINT_AMASS_CMD.")]

    max_domains = int_env("OSINT_AMASS_MAX_DOMAINS", 1, 1, 3)
    enum_timeout_sec = int_env("OSINT_AMASS_TIMEOUT_SEC", max(45, timeout_seconds * 3), 15, 3600)
    enum_timeout_min = max(1, int((enum_timeout_sec + 59) / 60))
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    max_urls = int_env("OSINT_AMASS_MAX_URLS", 60, 5, 1000)
    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0

    for domain in domains[:max_domains]:
        command = command_base + ["enum", "-passive", "-d", domain, "-timeout", str(enum_timeout_min)]
        result = run_command(command, timeout_seconds=enum_timeout_sec)
        if result.timed_out:
            findings.append(notice("amass", f'Amass timed out for "{domain}".'))
            continue

        output = "\n".join([result.stdout, result.stderr]).strip()
        subdomains = extract_subdomains(output, domain, limit=80)
        summary = f"Domain {domain}: discovered {len(subdomains)} subdomain candidate(s) via passive enumeration."
        if result.returncode not in (0,):
            summary += f" Exit code {result.returncode}."
        findings.append(
            ConnectorResult(
                source_type="amass",
                source_uri="",
                title=f"Amass summary for {domain}",
                snippet=truncate(summary, 230),
                confidence=0.44,
            )
        )

        for candidate in subdomains[:10]:
            findings.append(
                ConnectorResult(
                    source_type="amass",
                    source_uri="",
                    title=f"Amass subdomain candidate ({domain})",
                    snippet=candidate,
                    confidence=0.36,
                )
            )

        urls = [url for url in extract_profile_urls(output) if is_social_profile(url)]
        for url in urls[:max_urls]:
            checked_count += 1
            check = validate_profile_link(url, username=None, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="amass",
                    source_uri=check.final_url,
                    title=f"Amass profile lead for {domain}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}",
                    confidence=0.58,
                )
            )

    findings.append(
        ConnectorResult(
            source_type="amass",
            source_uri="",
            title="Amass scan summary",
            snippet=(
                f"Checked {min(len(domains), max_domains)} domain(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.36,
        )
    )
    return findings


def run_ghunt(emails: list[str], timeout_seconds: int) -> list[ConnectorResult]:
    if not emails:
        return []

    command_base = resolve_command(
        "OSINT_GHUNT_CMD",
        fallback=[
            ["ghunt"],
            [sys.executable, "-m", "ghunt"],
        ],
    )
    if not command_base:
        return [notice("ghunt", "GHunt command not found in PATH or OSINT_GHUNT_CMD.")]

    max_emails = int_env("OSINT_GHUNT_MAX_EMAILS", 1, 1, 3)
    check_timeout = int_env("OSINT_URL_CHECK_TIMEOUT_SEC", 8, 3, 30)
    max_urls = int_env("OSINT_GHUNT_MAX_URLS", 80, 5, 1000)
    findings: list[ConnectorResult] = []
    checked_count = 0
    found_count = 0

    for email in emails[:max_emails]:
        tmp_file = None
        try:
            tmp = tempfile.NamedTemporaryFile(prefix="ghunt-", suffix=".json", delete=False)
            tmp_file = tmp.name
            tmp.close()
        except Exception:
            tmp_file = None

        if tmp_file:
            commands = [
                command_base + ["email", email, "--json", tmp_file],
                command_base + ["email", email],
            ]
        else:
            commands = [command_base + ["email", email]]

        result = run_command_variants(commands, timeout_seconds=max(10, timeout_seconds))
        if result.timed_out:
            if tmp_file and os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass
            findings.append(notice("ghunt", f'GHunt timed out for "{email}".'))
            continue

        output = "\n".join([result.stdout, result.stderr]).strip()
        payload: object | None = None
        if tmp_file and os.path.exists(tmp_file):
            try:
                with open(tmp_file, "r", encoding="utf-8", errors="ignore") as handle:
                    payload = parse_json_payload(handle.read())
            except Exception:
                payload = None
            finally:
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass
        if payload is None:
            payload = parse_json_payload(output)

        urls = [url for url in extract_profile_urls(output) if is_social_profile(url)]
        if isinstance(payload, (dict, list)):
            urls.extend([url for url in extract_urls_from_object(payload) if is_social_profile(url)])
        urls = list(dict.fromkeys(urls))

        for url in urls[:max_urls]:
            checked_count += 1
            check = validate_profile_link(url, username=None, timeout_seconds=check_timeout)
            if not check.ok:
                continue
            found_count += 1
            findings.append(
                ConnectorResult(
                    source_type="ghunt",
                    source_uri=check.final_url,
                    title=f"GHunt profile lead for {email}",
                    snippet=f"Verified profile URL ({check.reason}); HTTP {check.status_code or '-'}",
                    confidence=0.67,
                )
            )

        if output:
            findings.append(
                ConnectorResult(
                    source_type="ghunt",
                    source_uri="",
                    title=f"GHunt summary for {email}",
                    snippet=truncate(" ".join(output.split()), 230),
                    confidence=0.30,
                )
            )

        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    findings.append(
        ConnectorResult(
            source_type="ghunt",
            source_uri="",
            title="GHunt scan summary",
            snippet=(
                f"Checked {min(len(emails), max_emails)} email(s), "
                f"validated {checked_count} URL(s), accepted {found_count} person-profile URL(s)."
            ),
            confidence=0.35,
        )
    )
    return findings


def run_command_variants(commands: list[list[str]], timeout_seconds: int) -> CommandResult:
    fallback_markers = (
        "unrecognized",
        "unknown option",
        "unknown argument",
        "usage:",
        "error: argument",
    )
    last = CommandResult(returncode=None, stdout="", stderr="", timed_out=False)
    for index, command in enumerate(commands):
        result = run_command(command, timeout_seconds=timeout_seconds)
        last = result
        if result.timed_out:
            return result
        if result.returncode in (0, 1):
            return result
        combined = f"{result.stdout}\n{result.stderr}".lower()
        if index < len(commands) - 1 and any(marker in combined for marker in fallback_markers):
            continue
        return result
    return last


def parse_holehe_statuses(stdout: str, stderr: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    payload = parse_json_payload(stdout)
    if payload is None:
        payload = parse_json_payload(stderr)
    if payload is not None:
        collect_holehe_statuses_from_payload(payload, statuses)
    if statuses:
        return statuses

    text = "\n".join([stdout or "", stderr or ""])
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = HOLEHE_LINE_RE.match(line)
        if not match:
            continue
        marker = match.group("marker")
        site = normalize_holehe_site(match.group("site"))
        if not site:
            continue
        if marker == "+":
            merge_holehe_status(statuses, site, "exists")
        elif marker == "-":
            merge_holehe_status(statuses, site, "not_found")
        else:
            merge_holehe_status(statuses, site, "rate_limited")
    return statuses


def collect_holehe_statuses_from_payload(payload: object, statuses: dict[str, str]) -> None:
    if isinstance(payload, list):
        for item in payload:
            collect_holehe_statuses_from_payload(item, statuses)
        return
    if not isinstance(payload, dict):
        return

    for key, value in payload.items():
        key_text = str(key).strip()
        key_site = normalize_holehe_site(key_text)
        status = classify_holehe_status(value)
        if key_site and status:
            merge_holehe_status(statuses, key_site, status)

        if isinstance(value, dict):
            nested_site = normalize_holehe_site(str(value.get("site", value.get("name", ""))))
            nested_status = classify_holehe_status(value)
            if nested_site and nested_status:
                merge_holehe_status(statuses, nested_site, nested_status)
            collect_holehe_statuses_from_payload(value, statuses)
        elif isinstance(value, list):
            collect_holehe_statuses_from_payload(value, statuses)


def classify_holehe_status(value: object) -> str | None:
    if isinstance(value, bool):
        return "exists" if value else "not_found"
    if isinstance(value, (int, float)):
        return "exists" if value > 0 else "not_found"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "found", "exists", "exist", "valid", "yes", "registered", "+"}:
            return "exists"
        if lowered in {"false", "not found", "none", "no", "invalid", "-", "missing"}:
            return "not_found"
        if lowered:
            return "rate_limited"
        return None
    if isinstance(value, dict):
        normalized = {str(key).strip().lower(): item for key, item in value.items()}
        for key in ("exists", "exist", "found", "registered", "used", "valid"):
            if key in normalized:
                return classify_holehe_status(normalized[key])
        for key in ("rate_limit", "ratelimit", "retry", "throttled", "limited", "error"):
            if key in normalized:
                marker = normalized[key]
                if isinstance(marker, bool) and marker:
                    return "rate_limited"
                if isinstance(marker, str) and marker.strip():
                    return "rate_limited"
        if "status" in normalized:
            return classify_holehe_status(normalized["status"])
        if normalized:
            return "rate_limited"
        return None
    return None


def merge_holehe_status(statuses: dict[str, str], site: str, status: str) -> None:
    precedence = {
        "not_found": 1,
        "rate_limited": 2,
        "exists": 3,
    }
    current = statuses.get(site)
    if current is None or precedence.get(status, 0) > precedence.get(current, 0):
        statuses[site] = status


def normalize_holehe_site(raw: str) -> str:
    value = raw.strip().lower().strip("[](){}<>\"'`.,;")
    if not value:
        return ""
    if "://" in value:
        try:
            parsed = urllib.parse.urlparse(value)
            value = parsed.hostname or value
        except Exception:
            pass
    if value.startswith("www."):
        value = value[4:]
    value = value.strip()
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", value):
        return value
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,80}", value):
        return value
    return ""


def extract_emails(seed: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for local, domain in EMAIL_RE.findall(seed):
        email = f"{local}@{domain}".strip()
        lowered = email.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        values.append(email)
    return values


def extract_domains(seed: str, emails: list[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = value.strip().strip(".")
        if not cleaned:
            return
        lowered = cleaned.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        values.append(cleaned)

    for email in emails:
        if "@" in email:
            add(email.split("@", 1)[1])
    for domain in DOMAIN_RE.findall(seed):
        add(domain)
    for url in URL_RE.findall(seed):
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname:
            add(parsed.hostname)
    return values


def extract_phone_numbers(seed: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in PHONE_RE.findall(seed):
        cleaned = match.strip()
        digits = re.sub(r"\D", "", cleaned)
        if len(digits) < 8:
            continue
        normalized = "+" + digits if cleaned.startswith("+") else digits
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(cleaned)
    return values


def extract_subdomains(text: str, domain: str, limit: int) -> list[str]:
    if not text or not domain:
        return []
    escaped = re.escape(domain.lower())
    pattern = re.compile(rf"\b(?:[a-z0-9-]+\.)+{escaped}\b", re.IGNORECASE)
    values: list[str] = []
    seen: set[str] = set()
    for match in pattern.findall(text):
        lowered = match.lower()
        if lowered == domain.lower() or lowered in seen:
            continue
        seen.add(lowered)
        values.append(match)
        if len(values) >= max(1, limit):
            break
    return values


def extract_urls_from_object(payload: object) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
            return
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if isinstance(value, str):
            for url in extract_profile_urls(value):
                key = normalize_url(url)
                if key in seen:
                    continue
                seen.add(key)
                urls.append(url)

    walk(payload)
    return urls


def extract_usernames(seed: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        value = raw.strip().lstrip("@")
        if not value:
            return
        if not USERNAME_RE.match(value):
            return
        lowered = value.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        candidates.append(value)

    for handle in HANDLE_RE.findall(seed):
        add(handle)

    for local, _domain in EMAIL_RE.findall(seed):
        add(local.split("+", 1)[0])

    for url in URL_RE.findall(seed):
        parsed = urllib.parse.urlparse(url)
        host = normalize_host(parsed.hostname or "")
        if host not in SOCIAL_HOSTS:
            continue
        segment = parsed.path.strip("/").split("/", 1)[0]
        if segment:
            add(segment)

    plain = seed.strip()
    if plain and USERNAME_RE.match(plain) and "." not in plain and " " not in plain:
        add(plain)

    return candidates


def extract_targets(seed: str, usernames: list[str]) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = value.strip().strip("\"'")
        if not cleaned:
            return
        lowered = cleaned.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        targets.append(cleaned)

    for email in extract_emails(seed):
        add(email)
    for phone in extract_phone_numbers(seed):
        add(phone)
    for domain in DOMAIN_RE.findall(seed):
        add(domain)
    for ip in IPV4_RE.findall(seed):
        add(ip)
    for url in URL_RE.findall(seed):
        add(url)
    for username in usernames:
        add(username)

    if not targets:
        add(seed)
    return targets


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def int_env(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return max(min_value, min(max_value, value))


def resolve_command(name: str, fallback: list[list[str]]) -> list[str] | None:
    explicit = os.getenv(name, "").strip()
    if explicit:
        return shlex.split(explicit, posix=(os.name != "nt"))

    for command in fallback:
        executable = command[0]
        if os.path.isabs(executable) and os.path.exists(executable):
            return command
        if shutil.which(executable):
            return command
        if executable == sys.executable:
            return command
    return None


def run_command(command: list[str], timeout_seconds: int) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1, timeout_seconds),
            check=False,
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    except Exception as exc:
        return CommandResult(
            returncode=None,
            stdout="",
            stderr=str(exc),
            timed_out=False,
        )


def http_request_json(
    url: str,
    method: str = "GET",
    form: dict[str, str] | None = None,
    timeout: int = 10,
) -> object | None:
    data = None
    headers = {"Accept": "application/json"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=max(1, timeout)) as response:
            body = response.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    return parse_json_payload(body)


def parse_json_payload(text: str) -> dict | list | None:
    payload = text.strip()
    if not payload:
        return None

    candidates = [0]
    for index, char in enumerate(payload):
        if char in "{[":
            candidates.append(index)

    seen: set[int] = set()
    for start in candidates:
        if start in seen:
            continue
        seen.add(start)
        try:
            parsed = json.loads(payload[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, (dict, list)):
            return parsed
    return None


def extract_profile_urls(text: str) -> list[str]:
    urls = []
    seen = set()
    for match in PROFILE_URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,);]")
        if cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        urls.append(cleaned)
    return urls


def is_social_profile(url: str) -> bool:
    try:
        host = canonical_social_host(urllib.parse.urlparse(url).hostname or "")
    except Exception:
        return False
    return host in SOCIAL_HOSTS


def normalize_host(host: str) -> str:
    host = host.lower().strip()
    if host.startswith("www."):
        return host[4:]
    return host


def canonical_social_host(host: str) -> str:
    normalized = normalize_host(host)
    for known in SOCIAL_HOSTS:
        if normalized == known or normalized.endswith("." + known):
            return known
    return normalized


def parse_rate(value: object) -> float:
    if isinstance(value, (int, float)):
        return clamp(float(value), 0.0, 100.0)
    text = str(value or "").strip().replace("%", "")
    try:
        return clamp(float(text), 0.0, 100.0)
    except ValueError:
        return 50.0


def validate_profile_link(url: str, username: str | None, timeout_seconds: int) -> UrlCheck:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return UrlCheck(False, url, None, "invalid scheme")

    host = canonical_social_host(parsed.hostname or "")
    if host not in SOCIAL_HOSTS:
        return UrlCheck(False, url, None, "unsupported host")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    request = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=max(2, timeout_seconds)) as response:
            status = int(getattr(response, "status", 0) or 0)
            final_url = str(getattr(response, "url", "") or response.geturl() or url)
            body = response.read(16000).decode("utf-8", errors="ignore").lower()
    except urllib.error.HTTPError as exc:
        return UrlCheck(False, url, int(exc.code), "http error")
    except urllib.error.URLError as exc:
        reason = str(exc.reason) if getattr(exc, "reason", None) else str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in reason.upper():
            try:
                insecure_context = ssl._create_unverified_context()
                with urllib.request.urlopen(
                    request,
                    timeout=max(2, timeout_seconds),
                    context=insecure_context,
                ) as response:
                    status = int(getattr(response, "status", 0) or 0)
                    final_url = str(getattr(response, "url", "") or response.geturl() or url)
                    body = response.read(16000).decode("utf-8", errors="ignore").lower()
            except urllib.error.HTTPError as retry_exc:
                return UrlCheck(False, url, int(retry_exc.code), "http error")
            except Exception:
                return UrlCheck(False, url, None, "request failed")
        else:
            return UrlCheck(False, url, None, "request failed")
    except Exception:
        return UrlCheck(False, url, None, "request failed")

    if status >= 400 or status < 200:
        return UrlCheck(False, final_url, status, "bad status")

    final = urllib.parse.urlparse(final_url)
    final_host = canonical_social_host(final.hostname or "")
    if final_host not in SOCIAL_HOSTS:
        return UrlCheck(False, final_url, status, "redirected outside social host")

    if contains_negative_profile_text(body):
        return UrlCheck(False, final_url, status, "negative page content")

    if not looks_like_person_profile_path(final_host, final.path, username):
        return UrlCheck(False, final_url, status, "non-profile redirect")

    reason = "direct profile"
    if normalize_url(url) != normalize_url(final_url):
        reason = "redirected to profile"
    return UrlCheck(True, final_url, status, reason)


def contains_negative_profile_text(body: str) -> bool:
    for marker in NEGATIVE_PAGE_TEXT:
        if marker in body:
            return True
    return False


def looks_like_person_profile_path(host: str, path: str, username: str | None) -> bool:
    clean = (path or "/").strip()
    lower = clean.lower()
    if lower in {"/", ""}:
        return False

    segments = [segment for segment in lower.split("/") if segment]
    if not segments:
        return False
    if segments[0] in NON_PROFILE_SEGMENTS:
        return False

    if host in {"x.com", "twitter.com"}:
        if len(segments) == 1 and re.fullmatch(r"[a-z0-9_]{1,15}", segments[0]):
            return True
        return False

    if host == "reddit.com":
        if len(segments) >= 2 and segments[0] in {"u", "user"} and re.fullmatch(r"[a-z0-9_-]{3,30}", segments[1]):
            return True
        return False

    if host == "linkedin.com":
        if len(segments) >= 2 and segments[0] in {"in", "pub"} and re.fullmatch(r"[a-z0-9_%.-]{3,100}", segments[1]):
            return True
        return False

    if host == "tiktok.com":
        if len(segments) == 1 and segments[0].startswith("@") and re.fullmatch(r"@[a-z0-9._]{2,30}", segments[0]):
            return True
        return False

    if host == "youtube.com":
        if len(segments) >= 2 and segments[0] in {"@", "c", "channel", "user"}:
            return True
        if segments[0].startswith("@"):
            return True
        return False

    # github / instagram / facebook and similar: single username-ish segment.
    if len(segments) == 1 and re.fullmatch(r"[a-z0-9._-]{2,64}", segments[0]):
        if username:
            expected = username.lower().lstrip("@")
            candidate = segments[0].lstrip("@")
            if expected and expected not in candidate and candidate not in expected:
                # Keep generic matches if they still look like profile slugs.
                return True
        return True

    if USERNAME_IN_PATH_RE.search(clean):
        return True
    return False


def notice(source_type: str, message: str) -> ConnectorResult:
    return ConnectorResult(
        source_type=source_type,
        source_uri="",
        title="Connector notice",
        snippet=truncate(message, 240),
        confidence=0.20,
    )


def strip_html(value: str) -> str:
    no_tags = re.sub(r"<[^>]+>", "", value)
    return (
        no_tags.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
    )


def dedupe(results: list[ConnectorResult]) -> list[ConnectorResult]:
    deduped: list[ConnectorResult] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in results:
        key = (item.source_type, item.source_uri, item.title, item.snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max(0, max_len - 3)] + "..."


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def normalize_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return value.strip().lower()
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").rstrip("/")
    return f"{parsed.scheme.lower()}://{host}{path}"
