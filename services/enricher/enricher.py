from __future__ import annotations

import json
import os
import ipaddress
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from connectors import run_public_connectors


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
HANDLE_RE = re.compile(r"(?<!\w)@[A-Z0-9_]{3,30}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d .()/-]{7,}\d)(?!\d)")
DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)
TOKEN_RE = re.compile(r"[A-Z]{3,}|\d{3,}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
HASHTAG_RE = re.compile(r"(?<!\w)#[A-Z0-9_]{2,60}\b", re.IGNORECASE)
USERNAME_RE = re.compile(r"^[A-Z0-9](?:[A-Z0-9._-]{1,62}[A-Z0-9])?$", re.IGNORECASE)
CRYPTO_PATTERNS = [
    ("btc_address", re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("eth_address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
]
COMMON_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}
SOCIAL_HOSTS = {
    "github.com",
    "gitlab.com",
    "reddit.com",
    "x.com",
    "twitter.com",
    "instagram.com",
    "tiktok.com",
    "youtube.com",
    "linkedin.com",
    "medium.com",
}
ACCOUNT_PLATFORMS = {
    "github": "https://github.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "facebook": "https://www.facebook.com/{username}",
    "linkedin": "https://www.linkedin.com/in/{username}/",
}
LINK_IDENTIFIER_KINDS = {"url"}


def identifier(kind: str, value: str, confidence: float, source: str = "seed") -> dict:
    return {
        "kind": kind,
        "value": value,
        "confidence": confidence,
        "source": source,
    }


def add_unique(values: list[dict], seen: set[tuple[str, str]], kind: str, value: str, confidence: float,
               source: str = "seed") -> None:
    normalized = value.strip().rstrip(".,;)")
    key = (kind, normalized.lower())
    if normalized and key not in seen:
        seen.add(key)
        values.append(identifier(kind, normalized, confidence, source))


def local_part_candidates(local_part: str, domain: str) -> list[tuple[str, str, float, str]]:
    candidates: list[tuple[str, str, float, str]] = []
    base = local_part.split("+", 1)[0]
    if base:
        candidates.append(("email_local_part", local_part, 0.70, "derived:email"))
        candidates.append(("username_candidate", base, 0.62, "derived:email_local_part"))

    if "+" in local_part:
        tag = local_part.split("+", 1)[1]
        if tag:
            candidates.append(("email_plus_tag", tag, 0.46, "derived:email"))

    if domain.lower() in {"gmail.com", "googlemail.com"} and "." in base:
        gmail_base = base.replace(".", "")
        candidates.append(("username_candidate", gmail_base, 0.58, "derived:gmail_normalization"))

    for token in TOKEN_RE.findall(base):
        candidates.append(("keyword_candidate", token, 0.34, "derived:email_local_part"))

    return candidates


def domain_parts(domain: str) -> list[tuple[str, str, float, str]]:
    cleaned = domain.lower().strip(".")
    labels = [label for label in cleaned.split(".") if label]
    candidates: list[tuple[str, str, float, str]] = []
    if len(labels) >= 2:
        candidates.append(("tld", labels[-1], 0.42, "derived:domain"))
        candidates.append(("root_domain", ".".join(labels[-2:]), 0.58, "derived:domain"))
    if len(labels) > 2:
        candidates.append(("subdomain", ".".join(labels[:-2]), 0.52, "derived:domain"))
    return candidates


def url_candidates(url: str) -> list[tuple[str, str, float, str]]:
    parsed = urlparse(url)
    candidates: list[tuple[str, str, float, str]] = []
    if parsed.scheme:
        candidates.append(("url_scheme", parsed.scheme, 0.40, "derived:url"))
    if parsed.hostname:
        candidates.append(("domain", parsed.hostname, 0.70, "derived:url"))
        candidates.extend(domain_parts(parsed.hostname))
    if parsed.path and parsed.path != "/":
        candidates.append(("url_path", parsed.path, 0.48, "derived:url"))
        segments = [segment for segment in parsed.path.split("/") if segment]
        if parsed.hostname and normalized_host(parsed.hostname) in SOCIAL_HOSTS and segments:
            username = segments[0].lstrip("@")
            if USERNAME_RE.match(username):
                candidates.append(("username_candidate", username, 0.60, "derived:social_url"))
    return candidates


def normalized_host(host: str) -> str:
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def account_candidates(username: str, source: str) -> list[tuple[str, str, float, str]]:
    cleaned = username.strip().lstrip("@")
    if not USERNAME_RE.match(cleaned):
        return []
    candidates: list[tuple[str, str, float, str]] = []
    for platform, template in ACCOUNT_PLATFORMS.items():
        candidates.append((
            "account_url_candidate",
            template.format(username=cleaned),
            0.30,
            f"candidate:{platform}:{source}",
        ))
    return candidates


def ip_candidates(value: str) -> list[tuple[str, str, float, str]]:
    address = ipaddress.ip_address(value)
    scope = "private" if address.is_private else "public"
    if address.is_loopback:
        scope = "loopback"
    elif address.is_multicast:
        scope = "multicast"
    elif address.is_reserved:
        scope = "reserved"

    return [
        ("ip_address", value, 0.82, "seed"),
        ("ip_version", f"IPv{address.version}", 0.62, "derived:ip"),
        ("ip_scope", scope, 0.56, "derived:ip"),
        ("reverse_dns_candidate", address.reverse_pointer, 0.34, "derived:ip"),
    ]


def phone_candidates(phone: str) -> list[tuple[str, str, float, str]]:
    digits = re.sub(r"\D", "", phone)
    candidates = [("phone_digits", digits, 0.50, "derived:phone")]
    if phone.strip().startswith("+") and len(digits) >= 8:
        code = digits[:1] if digits.startswith("1") else digits[:3]
        candidates.append(("phone_country_code_candidate", code, 0.28, "derived:phone"))
    if len(digits) >= 10:
        candidates.append(("phone_last4", digits[-4:], 0.24, "derived:phone"))
    return candidates


def name_like_candidates(seed: str) -> list[tuple[str, str, float, str]]:
    if any(pattern.search(seed) for pattern in [EMAIL_RE, URL_RE, HANDLE_RE, PHONE_RE, DOMAIN_RE, IPV4_RE]):
        return []
    words = [word for word in re.split(r"\s+", seed.strip()) if word]
    if not 2 <= len(words) <= 5:
        return []
    if not all(re.match(r"^[A-Za-z][A-Za-z'.-]{1,40}$", word) for word in words):
        return []
    full_name = " ".join(words)
    candidates = [("name_candidate", full_name, 0.36, "derived:free_text")]
    candidates.append(("quoted_name_search", f'"{full_name}"', 0.30, "derived:name_candidate"))
    if len(words) >= 2:
        candidates.append(("initial_last_candidate", f"{words[0][0]}{words[-1]}", 0.24, "derived:name_candidate"))
    return candidates


def suggested_search(query: str, reason: str) -> dict:
    return {
        "query": query,
        "status": "suggested",
        "resultCount": 0,
        "reason": reason,
    }


def build_suggested_searches(identifiers: list[dict]) -> list[dict]:
    searches: list[dict] = []
    seen: set[str] = set()

    def add(query: str, reason: str) -> None:
        normalized = query.strip()
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            searches.append(suggested_search(normalized, reason))

    for item in identifiers:
        kind = item["kind"]
        value = item["value"]
        if kind == "email":
            local, domain = value.split("@", 1)
            add(f'"{value}"', "exact email lookup")
            add(f'"{local}"', "username/local-part pivot")
            add(f'"{local}" "{domain}"', "email local-part and domain pivot")
        elif kind in {"username_candidate", "handle"}:
            username = value[1:] if value.startswith("@") else value
            add(f'"{username}"', "exact username candidate lookup")
            add(f'site:github.com "{username}"', "GitHub username pivot")
            add(f'site:instagram.com "{username}"', "Instagram username pivot")
            add(f'site:facebook.com "{username}"', "Facebook username pivot")
            add(f'site:linkedin.com/in "{username}"', "LinkedIn profile slug pivot")
            add(f'site:reddit.com "{username}"', "Reddit username pivot")
            add(f'site:x.com "{username}"', "X/Twitter username pivot")
        elif kind == "account_url_candidate":
            add(f'"{value}"', "candidate social/profile URL review")
        elif kind == "domain":
            add(f'"{value}"', "domain pivot")
            add(f'site:{value}', "site-restricted domain search")
            add(f'"@{value}"', "email address domain pivot")
        elif kind == "root_domain":
            add(f'"{value}"', "root domain pivot")
        elif kind == "ip_address":
            add(f'"{value}"', "exact IP lookup")
            add(f'"{value}" "whois"', "IP ownership pivot")
        elif kind == "phone":
            add(f'"{value}"', "exact phone lookup")
        elif kind == "url":
            add(f'"{value}"', "exact URL lookup")
        elif kind in {"btc_address", "eth_address"}:
            add(f'"{value}"', "exact crypto address lookup")
        elif kind in {"name_candidate", "quoted_name_search"}:
            add(value if value.startswith('"') else f'"{value}"', "exact name candidate lookup")
        elif kind == "hashtag":
            add(value, "hashtag pivot")

    return searches


def build_correlation_keys(seed: str, identifiers: list[dict]) -> dict:
    email_keys: set[str] = set()
    username_keys: set[str] = set()
    domain_keys: set[str] = set()

    def add_username(value: str) -> None:
        candidate = value.strip().lstrip("@").lower()
        if not candidate:
            return
        if USERNAME_RE.match(candidate):
            username_keys.add(candidate)

    def add_domain(value: str) -> None:
        candidate = value.strip().strip(".").lower()
        if candidate and "." in candidate:
            domain_keys.add(candidate)

    for item in identifiers:
        kind = str(item.get("kind", "")).strip()
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        if kind == "email":
            lowered = value.lower()
            email_keys.add(lowered)
            if "@" in lowered:
                local, domain = lowered.split("@", 1)
                add_username(local.split("+", 1)[0])
                add_domain(domain)
            continue
        if kind in {"username_candidate", "handle", "email_local_part"}:
            add_username(value)
            continue
        if kind in {"domain", "root_domain", "email_provider"}:
            add_domain(value)
            continue
        if kind == "url":
            try:
                parsed = urlparse(value)
            except Exception:
                continue
            if parsed.hostname:
                host = normalized_host(parsed.hostname)
                add_domain(host)
                if host in SOCIAL_HOSTS:
                    segment = parsed.path.strip("/").split("/", 1)[0].lstrip("@")
                    add_username(segment)
            continue
        if kind == "account_url_candidate":
            try:
                parsed = urlparse(value)
            except Exception:
                continue
            host = normalized_host(parsed.hostname or "")
            if host in SOCIAL_HOSTS:
                segment = parsed.path.strip("/").split("/", 1)[0].lstrip("@")
                add_username(segment)

    for email in EMAIL_RE.findall(seed):
        normalized_email = email.lower()
        email_keys.add(normalized_email)
        if "@" in normalized_email:
            local, domain = normalized_email.split("@", 1)
            add_username(local.split("+", 1)[0])
            add_domain(domain)
    for domain in DOMAIN_RE.findall(seed):
        add_domain(domain)
    for handle in HANDLE_RE.findall(seed):
        add_username(handle[1:])

    return {
        "email": sorted(email_keys),
        "username": sorted(username_keys),
        "domain": sorted(domain_keys),
    }


def extract_identifiers(seed: str) -> list[dict]:
    values: list[dict] = []
    seen: set[tuple[str, str]] = set()
    protected_spans = [
        match.span()
        for _, pattern in CRYPTO_PATTERNS
        for match in pattern.finditer(seed)
    ]

    def add(kind: str, value: str, confidence: float) -> None:
        add_unique(values, seen, kind, value, confidence)

    def overlaps_protected(span: tuple[int, int]) -> bool:
        return any(span[0] < protected[1] and protected[0] < span[1] for protected in protected_spans)

    for email in EMAIL_RE.findall(seed):
        add("email", email, 0.88)
        local_part, domain = email.split("@", 1)
        add("domain", domain, 0.72)
        for kind, value, confidence, source in domain_parts(domain):
            add_unique(values, seen, kind, value, confidence, source)
        if domain.lower() in COMMON_PROVIDERS:
            add_unique(values, seen, "email_provider", domain, 0.52, "derived:email_domain")
        for kind, value, confidence, source in local_part_candidates(local_part, domain):
            add_unique(values, seen, kind, value, confidence, source)
            if kind == "username_candidate":
                for account_kind, account_value, account_confidence, account_source in account_candidates(value, source):
                    add_unique(values, seen, account_kind, account_value, account_confidence, account_source)

    for url in URL_RE.findall(seed):
        cleaned = url.rstrip(".,;)")
        add("url", cleaned, 0.82)
        for kind, value, confidence, source in url_candidates(cleaned):
            add_unique(values, seen, kind, value, confidence, source)

    for handle in HANDLE_RE.findall(seed):
        add("handle", handle, 0.64)
        add_unique(values, seen, "username_candidate", handle[1:], 0.56, "derived:handle")
        for kind, value, confidence, source in account_candidates(handle, "handle"):
            add_unique(values, seen, kind, value, confidence, source)

    for hashtag in HASHTAG_RE.findall(seed):
        add("hashtag", hashtag, 0.48)

    for match in PHONE_RE.finditer(seed):
        if overlaps_protected(match.span()):
            continue
        phone = match.group(0)
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 8:
            add("phone", phone, 0.58)
            for kind, value, confidence, source in phone_candidates(phone):
                add_unique(values, seen, kind, value, confidence, source)

    for domain in DOMAIN_RE.findall(seed):
        if "@" not in domain:
            add("domain", domain, 0.60)
            for kind, value, confidence, source in domain_parts(domain):
                add_unique(values, seen, kind, value, confidence, source)

    for ip in IPV4_RE.findall(seed):
        try:
            for kind, value, confidence, source in ip_candidates(ip):
                add_unique(values, seen, kind, value, confidence, source)
        except ValueError:
            continue

    for kind, pattern in CRYPTO_PATTERNS:
        for match in pattern.finditer(seed):
            add(kind, match.group(0), 0.74)

    stripped = seed.strip()
    if not values and USERNAME_RE.match(stripped) and "." not in stripped:
        add_unique(values, seen, "username_candidate", stripped, 0.48, "seed")
        for kind, value, confidence, source in account_candidates(stripped, "username_seed"):
            add_unique(values, seen, kind, value, confidence, source)
        for token in TOKEN_RE.findall(stripped):
            add_unique(values, seen, "keyword_candidate", token, 0.28, "derived:username_candidate")

    for kind, value, confidence, source in name_like_candidates(seed):
        add_unique(values, seen, kind, value, confidence, source)

    if not values:
        add("free_text", seed.strip(), 0.35)

    return values


def link_identifiers(identifiers: list[dict], evidence: list[dict]) -> list[dict]:
    links: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, value: str, confidence: float, source: str) -> None:
        normalized = value.strip().rstrip(".,;)")
        lowered = normalized.lower()
        if not normalized or not lowered.startswith(("http://", "https://")):
            return
        if lowered in seen:
            return
        seen.add(lowered)
        links.append(identifier(kind, normalized, confidence, source))

    for item in identifiers:
        kind = str(item.get("kind", ""))
        value = str(item.get("value", ""))
        if kind not in LINK_IDENTIFIER_KINDS:
            continue
        add("seed_link", value, float(item.get("confidence", 0.0) or 0.0), str(item.get("source", "seed")))

    for item in evidence:
        source_uri = str(item.get("source_uri", "")).strip()
        source_type = str(item.get("source_type", ""))
        if not source_uri or source_type == "seed":
            continue
        add(
            "verified_profile_link",
            source_uri,
            float(item.get("confidence", 0.0) or 0.0),
            f"found:{source_type}",
        )

    return links


def enrich(seed: str) -> dict:
    evidence = [result.__dict__ for result in run_public_connectors(seed)]
    extracted = extract_identifiers(seed)
    identifiers = link_identifiers(extracted, evidence)
    searches = build_suggested_searches(extracted)
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
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/enrich":
            self.send_error(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body) if body else {}
            seed = str(payload.get("seed", "")).strip()
            if not seed:
                raise ValueError("seed is required")
            self.send_json(200, enrich(seed))
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
    host = os.getenv("OSINT_ENRICHER_HOST", "127.0.0.1")
    port = int(os.getenv("OSINT_ENRICHER_PORT", "8091"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Enrichment service listening on http://{host}:{port}/enrich")
    server.serve_forever()
