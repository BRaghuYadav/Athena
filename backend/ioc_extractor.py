"""
ioc_extractor.py — Deterministic IOC extraction engine
Regex-based. No LLM needed. Runs instantly.
Handles: hashes, IPs, domains, URLs, file paths, registry keys, emails,
and package@version artifacts.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, List
from urllib.parse import urlparse

FP_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4",
    "169.254.169.254", "224.0.0.1", "10.0.0.1", "192.168.0.1", "192.168.1.1",
}
FP_DOMAINS = {
    "example.com", "google.com", "microsoft.com", "github.com", "twitter.com",
    "facebook.com", "medium.com", "linkedin.com", "sentinelone.com", "virustotal.com",
    "abuse.ch", "cisa.gov", "wikipedia.org", "youtube.com", "apple.com",
    "bleepingcomputer.com",
}

DOMAIN_TLDS = (
    "com|net|org|io|info|biz|top|xyz|site|online|space|pro|dev|app|cloud|tech|ru|cn|tk|ml|"
    "ga|cf|gq|cc|pw|ws|co|me|us|uk|de|fr|it|nl|br|au|ca|eu|tv|club|live|world|link|store|"
    "shop|blog|web|fun|vip|ai|gg|so|ly|to|in|jp|kr"
)
DOMAIN_RE = re.compile(
    rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{DOMAIN_TLDS})\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)
EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
REGISTRY_RE = re.compile(r'HK(?:LM|CU|CR|U|CC)\\[^\s"\'<>()\]]+', re.IGNORECASE)
PACKAGE_RE = re.compile(r'\b(?:@?[a-z0-9._-]+(?:/[a-z0-9._-]+)?)@(?:\^|~)?\d+\.\d+\.\d+\b', re.IGNORECASE)
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

# Windows paths with drive letter or environment variables like %PROGRAMDATA%\wt.exe
WIN_PATH_RE = re.compile(
    r'(?:\b[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\)(?:[^\s\\/:*?"<>|]+\\)*[^\s\\/:*?"<>|]+(?:\.\w{1,8})?',
    re.IGNORECASE,
)
# Linux/macOS paths, including /Library/Caches/... and /tmp/ld.py
NIX_PATH_RE = re.compile(
    r'/(?:tmp|var|etc|opt|usr|home|root|dev|proc|mnt|srv|library|users|private|applications)/[^\s"\'<>()\]]+',
    re.IGNORECASE,
)

# Small context windows used to promote domains and paths that appear in suspicious wording.
DOMAIN_CONTEXT_KEYWORDS = {
    "c2", "command-and-control", "command and control", "beacon", "callback", "exfil",
    "malware", "payload", "backdoor", "ioc", "indicator", "infrastructure", "server",
    "drops", "dropper", "download", "connects", "connected", "stole", "steals",
}
PATH_CONTEXT_KEYWORDS = {
    "drop", "dropped", "writes", "written", "payload", "exec", "execute", "copy",
    "copied", "saved", "persistence", "script", "binary", "malware", "staged",
}


@dataclass
class IOCResult:
    sha256: List[str] = field(default_factory=list)
    sha1: List[str] = field(default_factory=list)
    md5: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    registry: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    packages: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            len(self.sha256) + len(self.sha1) + len(self.md5) + len(self.ips) +
            len(self.domains) + len(self.urls) + len(self.paths) + len(self.registry) +
            len(self.emails) + len(self.packages)
        )

    def to_dict(self):
        d = asdict(self)
        d["total"] = self.total
        return d

    @property
    def is_empty(self) -> bool:
        return self.total == 0


def _dedupe_keep_order(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value is None:
            continue
        cleaned = str(value).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(cleaned)
    return out


def _normalize_text(text: str) -> str:
    clean = text.replace("[.]", ".").replace("(.)", ".")
    clean = clean.replace("hxxp://", "http://").replace("hxxps://", "https://")
    clean = clean.replace("hxxp", "http").replace("hXXp", "http")
    clean = clean.replace("[@]", "@").replace("[: ]//", "://").replace("[: ]", ":")
    clean = clean.replace("\\/", "/")
    return clean


def _is_public_ipv4(ip: str) -> bool:
    if ip in FP_IPS:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
        return isinstance(parsed, ipaddress.IPv4Address) and not (
            parsed.is_private or parsed.is_loopback or parsed.is_multicast or
            parsed.is_unspecified or parsed.is_link_local or parsed.is_reserved
        )
    except ValueError:
        return False


def _sanitize_domain(domain: str) -> str:
    return domain.lower().strip(".,;:'\")]")


def _domain_has_suspicious_context(text: str, domain: str) -> bool:
    lowered = text.lower()
    needle = domain.lower()
    idx = lowered.find(needle)
    while idx != -1:
        window = lowered[max(0, idx - 120): idx + len(needle) + 120]
        if any(keyword in window for keyword in DOMAIN_CONTEXT_KEYWORDS):
            return True
        idx = lowered.find(needle, idx + len(needle))
    return False


def _path_has_suspicious_context(text: str, path: str) -> bool:
    lowered = text.lower()
    needle = path.lower()
    idx = lowered.find(needle)
    while idx != -1:
        window = lowered[max(0, idx - 120): idx + len(needle) + 120]
        if any(keyword in window for keyword in PATH_CONTEXT_KEYWORDS):
            return True
        idx = lowered.find(needle, idx + len(needle))
    return False


def _extract_urls(clean: str) -> List[str]:
    urls = [m.group(0).rstrip('.,;)\"\'') for m in URL_RE.finditer(clean)]
    return _dedupe_keep_order(urls)[:30]


def _extract_domains(clean: str, urls: List[str], email_domains: set[str]) -> List[str]:
    domains: List[str] = []
    # First, recover domains from explicit URLs in order.
    for url in urls:
        host = urlparse(url).hostname
        if host:
            domains.append(_sanitize_domain(host))

    # Then recover standalone domains from the text.
    for match in DOMAIN_RE.finditer(clean):
        domains.append(_sanitize_domain(match.group(0)))

    filtered: List[str] = []
    for domain in _dedupe_keep_order(domains):
        if domain in FP_DOMAINS:
            continue
        if domain in email_domains:
            # Do not treat contact-provider domains as infra unless the article uses them in suspicious context.
            if not _domain_has_suspicious_context(clean, domain):
                continue
        filtered.append(domain)
    return filtered


def _extract_paths(clean: str) -> List[str]:
    candidates: List[str] = []
    for regex in (WIN_PATH_RE, NIX_PATH_RE):
        for match in regex.finditer(clean):
            value = match.group(0).rstrip('.,;)\"]')
            # Avoid collecting bare directories too aggressively unless context looks suspicious.
            candidates.append(value)
    return _dedupe_keep_order(candidates)


def extract_iocs(text: str) -> IOCResult:
    """Extract IOCs from arbitrary text. Handles defanging and keeps stable ordering."""
    clean = _normalize_text(text)
    result = IOCResult()

    result.sha256 = _dedupe_keep_order(m.group(0).lower() for m in SHA256_RE.finditer(clean))

    sha1_candidates = _dedupe_keep_order(m.group(0).lower() for m in SHA1_RE.finditer(clean))
    result.sha1 = [h for h in sha1_candidates if not any(h in s for s in result.sha256)]

    md5_candidates = _dedupe_keep_order(m.group(0).lower() for m in MD5_RE.finditer(clean))
    all_longer = result.sha256 + result.sha1
    result.md5 = [h for h in md5_candidates if not any(h in s for s in all_longer)]

    result.ips = _dedupe_keep_order(ip for ip in IP_RE.findall(clean) if _is_public_ipv4(ip))

    result.emails = _dedupe_keep_order(m.group(0).lower() for m in EMAIL_RE.finditer(clean))
    email_domains = {e.split('@', 1)[1] for e in result.emails if '@' in e}

    result.urls = _extract_urls(clean)
    result.domains = _extract_domains(clean, result.urls, email_domains)

    extracted_paths = _extract_paths(clean)
    # Keep high-value paths even when the model is weak; in suspicious wording, env-var paths are useful.
    result.paths = _dedupe_keep_order(
        p for p in extracted_paths
        if (
            p.startswith('%') or p.startswith('/') or re.match(r'^[A-Za-z]:\\', p) or
            _path_has_suspicious_context(clean, p)
        )
    )

    result.registry = _dedupe_keep_order(m.group(0) for m in REGISTRY_RE.finditer(clean))
    result.packages = _dedupe_keep_order(m.group(0).lower() for m in PACKAGE_RE.finditer(clean))

    return result


def classify_input(text: str) -> str:
    """Classify input as: url, ioc, or nl (natural language)."""
    stripped = text.strip()

    if re.match(r'^https?://', stripped, re.IGNORECASE) and stripped.count('\n') <= 2:
        return "url"

    if re.match(r'^[a-fA-F0-9]{32,64}$', stripped):
        return "ioc"

    iocs = extract_iocs(stripped)
    if iocs.total >= 2:
        return "ioc"

    return "nl"
