from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from ioc_extractor import IOCResult, extract_iocs

DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|top|xyz|site|online|space|pro|dev|app|cloud|tech|ru|cn|tk|ml|ga|cf|gq|cc|pw|ws|co|me|us|uk|de|fr|it|nl|br|au|ca|eu|tv|club|live|world|link|store|shop|blog|web|fun|vip|ai|gg|so|ly|to|in|jp|kr)\b', re.IGNORECASE)

ATTACK_STAGE_RULES = [
    ("Initial Access", ["phish", "malspam", "lure", "compromised package", "supply chain", "npm", "dependency"]),
    ("Execution", ["exec", "execute", "run", "powershell", "python", "vbscript", "osascript", "bash", "sh", "nohup"]),
    ("Persistence", ["persistence", "scheduled task", "run key", "startup", "service", "%programdata%", "copied powershell"]),
    ("Credential Access", ["credential", "cookie", "token", "steal", "login data", "web data"]),
    ("Command and Control", ["c2", "command-and-control", "command and control", "beacon", "callback", "exfil", "domain"]),
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "c2", "command-and-control", "command and control", "beacon", "callback", "ioc", "indicator",
    "malware", "payload", "backdoor", "server", "connect", "communicates", "exfil",
]


@dataclass
class BehaviorCandidate:
    type: str
    confidence: str = "medium"
    rationale: str = ""
    hunt_priority: int = 3
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ArticleAnalysis:
    title: str = ""
    summary: str = ""
    attack_stages: List[str] = field(default_factory=list)
    iocs: IOCResult = field(default_factory=IOCResult)
    behaviors: List[BehaviorCandidate] = field(default_factory=list)
    artifact_priority: List[Dict[str, Any]] = field(default_factory=list)
    supply_chain_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    identity_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_model: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["iocs"] = self.iocs.to_dict()
        return data


def _merge_unique(existing: List[str], incoming: List[str]) -> List[str]:
    seen = set()
    merged: List[str] = []
    for item in existing + incoming:
        if not item:
            continue
        val = str(item).strip()
        if not val:
            continue
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(val)
    return merged


def _normalize_iocs(model_data: Dict[str, Any]) -> IOCResult:
    return IOCResult(
        sha256=[x.lower() for x in model_data.get("sha256", []) if isinstance(x, str)],
        sha1=[x.lower() for x in model_data.get("sha1", []) if isinstance(x, str)],
        md5=[x.lower() for x in model_data.get("md5", []) if isinstance(x, str)],
        ips=[x for x in model_data.get("ips", []) if isinstance(x, str)],
        domains=[x.lower() for x in model_data.get("domains", []) if isinstance(x, str)],
        urls=[x for x in model_data.get("urls", []) if isinstance(x, str)],
        paths=[x for x in model_data.get("paths", []) if isinstance(x, str)],
        registry=[x for x in model_data.get("registry", []) if isinstance(x, str)],
        emails=[x.lower() for x in model_data.get("emails", []) if isinstance(x, str)],
        packages=[x.lower() for x in model_data.get("packages", []) if isinstance(x, str)],
    )


def merge_iocs(regex_iocs: IOCResult, model_data: Dict[str, Any] | None = None) -> IOCResult:
    model_iocs = _normalize_iocs(model_data or {})
    return IOCResult(
        sha256=_merge_unique(regex_iocs.sha256, model_iocs.sha256),
        sha1=_merge_unique(regex_iocs.sha1, model_iocs.sha1),
        md5=_merge_unique(regex_iocs.md5, model_iocs.md5),
        ips=_merge_unique(regex_iocs.ips, model_iocs.ips),
        domains=_merge_unique(regex_iocs.domains, model_iocs.domains),
        urls=_merge_unique(regex_iocs.urls, model_iocs.urls),
        paths=_merge_unique(regex_iocs.paths, model_iocs.paths),
        registry=_merge_unique(regex_iocs.registry, model_iocs.registry),
        emails=_merge_unique(regex_iocs.emails, model_iocs.emails),
        packages=_merge_unique(regex_iocs.packages, model_iocs.packages),
    )


def _extract_supply_chain_artifacts(merged_iocs: IOCResult, model_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for pkg in merged_iocs.packages:
        if "@" not in pkg:
            continue
        name, version = pkg.rsplit("@", 1)
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({
            "type": "package",
            "name": name,
            "version": version,
            "value": pkg,
            "importance": "high",
            "reason": "Package/version artifact extracted from the article; useful for supply-chain hunting and triage.",
        })

    for item in model_data.get("supply_chain_artifacts", []) or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip().lower()
        version = str(item.get("version", "")).strip()
        value = str(item.get("value", f"{name}@{version}" if name and version else name)).strip()
        if not value:
            continue
        key = (name, version or value)
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({
            "type": str(item.get("type", "package")),
            "name": name,
            "version": version,
            "value": value,
            "importance": str(item.get("importance", "high")),
            "reason": str(item.get("reason", "Model-extracted supply-chain artifact.")),
        })

    return artifacts


def _extract_identity_artifacts(merged_iocs: IOCResult, model_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for email in merged_iocs.emails:
        domain = email.split("@", 1)[1] if "@" in email else ""
        if email in seen:
            continue
        seen.add(email)
        artifacts.append({
            "type": "email",
            "value": email,
            "domain": domain,
            "importance": "medium",
            "reason": "Identity/contact artifact extracted from the article. Do not treat as network infrastructure by default.",
        })

    for item in model_data.get("identity_artifacts", []) or []:
        if not isinstance(item, dict) or not item.get("value"):
            continue
        value = str(item.get("value")).strip().lower()
        if value in seen:
            continue
        seen.add(value)
        artifacts.append({
            "type": str(item.get("type", "identity")),
            "value": value,
            "domain": str(item.get("domain", "")).strip().lower(),
            "importance": str(item.get("importance", "medium")),
            "reason": str(item.get("reason", "Identity-related artifact extracted by model.")),
        })

    return artifacts


def _fallback_title(article_text: str, model_data: Dict[str, Any]) -> str:
    title = str(model_data.get("title", "")).strip()
    if title:
        return title

    lines = [ln.strip() for ln in article_text.splitlines() if ln.strip()]
    if not lines:
        return ""

    for line in lines[:8]:
        if len(line) < 15:
            continue
        if line.lower().startswith(("http://", "https://")):
            continue
        if len(line) <= 140:
            return re.sub(r'\s+', ' ', line)
    return re.sub(r'\s+', ' ', lines[0])[:140]


def _fallback_summary(article_text: str, model_data: Dict[str, Any]) -> str:
    summary = str(model_data.get("summary", "")).strip()
    if summary:
        return summary

    compact = re.sub(r'\s+', ' ', article_text).strip()
    if not compact:
        return ""

    sentences = re.split(r'(?<=[.!?])\s+', compact)
    selected = []
    for sentence in sentences:
        s = sentence.strip()
        if 40 <= len(s) <= 260:
            selected.append(s)
        if len(selected) == 2:
            break
    return " ".join(selected)[:400]


def _promote_contextual_domains(article_text: str, merged_iocs: IOCResult) -> IOCResult:
    lowered = article_text.lower()
    promoted = list(merged_iocs.domains)
    domain_matches = [m.group(0) for m in DOMAIN_RE.finditer(article_text)]
    path_basenames = {p.rsplit('/', 1)[-1].rsplit('\\', 1)[-1].lower() for p in merged_iocs.paths}
    for domain in domain_matches:
        d = domain.lower().strip('.,;:')
        if d in path_basenames:
            continue
        if d in promoted:
            continue
        idx = lowered.find(d)
        if idx == -1:
            continue
        window = lowered[max(0, idx - 120): idx + len(d) + 120]
        if any(keyword in window for keyword in SUSPICIOUS_DOMAIN_KEYWORDS):
            promoted.append(d)
    merged_iocs.domains = _merge_unique([], promoted)
    return merged_iocs


def _infer_attack_stages(article_text: str, model_data: Dict[str, Any]) -> List[str]:
    stages = [str(x) for x in model_data.get("attack_stages", []) if isinstance(x, str) and str(x).strip()]
    lowered = article_text.lower()
    for stage, keywords in ATTACK_STAGE_RULES:
        if stage in stages:
            continue
        if any(keyword in lowered for keyword in keywords):
            stages.append(stage)
    return stages


def _build_artifact_priority(merged_iocs: IOCResult, supply_chain_artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    priority: List[Dict[str, Any]] = []

    for item in supply_chain_artifacts:
        priority.append({
            "type": "package",
            "value": item["value"],
            "importance": "high",
            "reason": "Named package/version artifact directly supports supply-chain scoping and triage.",
        })

    for path in merged_iocs.paths[:8]:
        importance = "high" if path.startswith('%') or '/tmp/' in path.lower() or '/library/caches/' in path.lower() else "medium"
        priority.append({
            "type": "path",
            "value": path,
            "importance": importance,
            "reason": "Execution or staging path useful for host-level confirmation and pivots.",
        })

    for domain in merged_iocs.domains[:8]:
        priority.append({
            "type": "domain",
            "value": domain,
            "importance": "high",
            "reason": "Potential infrastructure indicator recovered from the article text.",
        })

    for email in merged_iocs.emails[:5]:
        priority.append({
            "type": "email",
            "value": email,
            "importance": "medium",
            "reason": "Identity/contact artifact; useful for context but not network hunting by default.",
        })

    # Deduplicate by type/value while keeping order.
    seen = set()
    deduped = []
    for item in priority:
        key = (item.get("type"), str(item.get("value", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def normalize_analysis(article_text: str, model_data: Dict[str, Any] | None = None) -> ArticleAnalysis:
    regex_iocs = extract_iocs(article_text)
    model_data = model_data or {}
    merged_iocs = merge_iocs(regex_iocs, model_data)
    merged_iocs = _promote_contextual_domains(article_text, merged_iocs)

    behaviors: List[BehaviorCandidate] = []
    for item in model_data.get("behaviors", []) or []:
        if not isinstance(item, dict) or not item.get("type"):
            continue
        behaviors.append(
            BehaviorCandidate(
                type=str(item.get("type")),
                confidence=str(item.get("confidence", "medium")),
                rationale=str(item.get("rationale", "")),
                hunt_priority=int(item.get("hunt_priority", 3)),
                evidence=item.get("evidence", {}) if isinstance(item.get("evidence", {}), dict) else {},
            )
        )

    supply_chain_artifacts = _extract_supply_chain_artifacts(merged_iocs, model_data)
    identity_artifacts = _extract_identity_artifacts(merged_iocs, model_data)
    artifact_priority = _build_artifact_priority(merged_iocs, supply_chain_artifacts)

    warnings = []
    if merged_iocs.is_empty and not behaviors:
        warnings.append("No strong artifacts or behaviors extracted; article may be too generic.")
    if not str(model_data.get("title", "")).strip() and not str(model_data.get("summary", "")).strip():
        warnings.append("Model article analysis was sparse; heuristic fallback enriched the result.")

    return ArticleAnalysis(
        title=_fallback_title(article_text, model_data),
        summary=_fallback_summary(article_text, model_data),
        attack_stages=_infer_attack_stages(article_text, model_data),
        iocs=merged_iocs,
        behaviors=sorted(behaviors, key=lambda x: x.hunt_priority),
        artifact_priority=artifact_priority,
        supply_chain_artifacts=supply_chain_artifacts,
        identity_artifacts=identity_artifacts,
        warnings=warnings,
        raw_model=model_data,
    )
