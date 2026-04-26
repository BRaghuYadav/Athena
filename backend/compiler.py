"""
compiler.py — Deterministic S1QL compiler.
The LLM proposes intent/behaviors; this module owns the final query shape.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ioc_extractor import IOCResult


def _quote_list(values: List[str]) -> str:
    vals = [str(v) for v in values if v]
    return ", ".join(f'"{v}"' for v in vals)


def _obj_field(obj: Any, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def compile_ioc_query(iocs: IOCResult) -> Dict[str, Any]:
    conditions: List[str] = []
    columns = [
        "event.time", "endpoint.name", "event.category", "event.type",
        "src.process.name", "src.process.cmdline", "src.process.parent.name",
        "tgt.file.path", "dst.ip.address", "url.address", "event.dns.request",
        "src.process.storyline.id"
    ]

    if iocs.sha256:
        conditions.append(f"src.process.image.sha256 in ({_quote_list(iocs.sha256)})")
    if iocs.sha1:
        conditions.append(f"src.process.image.sha1 in ({_quote_list(iocs.sha1)})")
    if iocs.md5:
        conditions.append(f"src.process.image.md5 in ({_quote_list(iocs.md5)})")
    if iocs.ips:
        conditions.append(f"dst.ip.address in ({_quote_list(iocs.ips)})")
    if iocs.domains:
        domain_values = _quote_list(iocs.domains)
        conditions.append(f"(event.dns.request in:anycase ({domain_values}) OR url.address contains:anycase ({domain_values}))")
    if iocs.urls:
        conditions.append(f"url.address in:anycase ({_quote_list(iocs.urls)})")
    if iocs.paths:
        path_values = _quote_list(iocs.paths)
        conditions.append(f"(tgt.file.path contains:anycase ({path_values}) OR src.process.image.path contains:anycase ({path_values}))")
    if iocs.registry:
        conditions.append(f"registry.keyPath contains:anycase ({_quote_list(iocs.registry)})")

    if not conditions:
        return {
            "query": "",
            "severity": "LOW",
            "explanation": "No usable IOCs were extracted.",
            "mitre": [],
            "notes": ["Provide a hash, domain, IP, path, or registry key."],
            "warnings": ["IOC pack was empty."],
            "pack_type": "ioc_confirmation",
            "expected_signal": "low",
        }

    query = "(\n    " + "\n    OR ".join(conditions) + "\n)\n"
    query += "| columns " + ", ".join(columns) + "\n| sort -event.time\n| limit 500"

    warnings = []
    if iocs.domains and not (iocs.sha256 or iocs.paths or iocs.packages):
        warnings.append("Domain-only hunts can be noisy; prefer behavioral pivots if available.")
    if iocs.ips and not (iocs.sha256 or iocs.paths or iocs.registry):
        warnings.append("IP-only hunts can drift quickly and should be used as confirmation.")

    return {
        "query": query,
        "severity": "MEDIUM" if warnings else "HIGH",
        "explanation": "IOC confirmation hunt compiled deterministically from extracted indicators.",
        "mitre": [],
        "notes": ["Use storyline.id to pivot from an IOC hit into process and file activity."],
        "warnings": warnings,
        "pack_type": "ioc_confirmation",
        "expected_signal": "medium" if warnings else "high",
        "why": "Confirms whether known report indicators appear in the estate.",
        "false_positive_caution": warnings[0] if warnings else "Low when combined with behavior or file context.",
    }


def compile_supply_chain_query(supply_chain_artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    package_terms = [a.get("value") or a.get("name") for a in supply_chain_artifacts if isinstance(a, dict)]
    package_terms = [p for p in package_terms if p]
    if not package_terms:
        return {
            "query": "",
            "severity": "LOW",
            "explanation": "No package artifacts were extracted.",
            "mitre": [],
            "notes": [],
            "warnings": ["Supply-chain pack was empty."],
            "pack_type": "supply_chain_confirmation",
            "expected_signal": "low",
        }

    query = (
        'event.category = "process"\n'
        'AND event.type in:matchcase ("Process Creation")\n'
        'AND src.process.parent.name in:anycase ("npm", "node", "yarn", "pnpm", "pip", "python", "python3")\n'
        f'AND src.process.cmdline contains:anycase ({_quote_list(package_terms[:10])})\n'
        '| columns event.time, endpoint.name, src.process.parent.name, src.process.name, src.process.cmdline, src.process.user, src.process.storyline.id\n'
        '| sort -event.time\n| limit 300'
    )
    return {
        "query": query,
        "severity": "HIGH",
        "explanation": "Supply-chain confirmation hunt compiled from extracted package/version artifacts.",
        "mitre": [],
        "notes": ["Especially useful when the report names malicious package versions or dependencies."],
        "warnings": [],
        "pack_type": "supply_chain_confirmation",
        "expected_signal": "high",
        "why": "Looks for package-manager executions whose command line references named malicious packages or versions.",
        "false_positive_caution": "Developer and CI endpoints may legitimately reference packages; verify child process and storyline context.",
    }


def compile_star_rule(iocs: IOCResult) -> str:
    conditions = []
    if iocs.sha256:
        conditions.append(f"ImageSha256 in ({_quote_list(iocs.sha256)})")
    if iocs.ips:
        conditions.append(f"DstIP in ({_quote_list(iocs.ips)})")
    if iocs.domains:
        conditions.append(f"DnsRequest in ({_quote_list(iocs.domains)})")
    if not conditions:
        return ""
    return "IF " + " OR ".join(conditions) + " THEN Alert('Imported threat indicators')"


def compile_behavior_query(behavior: Any, iocs: IOCResult | None = None) -> Dict[str, Any]:
    btype = _obj_field(behavior, "type")
    evidence = _obj_field(behavior, "evidence", {}) or {}
    rationale = _obj_field(behavior, "rationale", "")
    confidence = _obj_field(behavior, "confidence", "medium")

    templates: Dict[str, Dict[str, str]] = {
        "package_manager_spawn": {
            "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.parent.name in:anycase ("npm", "node", "yarn", "pnpm", "pip", "python", "python3")\nAND src.process.name in:anycase ("bash", "sh", "python", "python3", "node", "powershell", "cmd")\n| columns event.time, endpoint.name, src.process.parent.name, src.process.name, src.process.cmdline, src.process.user, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Find package-manager-driven or dependency-driven child execution chains.",
            "signal": "high",
            "caution": "Build servers and developer endpoints may have legitimate package activity.",
        },
        "suspicious_interpreter_chain": {
            "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.parent.name in:anycase ("node", "npm", "python", "python3", "wscript", "cscript", "powershell", "cmd", "osascript")\nAND src.process.name in:anycase ("bash", "sh", "python", "python3", "powershell", "cmd", "curl", "wget", "osascript")\n| columns event.time, endpoint.name, src.process.parent.name, src.process.name, src.process.cmdline, src.process.user, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Hunts for interpreter-to-interpreter or script-driven execution chains.",
            "signal": "high",
            "caution": "Some automation tooling may trigger on IT/admin endpoints.",
        },
        "scheduled_task_persistence": {
            "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.name in:anycase ("schtasks.exe")\n| columns event.time, endpoint.name, src.process.name, src.process.cmdline, src.process.user, src.process.parent.name, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Detects scheduled task creation or modification used for persistence.",
            "signal": "high",
            "caution": "Legitimate software updaters can create tasks; review the task name and parent process.",
        },
        "runkey_persistence": {
            "query": 'event.category = "registry"\nAND registry.keyPath contains:anycase ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")\n| columns event.time, endpoint.name, registry.keyPath, registry.valueName, registry.valueData, src.process.name, src.process.cmdline, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Detects Run/RunOnce persistence writes.",
            "signal": "high",
            "caution": "Common enterprise software can also set Run keys.",
        },
        "service_creation": {
            "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.name in:anycase ("sc.exe")\nAND src.process.cmdline contains:anycase (" create ", " start=", " binPath=")\n| columns event.time, endpoint.name, src.process.name, src.process.cmdline, src.process.user, src.process.parent.name, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Detects likely malicious service creation patterns.",
            "signal": "high",
            "caution": "Expected during software installation or endpoint management actions.",
        },
        "lolbin_proxy_execution": {
            "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.name in:anycase ("rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "installutil.exe")\n| columns event.time, endpoint.name, src.process.name, src.process.cmdline, src.process.parent.name, src.process.user, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Finds common signed binary proxy execution patterns.",
            "signal": "high",
            "caution": "Review command-line arguments to separate admin use from malicious use.",
        },
        "browser_credential_access": {
            "query": 'event.category = "file"\nAND tgt.file.path contains:anycase ("Login Data", "Cookies", "Web Data")\n| columns event.time, endpoint.name, tgt.file.path, src.process.name, src.process.parent.name, src.process.user, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Looks for access to browser credential and cookie stores.",
            "signal": "medium",
            "caution": "Browser updates and sync software can touch these paths.",
        },
        "file_drop_and_execute": {
            "query": 'event.category in ("file", "process")\nAND (tgt.file.path contains:anycase ("\\AppData\\", "\\Temp\\", "/tmp/", "/library/caches/") OR src.process.image.path contains:anycase ("\\AppData\\", "\\Temp\\", "/tmp/", "/library/caches/"))\n| columns event.time, endpoint.name, event.category, src.process.name, src.process.image.path, tgt.file.path, src.process.parent.name, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Captures temp/AppData/cache staging and likely follow-on execution.",
            "signal": "medium",
            "caution": "Installers and self-updaters may also stage here.",
        },
        "suspicious_network_beacon": {
            "query": 'event.category = "network"\nAND event.network.direction = "OUTGOING"\n| columns event.time, endpoint.name, src.process.name, src.process.cmdline, dst.ip.address, dst.port.number, url.address, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "Starting point for outbound beacon review when report network details are weak or rotating.",
            "signal": "low",
            "caution": "Broad network hunts are noisy; narrow with process, domain, or port as soon as possible.",
        },
        "registry_modification": {
            "query": 'event.category = "registry"\n| columns event.time, endpoint.name, registry.keyPath, registry.valueName, registry.valueData, src.process.name, src.process.cmdline, src.process.storyline.id\n| sort -event.time\n| limit 300',
            "why": "General registry modification pivot when the report mentions registry tampering.",
            "signal": "low",
            "caution": "Use article-specific registry values if available.",
        },
    }

    template = templates.get(btype)
    if not template:
        return {
            "query": "",
            "severity": "LOW",
            "explanation": f"No deterministic template exists yet for behavior '{btype}'.",
            "mitre": [],
            "notes": [],
            "warnings": [f"Unsupported behavior type: {btype}"],
            "pack_type": "behavior_primary",
            "expected_signal": "low",
        }

    query = template["query"]
    if evidence.get("parent") and evidence.get("child"):
        parent = str(evidence["parent"])
        child = str(evidence["child"])
        query = (
            'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\n'
            f'AND src.process.parent.name in:anycase ("{parent}")\n'
            f'AND src.process.name in:anycase ("{child}")\n'
            '| columns event.time, endpoint.name, src.process.parent.name, src.process.name, src.process.cmdline, src.process.user, src.process.storyline.id\n'
            '| sort -event.time\n| limit 300'
        )

    if evidence.get("packages") and btype == "package_manager_spawn":
        packages = [p for p in evidence.get("packages", []) if p]
        if packages:
            query = query.replace('| columns', f'AND src.process.cmdline contains:anycase ({_quote_list(packages[:10])})\n| columns', 1)

    if evidence.get("path"):
        path = str(evidence["path"])
        query = query.replace('| columns', f'AND (tgt.file.path contains:anycase ("{path}") OR src.process.image.path contains:anycase ("{path}"))\n| columns', 1)
    elif evidence.get("paths"):
        paths = [p for p in evidence.get("paths", []) if p]
        if paths:
            query = query.replace('| columns', f'AND (tgt.file.path contains:anycase ({_quote_list(paths[:8])}) OR src.process.image.path contains:anycase ({_quote_list(paths[:8])}))\n| columns', 1)
    elif evidence.get("filename"):
        filename = str(evidence["filename"])
        query = query.replace('| columns', f'AND (tgt.file.path contains:anycase ("{filename}") OR src.process.cmdline contains:anycase ("{filename}"))\n| columns', 1)

    if btype == "suspicious_network_beacon" and iocs and (iocs.domains or iocs.ips):
        narrowing = []
        if iocs.ips:
            narrowing.append(f'dst.ip.address in ({_quote_list(iocs.ips[:10])})')
        if iocs.domains:
            narrowing.append(f'url.address contains:anycase ({_quote_list(iocs.domains[:10])})')
        query = query.replace('| columns', 'AND (' + ' OR '.join(narrowing) + ')\n| columns', 1)

    severity = "HIGH" if template["signal"] == "high" else "MEDIUM"
    if confidence == "low":
        severity = "MEDIUM"

    return {
        "query": query,
        "severity": severity,
        "explanation": rationale or template["why"],
        "mitre": [],
        "notes": ["Behavior-first hunt compiled from mapped behavior class."],
        "warnings": [],
        "pack_type": "behavior_primary",
        "expected_signal": template["signal"],
        "why": template["why"],
        "false_positive_caution": template["caution"],
        "behavior_type": btype,
    }


def rank_query_pack(hunts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    signal_score = {"high": 3, "medium": 2, "low": 1}
    severity_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return sorted(
        hunts,
        key=lambda h: (
            signal_score.get(h.get("expected_signal", "low"), 1),
            severity_score.get(h.get("severity", "LOW"), 1),
            h.get("confidence", 0.0),
        ),
        reverse=True,
    )


def compile_intent_to_s1ql(intent: Dict[str, Any], library: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    category = intent.get("category", "process")
    platform = intent.get("platform", "all")
    filters = intent.get("filters", {})
    conditions = [f'event.category = "{category}"']
    columns = ["event.time", "endpoint.name", "src.process.name", "src.process.cmdline", "src.process.parent.name", "src.process.user"]

    if platform != "all":
        conditions.append(f'endpoint.os = "{platform}"')

    if category == "network":
        columns = ["event.time", "endpoint.name", "src.process.name", "src.process.cmdline", "dst.ip.address", "dst.port.number", "url.address", "src.process.storyline.id"]
    elif category == "registry":
        columns = ["event.time", "endpoint.name", "registry.keyPath", "registry.valueName", "registry.valueData", "src.process.name", "src.process.storyline.id"]

    if filters.get("process_name"):
        conditions.append(f"src.process.name in:anycase ({_quote_list(filters['process_name'])})")
    if filters.get("path_contains"):
        conditions.append(f"src.process.image.path contains:anycase ({_quote_list(filters['path_contains'])})")
    if filters.get("cmdline_contains"):
        conditions.append(f"src.process.cmdline contains:anycase ({_quote_list(filters['cmdline_contains'])})")
    if filters.get("signed_status") and filters["signed_status"] != "any":
        conditions.append(f'src.process.signedStatus = "{filters["signed_status"]}"')
        columns.append("src.process.signedStatus")
    if filters.get("parent_process"):
        conditions.append(f"src.process.parent.name in:anycase ({_quote_list(filters['parent_process'])})")
    if filters.get("dst_port"):
        conditions.append("dst.port.number IN (" + ", ".join(str(p) for p in filters["dst_port"]) + ")")
    if filters.get("dst_ip"):
        conditions.append(f"dst.ip.address in ({_quote_list(filters['dst_ip'])})")
    if filters.get("dns_domain"):
        conditions.append(f"event.dns.request in:anycase ({_quote_list(filters['dns_domain'])})")
    if filters.get("registry_path"):
        conditions.append(f"registry.keyPath contains:anycase ({_quote_list(filters['registry_path'])})")
    if filters.get("file_extension"):
        conditions.append(f"tgt.file.extension in:anycase ({_quote_list(filters['file_extension'])})")
    if filters.get("user"):
        conditions.append(f"src.process.user in:anycase ({_quote_list(filters['user'])})")

    query = "\nAND ".join(conditions) + "\n| columns " + ", ".join(dict.fromkeys(columns)) + "\n| sort -event.time\n| limit 500"
    return {
        "query": query,
        "severity": "HIGH" if filters.get("cmdline_contains") or filters.get("signed_status") == "unsigned" else "MEDIUM",
        "explanation": f"Compiled from intent: {intent.get('intent', 'custom_hunt')}.",
        "mitre": [],
        "notes": ["Query compiled deterministically from structured intent."],
        "warnings": [],
    }


FALLBACK_TEMPLATES = {
    "ransomware": {
        "query": 'endpoint.os == "windows"\nAND (\n    src.process.indicatorRansomwareCount > 0\n    OR src.process.indicatorEvasionCount > 2\n    OR src.process.indicatorBootConfigurationUpdateCount > 0\n)\n| group RansomwareScore = max(src.process.indicatorRansomwareCount), EvasionScore = max(src.process.indicatorEvasionCount), FilesModified = sum(src.process.tgtFileModificationCount) by endpoint.name, src.process.name, src.process.storyline.id',
        "severity": "HIGH",
        "explanation": "Ransomware behavioral template.",
        "mitre": ["T1486", "T1490"],
        "notes": ["Pivot on storyline.id for full chain."],
    },
    "unsigned_appdata": {
        "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\nAND src.process.signedStatus = "unsigned"\nAND src.process.image.path contains:anycase ("\\AppData\\")\n| columns event.time, endpoint.name, src.process.name, src.process.image.path, src.process.cmdline, src.process.user, src.process.parent.name, src.process.storyline.id\n| sort -event.time\n| limit 300',
        "severity": "HIGH",
        "explanation": "Unsigned process execution from AppData.",
        "mitre": ["T1036.005"],
        "notes": ["Legitimate Electron apps may also trigger."],
    },
    "generic_process": {
        "query": 'event.category = "process"\nAND event.type in:matchcase ("Process Creation")\n| columns event.time, endpoint.name, src.process.name, src.process.image.path, src.process.cmdline, src.process.user, src.process.parent.name\n| sort -event.time\n| limit 200',
        "severity": "MEDIUM",
        "explanation": "Base process creation query.",
        "mitre": ["T1059"],
        "notes": ["Refine with specific process names or command-line fragments."],
    },
}


def match_fallback_template(text: str) -> Dict[str, Any] | None:
    lower = text.lower()
    if "ransomware" in lower:
        return {**FALLBACK_TEMPLATES["ransomware"], "warnings": [], "matched_template": "fallback:ransomware"}
    if "unsigned" in lower and "appdata" in lower:
        return {**FALLBACK_TEMPLATES["unsigned_appdata"], "warnings": [], "matched_template": "fallback:unsigned_appdata"}
    return None
