from __future__ import annotations

import re
from typing import Dict, Iterable, List

from article_analyzer import ArticleAnalysis, BehaviorCandidate


def _matches(patterns: Iterable[str], text: str) -> List[str]:
    return [pat for pat in patterns if re.search(pat, text, re.IGNORECASE)]


def _has_existing(analysis: ArticleAnalysis, behavior_type: str) -> bool:
    return any(b.type == behavior_type for b in analysis.behaviors)


def _add_behavior(analysis: ArticleAnalysis, behavior_type: str, matched: List[str], rationale: str, priority: int = 2, evidence: Dict | None = None):
    if _has_existing(analysis, behavior_type):
        return
    analysis.behaviors.append(
        BehaviorCandidate(
            type=behavior_type,
            confidence="high" if len(matched) >= 2 else "medium",
            rationale=rationale,
            hunt_priority=priority,
            evidence=evidence or {"matched_terms": matched[:6]},
        )
    )


def enrich_behaviors(analysis: ArticleAnalysis, article_text: str) -> ArticleAnalysis:
    lower = article_text.lower()

    # 1) Supply-chain execution: require package ecosystem evidence or extracted package artifacts.
    supply_hits = _matches([r"\bnpm\b", r"\byarn\b", r"\bpnpm\b", r"\bpip\b", r"postinstall", r"preinstall", r"dependency", r"package"], lower)
    if analysis.supply_chain_artifacts or len(supply_hits) >= 2:
        evidence = {
            "matched_terms": supply_hits[:6],
            "packages": [a.get("value") for a in analysis.supply_chain_artifacts[:6]],
        }
        _add_behavior(
            analysis,
            "package_manager_spawn",
            supply_hits or ["supply_chain_artifact"],
            "Package/dependency execution chain is directly suggested by supply-chain package evidence in the article.",
            priority=1,
            evidence=evidence,
        )

    # 2) Suspicious interpreter chain: require at least two interpreters or explicit chain wording.
    interpreters = _matches([r"powershell", r"python3?", r"bash", r"\bsh\b", r"wscript", r"cscript", r"node", r"osascript", r"vbscript"], lower)
    chain_terms = _matches([r"spawn", r"execute", r"launch", r"dropper", r"postinstall", r"child process"], lower)
    if len(set(interpreters)) >= 2 and chain_terms:
        _add_behavior(
            analysis,
            "suspicious_interpreter_chain",
            list(dict.fromkeys(interpreters + chain_terms)),
            "Multiple interpreter/script engines plus execution wording suggest a suspicious chained execution flow.",
            priority=1,
            evidence={"interpreters": list(dict.fromkeys(interpreters[:6]))},
        )

    # 3) File drop and execute: require staged path evidence or explicit dropped/downloaded wording.
    drop_hits = _matches([r"drop", r"download", r"write", r"payload", r"tmp", r"appdata", r"cache"], lower)
    if analysis.iocs.paths or len(drop_hits) >= 2:
        _add_behavior(
            analysis,
            "file_drop_and_execute",
            drop_hits or ["path_artifact"],
            "Explicit path or staging language indicates likely file drop and follow-on execution.",
            priority=2,
            evidence={"paths": analysis.iocs.paths[:6]},
        )

    # 4) Browser credential access: high bar; only add when article explicitly names browser stores or browser creds/cookies.
    browser_hits = _matches([r"login data", r"web data", r"\bcookies\b", r"browser credential", r"browser credential store", r"saved passwords?"], lower)
    if browser_hits:
        _add_behavior(
            analysis,
            "browser_credential_access",
            browser_hits,
            "Article explicitly references browser credential or cookie stores.",
            priority=2,
        )

    # 5) Registry modification: high bar; only when there is registry path evidence or explicit registry wording.
    reg_hits = _matches([r"hklm\\", r"hkcu\\", r"registry key", r"runonce", r"currentversion\\run"], lower)
    if analysis.iocs.registry or reg_hits:
        _add_behavior(
            analysis,
            "registry_modification",
            reg_hits or ["registry_artifact"],
            "Article explicitly references registry modification or provides a registry path.",
            priority=1,
            evidence={"registry": analysis.iocs.registry[:6]},
        )

    # 6) Beaconing/network: only when there is a real domain/IP or clear C2 wording.
    net_hits = _matches([r"\bc2\b", r"command and control", r"beacon", r"callback", r"exfiltrat", r"communicat"], lower)
    if analysis.iocs.domains or analysis.iocs.ips or len(net_hits) >= 1:
        _add_behavior(
            analysis,
            "suspicious_network_beacon",
            net_hits or ["network_ioc"],
            "Network infrastructure or C2 language is present; useful as a confirmation hunt rather than first pivot.",
            priority=3,
            evidence={"domains": analysis.iocs.domains[:6], "ips": analysis.iocs.ips[:6]},
        )

    analysis.behaviors.sort(key=lambda x: (x.hunt_priority, x.type))
    return analysis
