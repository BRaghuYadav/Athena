"""
ollama_client.py — talks to local Ollama running Phi-4-mini.
The model interprets threat content and extracts structured intent/behaviors.
Final S1QL is always compiled deterministically elsewhere.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "phi4-mini"
SKILLS_DIR = os.path.join(os.path.dirname(__file__), "skills")


def _load_skill(filename: str) -> str:
    path = os.path.join(SKILLS_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


CYBER_SKILL = _load_skill("cybersecurity_skill.md")
S1QL_SKILL = _load_skill("s1ql_mastery_skill.md")

INTENT_SYSTEM_PROMPT = f"""You are an S1QL intent extractor for SentinelOne Deep Visibility.
Given an analyst's hunt description, extract structured intent.

Use this S1QL guidance:
{S1QL_SKILL[:5000]}

RESPOND ONLY WITH VALID JSON.

Schema:
{{
  "intent": "short_snake_case_name",
  "category": "process|file|network|registry|dns|url|scheduled_task|logins|cross_process|command_script|indicators",
  "platform": "windows|linux|macos|all",
  "time_range": "1h|6h|24h|7d|30d",
  "filters": {{
    "process_name": [],
    "path_contains": [],
    "cmdline_contains": [],
    "signed_status": "unsigned|signed|any",
    "parent_process": [],
    "dst_port": [],
    "dst_ip": [],
    "dns_domain": [],
    "registry_path": [],
    "file_extension": [],
    "user": []
  }},
  "behavior": "hunt|detect|investigate|baseline",
  "confidence": 0.85,
  "closest_template": null
}}
"""

ARTICLE_ANALYSIS_PROMPT = f"""You are a threat-report analyst for a SOC.
Use the following operating guidance.

[CYBER_SKILL]
{CYBER_SKILL[:7000]}

RESPOND ONLY WITH VALID JSON.

Schema:
{{
  "title": "short title",
  "summary": "2-3 sentence summary",
  "attack_stages": ["execution", "persistence", "command_and_control"],
  "sha256": [],
  "sha1": [],
  "md5": [],
  "ips": [],
  "domains": [],
  "urls": [],
  "paths": [],
  "registry": [],
  "emails": [],
  "packages": [],
  "identity_artifacts": [
    {{"type": "email|maintainer|account", "value": "...", "domain": "...", "importance": "medium", "reason": "..."}}
  ],
  "supply_chain_artifacts": [
    {{"type": "package|dependency", "name": "axios", "version": "1.14.1", "value": "axios@1.14.1", "importance": "high", "reason": "..."}}
  ],
  "artifact_priority": [
    {{"type": "process|path|domain|ip|hash|registry|task|package", "value": "...", "importance": "high|medium|low", "reason": "..."}}
  ],
  "behaviors": [
    {{
      "type": "parent_child_execution|suspicious_interpreter_chain|package_manager_spawn|file_drop_and_execute|scheduled_task_persistence|runkey_persistence|service_creation|browser_credential_access|lolbin_proxy_execution|suspicious_network_beacon|script_execution|archive_or_temp_staging|registry_modification",
      "confidence": "low|medium|high",
      "rationale": "why this matters",
      "hunt_priority": 1,
      "evidence": {{"parent": "optional", "child": "optional", "path": "optional", "filename": "optional", "packages": []}}
    }}
  ]
}}

Rules:
- Prefer high-signal behaviors over bulk IOC dumping.
- Extract malicious package or dependency names/versions when present.
- Put maintainer/contact emails into identity_artifacts, not infrastructure.
- Do not invent hashes, domains, IPs, or file paths.
- If the article is ambiguous, lower confidence rather than guessing.
- Return at most 5 behaviors.
"""


async def check_ollama_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                return any(MODEL_NAME in m for m in models)
    except Exception:
        pass
    return False


async def _chat_json(system_prompt: str, user_prompt: str, num_predict: int = 1024, timeout: float = 90.0) -> Optional[dict]:
    try:
        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": num_predict},
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
            if r.status_code != 200:
                logger.warning("Ollama returned %s: %s", r.status_code, r.text[:200])
                return None
            content = r.json().get("message", {}).get("content", "").strip()
            if content.startswith("```"):
                content = content.split("```", 2)[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)
    except Exception as e:
        logger.warning("Ollama JSON call failed: %s", e)
        return None


async def extract_intent(user_text: str) -> Optional[dict]:
    return await _chat_json(INTENT_SYSTEM_PROMPT, f"Extract hunt intent from: {user_text}", num_predict=512, timeout=60.0)


async def extract_article_analysis(article_text: str) -> Optional[dict]:
    truncated = article_text[:6000]
    return await _chat_json(
        ARTICLE_ANALYSIS_PROMPT,
        f"Analyze this threat article and extract the structured hunting view:\n\n{truncated}",
        num_predict=900,
        timeout=90.0,
    )


async def extract_iocs_from_text(article_text: str) -> Optional[dict]:
    analysis = await extract_article_analysis(article_text)
    if not analysis:
        return None
    return {
        "title": analysis.get("title", ""),
        "summary": analysis.get("summary", ""),
        "sha256": analysis.get("sha256", []),
        "sha1": analysis.get("sha1", []),
        "md5": analysis.get("md5", []),
        "ips": analysis.get("ips", []),
        "domains": analysis.get("domains", []),
        "urls": analysis.get("urls", []),
        "paths": analysis.get("paths", []),
        "registry": analysis.get("registry", []),
        "emails": analysis.get("emails", []),
        "packages": analysis.get("packages", []),
    }


async def fetch_url_content(url: str) -> Optional[str]:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; S1Assistant/2.0; +internal-soc-tool)"}
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                return None
            html = r.text
            html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r"<(nav|header|footer|aside)[^>]*>.*?</\\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<[^>]+>", " ", html)
            text = re.sub(r"&nbsp;|&#160;", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text[:6000]
    except Exception as e:
        logger.warning("URL fetch failed for %s: %s", url, e)
        return None
