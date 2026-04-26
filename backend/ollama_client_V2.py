"""
ollama_client.py — improved context selection for long threat articles.
Uses deterministic chunk scoring so Phi sees the most IOC-rich / behavior-rich parts
instead of the first N characters blindly.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

import httpx

from ioc_extractor import extract_iocs

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "phi4-mini"
SKILLS_DIR = os.path.join(os.path.dirname(__file__), "skills")

MAX_FETCH_CHARS = 50000
MAX_CONTEXT_CHARS = 7000
MAX_SECONDARY_CONTEXT_CHARS = 5000
CHUNK_SIZE = 1400
CHUNK_OVERLAP = 180

HIGH_SIGNAL_TERMS = {
    "c2": 6,
    "command and control": 6,
    "persistence": 5,
    "scheduled task": 5,
    "registry": 4,
    "powershell": 4,
    "cmd.exe": 4,
    "bash": 3,
    "python": 3,
    "python3": 3,
    "osascript": 4,
    "vbscript": 4,
    "drop": 4,
    "dropped": 4,
    "download": 4,
    "downloaded": 4,
    "execute": 4,
    "executed": 4,
    "spawn": 4,
    "postinstall": 6,
    "package": 4,
    "dependency": 4,
    "npm": 5,
    "yarn": 4,
    "pnpm": 4,
    "pip": 4,
    "cookie": 3,
    "credential": 4,
    "token": 3,
    "exfil": 4,
    "maintainer": 3,
    "github": 2,
    "malicious": 3,
    "compromise": 3,
    "supply chain": 6,
}


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
{S1QL_SKILL[:4500]}

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
You are given selected high-signal sections from a longer threat article. The text may be incomplete,
but it was pre-selected to contain the most IOC-rich and behavior-rich content.

Use the following operating guidance.

[CYBER_SKILL]
{CYBER_SKILL[:4500]}

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


def _safe_json_loads(content: str) -> Optional[dict]:
    content = content.strip()
    if not content:
        return None
    if content.startswith("```"):
        parts = content.split("```", 2)
        if len(parts) >= 2:
            content = parts[1]
            if content.startswith("json"):
                content = content[4:]
    try:
        return json.loads(content)
    except Exception:
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return None
        return None


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
                logger.warning("Ollama returned %s: %s", r.status_code, r.text[:250])
                return None
            content = r.json().get("message", {}).get("content", "")
            return _safe_json_loads(content)
    except Exception as e:
        logger.warning("Ollama JSON call failed: %s", e)
        return None


async def extract_intent(user_text: str) -> Optional[dict]:
    return await _chat_json(INTENT_SYSTEM_PROMPT, f"Extract hunt intent from: {user_text}", num_predict=512, timeout=60.0)


def _normalize_whitespace(text: str) -> str:
    text = text.replace("\r", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    if not paragraphs:
        paragraphs = [text]

    chunks: List[str] = []
    current = ""
    for para in paragraphs:
        if len(para) > chunk_size * 1.4:
            sentences = re.split(r"(?<=[.!?])\s+", para)
        else:
            sentences = [para]

        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            if not current:
                current = sentence
                continue
            if len(current) + 1 + len(sentence) <= chunk_size:
                current += " " + sentence
            else:
                chunks.append(current)
                if overlap > 0 and len(current) > overlap:
                    tail = current[-overlap:]
                    current = tail + " " + sentence
                else:
                    current = sentence
    if current:
        chunks.append(current)
    return chunks


def _score_chunk(chunk: str, idx: int, total_chunks: int) -> int:
    score = 0
    lower = chunk.lower()

    # Lead and tail paragraphs often contain summary, impact, or IoCs.
    if idx == 0:
        score += 8
    elif idx == 1:
        score += 4
    if idx == total_chunks - 1:
        score += 3

    iocs = extract_iocs(chunk)
    score += len(iocs.domains) * 8
    score += len(iocs.urls) * 6
    score += len(iocs.ips) * 7
    score += len(iocs.paths) * 8
    score += len(iocs.registry) * 8
    score += len(iocs.packages) * 9
    score += len(iocs.emails) * 2
    score += (len(iocs.sha256) + len(iocs.sha1) + len(iocs.md5)) * 7

    for term, weight in HIGH_SIGNAL_TERMS.items():
        if term in lower:
            score += weight

    # Article phrases that often carry the actual interesting facts.
    if "indicators of compromise" in lower or "iocs" in lower:
        score += 8
    if "researchers said" in lower or "the report states" in lower:
        score += 3
    if re.search(r"\b(cve-\d{4}-\d+)\b", lower):
        score += 4
    if re.search(r"%[a-z_]+%\\", chunk, re.IGNORECASE):
        score += 8

    return score


def _build_ranked_article_context(article_text: str) -> Tuple[str, str]:
    text = _normalize_whitespace(article_text)
    if len(text) <= MAX_CONTEXT_CHARS:
        return text, ""

    chunks = _chunk_text(text)
    if not chunks:
        return text[:MAX_CONTEXT_CHARS], text[MAX_CONTEXT_CHARS:MAX_CONTEXT_CHARS + MAX_SECONDARY_CONTEXT_CHARS]

    scored = [(i, _score_chunk(chunk, i, len(chunks)), chunk) for i, chunk in enumerate(chunks)]
    scored.sort(key=lambda x: (-x[1], x[0]))

    # Always include the lead chunk. Then add best-scoring unique chunks in original order.
    chosen_idx = {0}
    selected: List[Tuple[int, str]] = [(0, chunks[0])]
    current_len = len(chunks[0])

    for idx, _, chunk in scored:
        if idx in chosen_idx:
            continue
        add_cost = len(chunk) + 16
        if current_len + add_cost > MAX_CONTEXT_CHARS:
            continue
        chosen_idx.add(idx)
        selected.append((idx, chunk))
        current_len += add_cost
        if current_len >= MAX_CONTEXT_CHARS * 0.92:
            break

    selected.sort(key=lambda x: x[0])
    primary_context = "\n\n".join(f"[SECTION {i+1}]\n{chunk}" for i, chunk in selected)

    secondary: List[Tuple[int, str]] = []
    secondary_len = 0
    for idx, _, chunk in scored:
        if idx in chosen_idx:
            continue
        add_cost = len(chunk) + 16
        if secondary_len + add_cost > MAX_SECONDARY_CONTEXT_CHARS:
            continue
        secondary.append((idx, chunk))
        secondary_len += add_cost
        if secondary_len >= MAX_SECONDARY_CONTEXT_CHARS * 0.92:
            break

    secondary.sort(key=lambda x: x[0])
    secondary_context = "\n\n".join(f"[SECTION {i+1}]\n{chunk}" for i, chunk in secondary)
    return primary_context, secondary_context


def _is_sparse_analysis(data: Optional[dict]) -> bool:
    if not data:
        return True
    filled = 0
    for key in ("title", "summary"):
        if str(data.get(key, "")).strip():
            filled += 1
    for key in ("domains", "urls", "paths", "packages", "ips", "sha256", "sha1", "md5", "registry", "emails"):
        if data.get(key):
            filled += 1
    if data.get("behaviors"):
        filled += 1
    return filled < 3


def _merge_unique_strs(*groups: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for group in groups:
        for item in group or []:
            if not isinstance(item, str):
                continue
            val = item.strip()
            if not val or val in seen:
                continue
            seen.add(val)
            out.append(val)
    return out


def _merge_model_analysis(primary: Optional[dict], secondary: Optional[dict]) -> Optional[dict]:
    if not primary and not secondary:
        return None
    if not primary:
        return secondary
    if not secondary:
        return primary

    merged = dict(primary)
    for key in ("title", "summary"):
        if not str(merged.get(key, "")).strip() and str(secondary.get(key, "")).strip():
            merged[key] = secondary[key]

    merged["attack_stages"] = _merge_unique_strs(primary.get("attack_stages", []), secondary.get("attack_stages", []))
    for key in ("sha256", "sha1", "md5", "ips", "domains", "urls", "paths", "registry", "emails", "packages"):
        merged[key] = _merge_unique_strs(primary.get(key, []), secondary.get(key, []))

    def merge_dict_list(key: str) -> List[dict]:
        seen = set()
        out = []
        for source in (primary.get(key, []), secondary.get(key, [])):
            for item in source or []:
                if not isinstance(item, dict):
                    continue
                identity = json.dumps(item, sort_keys=True, default=str)
                if identity in seen:
                    continue
                seen.add(identity)
                out.append(item)
        return out

    for key in ("identity_artifacts", "supply_chain_artifacts", "artifact_priority", "behaviors"):
        merged[key] = merge_dict_list(key)

    return merged


async def extract_article_analysis(article_text: str) -> Optional[dict]:
    primary_context, secondary_context = _build_ranked_article_context(article_text)
    primary = await _chat_json(
        ARTICLE_ANALYSIS_PROMPT,
        "Analyze these selected high-signal sections from a longer threat article and extract the structured hunting view:\n\n"
        + primary_context,
        num_predict=800,
        timeout=90.0,
    )

    if not _is_sparse_analysis(primary) or not secondary_context:
        return primary

    secondary = await _chat_json(
        ARTICLE_ANALYSIS_PROMPT,
        "The first pass was sparse. Analyze these additional selected sections from the same article and extract only facts actually present:\n\n"
        + secondary_context,
        num_predict=650,
        timeout=75.0,
    )
    return _merge_model_analysis(primary, secondary)


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
            html = re.sub(r"<(nav|header|footer|aside|noscript)[^>]*>.*?</\\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)

            # Preserve rough structure before stripping HTML.
            html = re.sub(r"</(p|div|section|article|li|ul|ol|h1|h2|h3|h4|h5|h6|blockquote|pre|code|table|tr)>", "\\n\\n", html, flags=re.IGNORECASE)
            html = re.sub(r"<br\s*/?>", "\\n", html, flags=re.IGNORECASE)

            text = re.sub(r"<[^>]+>", " ", html)
            text = text.replace("&nbsp;", " ").replace("&#160;", " ")
            text = re.sub(r"[ \t]+", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text)
            text = text.strip()
            return text[:MAX_FETCH_CHARS]
    except Exception as e:
        logger.warning("URL fetch failed for %s: %s", url, e)
        return None
