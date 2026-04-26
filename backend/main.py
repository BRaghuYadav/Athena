"""
main.py — S1 Query Assistant backend
Upgraded with article analysis, behavior mapping, and ranked hunt packs.
"""
import hashlib
import json
import logging
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from article_analyzer import IOCResult, normalize_analysis
from behavior_mapper import enrich_behaviors
from compiler import FALLBACK_TEMPLATES, compile_intent_to_s1ql, compile_star_rule, match_fallback_template
from database import get_db, init_db
from hunt_planner import build_hunt_pack
from ioc_extractor import classify_input, extract_iocs
from ollama_client import check_ollama_health, extract_article_analysis, extract_intent, fetch_url_content
from validator import get_schema, reload_schema, validate_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="S1 Query Assistant", version="4.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup():
    init_db()
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM query_library").fetchone()[0]
    conn.close()
    if count == 0:
        from library_seed import seed_library
        seed_library()
        logger.info("Query library seeded")


class GenerateRequest(BaseModel):
    input: str
    mode: Optional[str] = "auto"
    analyst_id: Optional[str] = "default"


class IOCRequest(BaseModel):
    sha256: List[str] = []
    sha1: List[str] = []
    md5: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    paths: List[str] = []
    registry: List[str] = []


class FeedbackRequest(BaseModel):
    query_hash: str
    analyst_id: Optional[str] = "default"
    verdict: str
    notes: Optional[str] = ""
    suppressions: List[dict] = []


class SuppressionRequest(BaseModel):
    scope: Optional[str] = "global"
    suppression_type: str
    value: str
    created_by: Optional[str] = "default"
    expires_at: Optional[str] = None


class ValidateRequest(BaseModel):
    query: str


def query_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def get_library_list() -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM query_library ORDER BY category, id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/health")
async def health():
    ollama_ok = await check_ollama_health()
    conn = get_db()
    lib_count = conn.execute("SELECT COUNT(*) FROM query_library").fetchone()[0]
    history_count = conn.execute("SELECT COUNT(*) FROM query_history").fetchone()[0]
    pack_count = conn.execute("SELECT COUNT(*) FROM hunt_packs").fetchone()[0]
    conn.close()
    return {
        "status": "ok",
        "ollama": "connected" if ollama_ok else "unavailable",
        "model": "phi4-mini",
        "library_queries": lib_count,
        "history_entries": history_count,
        "hunt_packs": pack_count,
        "schema_version": get_schema().get("version", "unknown"),
    }


@app.post("/api/analyze")
async def analyze(req: GenerateRequest):
    text = req.input.strip()
    if not text:
        raise HTTPException(400, "Input is required")

    mode = req.mode if req.mode != "auto" else classify_input(text)
    article_text = text
    source_url = None
    if mode == "url":
        source_url = text
        article_text = await fetch_url_content(text) or text

    model_analysis = await extract_article_analysis(article_text)
    analysis = normalize_analysis(article_text, model_analysis)
    analysis = enrich_behaviors(analysis, article_text)
    pack = build_hunt_pack(analysis)

    conn = get_db()
    primary_query = (pack.get("primary_hunt") or {}).get("query", "")
    qhash = query_hash(primary_query or article_text[:200])
    conn.execute(
        "INSERT INTO hunt_packs (query_hash, input_text, primary_hunt_json, supporting_hunts_json, analysis_json) VALUES (?,?,?,?,?)",
        (qhash, text, json.dumps(pack.get("primary_hunt")), json.dumps(pack.get("supporting_hunts", [])), json.dumps(pack.get("analysis", {})))
    )
    conn.commit()
    conn.close()

    return {
        "query_hash": qhash,
        "mode": mode,
        "source_url": source_url,
        **pack,
    }


@app.post("/api/generate")
async def generate(req: GenerateRequest):
    text = req.input.strip()
    if not text:
        raise HTTPException(400, "Input is required")

    mode = req.mode if req.mode != "auto" else classify_input(text)

    if mode == "url":
        pack = await analyze(req)
        primary = pack.get("primary_hunt") or {}
        query = primary.get("query", "")
        validation = primary.get("validation") or (validate_query(query) if query else {"status": "BLOCKED", "confidence": 0})
        result = {
            "type": "url",
            "query": query,
            "star_rule": "",
            "severity": primary.get("severity", "MEDIUM"),
            "explanation": primary.get("explanation", pack.get("summary", "")),
            "mitre": primary.get("mitre", []),
            "notes": primary.get("notes", []),
            "warnings": pack.get("warnings", []) + primary.get("warnings", []),
            "ioc_summary": pack.get("analysis", {}).get("iocs"),
            "validation": validation,
            "confidence": validation.get("confidence", 0.0),
            "intent_json": None,
            "query_pack": {
                "primary_hunt": primary,
                "supporting_hunts": pack.get("supporting_hunts", []),
                "analysis": pack.get("analysis", {}),
            },
        }
    elif mode == "ioc":
        iocs = extract_iocs(text)
        from compiler import compile_ioc_query
        compiled = compile_ioc_query(iocs)
        validation = validate_query(compiled["query"]) if compiled["query"] else {"status": "BLOCKED", "confidence": 0, "warnings": [], "errors": ["No IOCs"]}
        result = {
            "type": "ioc",
            "query": compiled["query"],
            "star_rule": compile_star_rule(iocs),
            "severity": compiled.get("severity", "MEDIUM"),
            "explanation": compiled.get("explanation", ""),
            "mitre": compiled.get("mitre", []),
            "notes": compiled.get("notes", []),
            "warnings": compiled.get("warnings", []),
            "ioc_summary": iocs.to_dict(),
            "validation": validation,
            "confidence": validation.get("confidence", 0.0),
            "intent_json": None,
        }
    else:
        library = get_library_list()
        intent = await extract_intent(text)
        if intent:
            compiled = compile_intent_to_s1ql(intent, library)
        else:
            compiled = match_fallback_template(text) or {**FALLBACK_TEMPLATES["generic_process"], "warnings": ["Phi-4-mini unavailable. Using generic template."]}
        validation = validate_query(compiled["query"])
        result = {
            "type": "nl",
            "query": compiled["query"],
            "star_rule": "",
            "severity": compiled.get("severity", "MEDIUM"),
            "explanation": compiled.get("explanation", ""),
            "mitre": compiled.get("mitre", []),
            "notes": compiled.get("notes", []),
            "warnings": compiled.get("warnings", []) + validation.get("warnings", []),
            "ioc_summary": None,
            "validation": validation,
            "confidence": validation.get("confidence", 0.0),
            "intent_json": intent,
            "matched_template": compiled.get("matched_template"),
        }

    qhash = query_hash(result["query"])
    conn = get_db()
    conn.execute(
        """INSERT INTO query_history
           (query_hash, input_text, input_type, query_text, star_rule, intent_json,
            severity, confidence, validation_status, validation_warnings, explanation,
            mitre, notes, ioc_summary, analyst_id, source)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (qhash, text, mode, result["query"], result.get("star_rule", ""), json.dumps(result.get("intent_json")),
         result["severity"], result["confidence"], result["validation"]["status"], json.dumps(result["validation"].get("warnings", [])),
         result["explanation"], json.dumps(result["mitre"]), json.dumps(result["notes"]), json.dumps(result.get("ioc_summary")), req.analyst_id, mode)
    )
    conn.commit()
    conn.close()
    result["query_hash"] = qhash
    return result


@app.post("/api/generate/iocs")
def generate_from_iocs(req: IOCRequest):
    from compiler import compile_ioc_query
    iocs = IOCResult(sha256=req.sha256, sha1=req.sha1, md5=req.md5, ips=req.ips, domains=req.domains, urls=req.urls, paths=req.paths, registry=req.registry)
    compiled = compile_ioc_query(iocs)
    validation = validate_query(compiled["query"]) if compiled["query"] else {"status": "BLOCKED", "confidence": 0}
    return {"query": compiled.get("query", ""), "star_rule": compile_star_rule(iocs), "severity": compiled.get("severity", "MEDIUM"), "validation": validation, "ioc_summary": iocs.to_dict()}


@app.get("/api/library")
def library(category: Optional[str] = None, platform: Optional[str] = None):
    conn = get_db()
    sql = "SELECT * FROM query_library WHERE 1=1"
    params = []
    if category and category != "All":
        sql += " AND category = ?"
        params.append(category)
    if platform and platform != "All":
        sql += " AND (platform = ? OR platform = 'All')"
        params.append(platform)
    sql += " ORDER BY category, id"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/history")
def history(analyst_id: Optional[str] = None, limit: int = 50):
    conn = get_db()
    sql = "SELECT * FROM query_history"
    params = []
    if analyst_id:
        sql += " WHERE analyst_id = ?"
        params.append(analyst_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for key in ["mitre", "notes", "validation_warnings", "ioc_summary", "intent_json"]:
            if d.get(key):
                try:
                    d[key] = json.loads(d[key])
                except Exception:
                    pass
        result.append(d)
    return result


@app.get("/api/hunt-packs")
def hunt_packs(limit: int = 20):
    conn = get_db()
    rows = conn.execute("SELECT * FROM hunt_packs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for key in ["primary_hunt_json", "supporting_hunts_json", "analysis_json"]:
            if d.get(key):
                d[key] = json.loads(d[key])
        result.append(d)
    return result


@app.post("/api/feedback")
def submit_feedback(req: FeedbackRequest):
    if req.verdict not in ("valid", "invalid", "noisy", "useful", "promoted"):
        raise HTTPException(400, "Invalid verdict")
    conn = get_db()
    conn.execute("INSERT INTO analyst_feedback (query_hash, analyst_id, verdict, suppressions_added, notes) VALUES (?,?,?,?,?)", (req.query_hash, req.analyst_id, req.verdict, json.dumps(req.suppressions), req.notes))
    for s in req.suppressions:
        conn.execute("INSERT INTO suppressions (scope, suppression_type, value, created_by, expires_at) VALUES (?,?,?,?,?)", (s.get("scope", "global"), s["type"], s["value"], req.analyst_id, s.get("expires_at")))
    conn.commit()
    conn.close()
    return {"status": "recorded"}


@app.get("/api/suppressions")
def list_suppressions():
    conn = get_db()
    rows = conn.execute("SELECT * FROM suppressions ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/suppressions")
def add_suppression(req: SuppressionRequest):
    conn = get_db()
    conn.execute("INSERT INTO suppressions (scope, suppression_type, value, created_by, expires_at) VALUES (?,?,?,?,?)", (req.scope, req.suppression_type, req.value, req.created_by, req.expires_at))
    conn.commit()
    conn.close()
    return {"status": "added"}


@app.post("/api/validate")
def validate(req: ValidateRequest):
    return validate_query(req.query)


@app.get("/api/schema")
def schema():
    return get_schema()


@app.post("/api/schema/reload")
def schema_reload():
    s = reload_schema()
    return {"status": "reloaded", "version": s.get("version"), "field_count": len(s.get("fields", {}))}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
