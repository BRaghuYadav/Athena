"""
phi4_test_harness.py — Local Model Capability Assessment

Run this ONCE to understand exactly what Phi-4-mini can do on your hardware.
It tests every micro-agent call shape and reports:
  - Can the model handle this prompt size? 
  - How long does it take?
  - Is the JSON output parseable?
  - Is the content useful?

Usage:
  cd backend
  python phi4_test_harness.py

Requires: Ollama running with phi4-mini pulled
  ollama pull phi4-mini
"""
import asyncio
import json
import time
import sys
import httpx

OLLAMA_URL = "http://localhost:11434"
MODEL = "phi4-mini"

# ═══════════════════════════════════════════════════
# TEST INFRASTRUCTURE
# ═══════════════════════════════════════════════════

class TestResult:
    def __init__(self, name, success, elapsed_ms, output=None, error=None, 
                 json_valid=False, content_quality="", prompt_chars=0, output_chars=0):
        self.name = name
        self.success = success
        self.elapsed_ms = elapsed_ms
        self.output = output
        self.error = error
        self.json_valid = json_valid
        self.content_quality = content_quality
        self.prompt_chars = prompt_chars
        self.output_chars = output_chars

    def __str__(self):
        status = "✓ PASS" if self.success else "✗ FAIL"
        json_s = "JSON:✓" if self.json_valid else "JSON:✗"
        return (f"  {status} | {self.name:45s} | {self.elapsed_ms:6d}ms | "
                f"prompt:{self.prompt_chars:5d}c | out:{self.output_chars:4d}c | "
                f"{json_s} | {self.content_quality}")


async def call_ollama(system: str, user: str, num_predict: int, timeout: float) -> dict:
    """Raw Ollama call — returns {success, elapsed_ms, content, error}"""
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": num_predict},
    }
    timeout_cfg = httpx.Timeout(connect=10.0, read=timeout, write=30.0, pool=30.0)
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            r = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
            elapsed = int((time.perf_counter() - started) * 1000)
            if r.status_code != 200:
                return {"success": False, "elapsed_ms": elapsed, "content": "", "error": f"HTTP {r.status_code}"}
            content = r.json().get("message", {}).get("content", "")
            return {"success": True, "elapsed_ms": elapsed, "content": content, "error": None}
    except httpx.ReadTimeout:
        elapsed = int((time.perf_counter() - started) * 1000)
        return {"success": False, "elapsed_ms": elapsed, "content": "", "error": f"ReadTimeout after {elapsed}ms"}
    except Exception as e:
        elapsed = int((time.perf_counter() - started) * 1000)
        return {"success": False, "elapsed_ms": elapsed, "content": "", "error": str(e)}


def try_parse_json(text: str) -> tuple:
    """Try to parse JSON from model output. Returns (parsed_dict, is_valid)"""
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1]
            if text.startswith("json"):
                text = text[4:]
    try:
        return json.loads(text), True
    except:
        import re
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0)), True
            except:
                pass
    return {}, False


# ═══════════════════════════════════════════════════
# TEST CASES
# ═══════════════════════════════════════════════════

async def test_0_health():
    """Test: Is Ollama running and phi4-mini available?"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            models = [m["name"] for m in r.json().get("models", [])]
            has_model = any(MODEL in m for m in models)
            return TestResult("Ollama health check", has_model, 0,
                            content_quality=f"Models: {', '.join(models[:5])}" if has_model else "phi4-mini NOT FOUND")
    except Exception as e:
        return TestResult("Ollama health check", False, 0, error=str(e))


async def test_1_minimal_json():
    """Test: Can it return valid JSON at all? Smallest possible call."""
    system = 'Return JSON only: {"status": "ok"}'
    user = "Say ok."
    r = await call_ollama(system, user, num_predict=20, timeout=15.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    return TestResult("Minimal JSON (20 tokens)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid,
                     content_quality=f"Got: {r['content'][:80]}" if r["success"] else r["error"],
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_2_summary_tiny():
    """Test: Summary agent with tiny payload (~200 chars)"""
    system = 'Return JSON: {"title": "short title", "summary": "one sentence"}'
    user = json.dumps({
        "artifacts": ["axios@1.14.1", "sfrclak.com", "/tmp/ld.py"],
        "primitives": ["package_execution_context", "interpreter_chain"],
    })
    r = await call_ollama(system, user, num_predict=80, timeout=20.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = ""
    if valid and parsed.get("title"):
        quality = f"title='{parsed['title'][:50]}'"
    elif r["success"]:
        quality = f"raw: {r['content'][:60]}"
    else:
        quality = r["error"]
    return TestResult("Summary (tiny, 80tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_3_summary_medium():
    """Test: Summary with more context (~500 chars)"""
    system = 'You are a SOC threat analyst. Return JSON: {"title": "factual title under 15 words", "summary": "one sentence under 30 words"}'
    user = json.dumps({
        "title_candidate": "Hackers compromise Axios npm package",
        "artifacts": ["axios@1.14.1", "axios@0.30.4", "plain-crypto-js@^4.2.1", "sfrclak.com", "%PROGRAMDATA%\\wt.exe", "/tmp/ld.py", "/Library/Caches/com.apple.act.mond"],
        "primitives": ["package_execution_context", "interpreter_chain", "temp_or_cache_staging", "suspicious_outbound_followup"],
        "lead_facts": ["compromised npm maintainer", "malicious dependency", "cross-platform RAT"]
    })
    r = await call_ollama(system, user, num_predict=100, timeout=25.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"title='{parsed.get('title','')[:50]}'" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Summary (medium, 100tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_4_strategy():
    """Test: Strategy agent — which hunt to start with and why"""
    system = 'Return JSON: {"start_with": "query name", "reason": "why", "next_pivot": "query name", "pivot_reason": "why"}'
    user = json.dumps({
        "primitives": [
            {"type": "package_execution_context", "confidence": "high"},
            {"type": "interpreter_chain", "confidence": "high"},
            {"type": "temp_or_cache_staging", "confidence": "high"},
        ],
        "queries": [
            {"name": "Package execution context", "signal": "high"},
            {"name": "Interpreter chain", "signal": "high"},
            {"name": "IOC confirmation", "signal": "high"},
        ]
    })
    r = await call_ollama(system, user, num_predict=120, timeout=25.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"start='{parsed.get('start_with','')}'" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Strategy (120tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_5_novelty():
    """Test: Novelty assessment"""
    system = 'Return JSON: {"status": "known_pattern|variant|novel_combination", "reason": "short reason", "unusual_elements": []}'
    user = json.dumps({
        "primitives": ["package_execution_context", "interpreter_chain", "temp_or_cache_staging"],
        "unusual": ["renamed PowerShell under %PROGRAMDATA%", "cross-platform payload"],
        "has_packages": True
    })
    r = await call_ollama(system, user, num_predict=100, timeout=20.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"status='{parsed.get('status','')}'" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Novelty (100tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_6_narrative():
    """Test: Attack narrative — the wow-factor test"""
    system = 'Return JSON: {"narrative": "2-3 sentence attack chain story"}'
    user = json.dumps({
        "stages": ["Initial Access", "Execution", "Persistence", "C2"],
        "primitives": ["package_execution_context", "interpreter_chain"],
        "artifacts": ["axios@1.14.1", "/tmp/ld.py", "sfrclak.com"]
    })
    r = await call_ollama(system, user, num_predict=140, timeout=30.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    narr = parsed.get("narrative", "")[:80] if valid else ""
    quality = f"narrative='{narr}'" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Narrative (140tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_7_guidance():
    """Test: Operational guidance"""
    system = 'Return JSON: {"guidance": "2-3 sentences of hunting advice"}'
    user = json.dumps({
        "primary": "Interpreter chain",
        "primitives": ["interpreter_chain", "suspicious_outbound_followup"],
        "route": "intel_article"
    })
    r = await call_ollama(system, user, num_predict=100, timeout=20.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"guidance='{parsed.get('guidance','')[:60]}'" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Guidance (100tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_8_intent():
    """Test: Operational intent extraction"""
    system = 'Return JSON: {"intent": "name", "platform": "windows|linux|all", "time_range": "24h", "primitive_hints": [], "notes": []}'
    user = "Hunt for suspicious PowerShell launched by Office applications on Windows in the last 24 hours"
    r = await call_ollama(system, user, num_predict=100, timeout=20.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"intent='{parsed.get('intent','')}' hints={parsed.get('primitive_hints',[])}" if valid else (r["error"] if not r["success"] else f"raw: {r['content'][:60]}")
    return TestResult("Intent extraction (100tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_9_with_few_shot():
    """Test: Does adding a few-shot example improve output quality?"""
    system = '''Return JSON: {"start_with": "query name", "reason": "why"}
Example:
INPUT: {"primitives": [{"type": "interpreter_chain"}], "queries": [{"name": "Interpreter chain"}]}
OUTPUT: {"start_with": "Interpreter chain", "reason": "Execution patterns survive IOC rotation."}'''
    user = json.dumps({
        "primitives": [{"type": "temp_or_cache_staging"}, {"type": "persistence_candidate"}],
        "queries": [{"name": "Temp staging"}, {"name": "Persistence hunt"}, {"name": "IOC check"}]
    })
    r = await call_ollama(system, user, num_predict=100, timeout=25.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"start='{parsed.get('start_with','')}' reason='{parsed.get('reason','')[:50]}'" if valid else (r["error"] if not r["success"] else r["content"][:60])
    return TestResult("Strategy+few-shot (100tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_10_with_rules():
    """Test: Does adding cyber rules context improve quality? (bigger prompt)"""
    rules = """Rules:
- Prefer behavior anchors over mutable infrastructure
- When both behavior and IOC hunts exist, start with behavior
- Cross-platform delivery plus OS-specific staging is high-value signal"""
    system = f'You are a SOC analyst. {rules}\nReturn JSON: {{"start_with": "", "reason": "", "next_pivot": "", "pivot_reason": ""}}'
    user = json.dumps({
        "primitives": [
            {"type": "package_execution_context", "confidence": "high"},
            {"type": "interpreter_chain", "confidence": "high"},
        ],
        "queries": [{"name": "Package exec"}, {"name": "Interpreter chain"}, {"name": "IOC confirm"}]
    })
    r = await call_ollama(system, user, num_predict=120, timeout=30.0)
    parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
    quality = f"start='{parsed.get('start_with','')}' reason='{parsed.get('reason','')[:40]}'" if valid else (r["error"] if not r["success"] else r["content"][:60])
    return TestResult("Strategy+rules (120tok)", r["success"], r["elapsed_ms"],
                     output=parsed, json_valid=valid, content_quality=quality,
                     prompt_chars=len(system)+len(user), output_chars=len(r["content"]))


async def test_11_timeout_sweep():
    """Test: What timeout actually works? Test 10s, 20s, 30s, 45s, 60s"""
    system = 'Return JSON: {"title": "short title", "summary": "one sentence"}'
    user = json.dumps({"artifacts": ["axios@1.14.1", "sfrclak.com"], "primitives": ["interpreter_chain"]})
    results = []
    for timeout in [10, 20, 30, 45, 60]:
        r = await call_ollama(system, user, num_predict=80, timeout=float(timeout))
        parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
        results.append(TestResult(
            f"Timeout sweep: {timeout}s", r["success"], r["elapsed_ms"],
            json_valid=valid,
            content_quality=f"{'OK' if r['success'] else r['error'][:30]}",
            prompt_chars=len(system)+len(user), output_chars=len(r["content"])
        ))
        if r["success"]:
            break  # found the working timeout, no need to test longer
    return results


async def test_12_num_predict_sweep():
    """Test: How much output can we get? Test 40, 80, 120, 160, 200 tokens"""
    system = 'Return JSON: {"narrative": "attack chain story in 2-3 sentences"}'
    user = json.dumps({"stages": ["Execution", "C2"], "artifacts": ["axios@1.14.1", "/tmp/ld.py"]})
    results = []
    for np in [40, 80, 120, 160, 200]:
        r = await call_ollama(system, user, num_predict=np, timeout=60.0)
        parsed, valid = try_parse_json(r["content"]) if r["success"] else ({}, False)
        narr_len = len(parsed.get("narrative", "")) if valid else 0
        results.append(TestResult(
            f"num_predict sweep: {np}tok", r["success"], r["elapsed_ms"],
            json_valid=valid,
            content_quality=f"narrative_len={narr_len}" if valid else (r["error"][:30] if not r["success"] else "parse_fail"),
            prompt_chars=len(system)+len(user), output_chars=len(r["content"])
        ))
    return results


async def test_13_parallel_vs_sequential():
    """Test: Can Ollama handle parallel requests? Or does it serialize?"""
    system = 'Return JSON: {"ok": true}'
    user = "Respond."

    # Sequential
    seq_start = time.perf_counter()
    for _ in range(3):
        await call_ollama(system, user, num_predict=10, timeout=15.0)
    seq_ms = int((time.perf_counter() - seq_start) * 1000)

    # Parallel
    par_start = time.perf_counter()
    await asyncio.gather(
        call_ollama(system, user, num_predict=10, timeout=15.0),
        call_ollama(system, user, num_predict=10, timeout=15.0),
        call_ollama(system, user, num_predict=10, timeout=15.0),
    )
    par_ms = int((time.perf_counter() - par_start) * 1000)

    return TestResult(
        "Parallel vs Sequential (3 calls)", True, 0,
        content_quality=f"Sequential: {seq_ms}ms | Parallel: {par_ms}ms | Speedup: {seq_ms/max(par_ms,1):.1f}x"
    )


# ═══════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════

async def run_all():
    print("=" * 100)
    print("PHI-4-MINI LOCAL MODEL CAPABILITY ASSESSMENT")
    print(f"Ollama: {OLLAMA_URL} | Model: {MODEL}")
    print("=" * 100)
    print()

    all_results = []

    # Health check first
    print("── Health Check ──")
    r = await test_0_health()
    print(r)
    all_results.append(r)
    if not r.success:
        print("\n✗ Ollama is not running or phi4-mini is not available.")
        print("  Run: ollama pull phi4-mini")
        return
    print()

    # Core capability tests
    print("── Core Capability Tests ──")
    tests = [
        test_1_minimal_json,
        test_2_summary_tiny,
        test_3_summary_medium,
        test_4_strategy,
        test_5_novelty,
        test_6_narrative,
        test_7_guidance,
        test_8_intent,
    ]
    for test_fn in tests:
        r = await test_fn()
        print(r)
        all_results.append(r)
    print()

    # Enhancement tests
    print("── Enhancement Tests (few-shot, rules) ──")
    for test_fn in [test_9_with_few_shot, test_10_with_rules]:
        r = await test_fn()
        print(r)
        all_results.append(r)
    print()

    # Sweep tests
    print("── Timeout Sweep ──")
    timeout_results = await test_11_timeout_sweep()
    for r in timeout_results:
        print(r)
    all_results.extend(timeout_results)
    print()

    print("── num_predict Sweep ──")
    np_results = await test_12_num_predict_sweep()
    for r in np_results:
        print(r)
    all_results.extend(np_results)
    print()

    print("── Parallel vs Sequential ──")
    r = await test_13_parallel_vs_sequential()
    print(r)
    all_results.append(r)
    print()

    # Summary
    print("=" * 100)
    print("SUMMARY")
    print("=" * 100)
    passed = sum(1 for r in all_results if r.success)
    failed = sum(1 for r in all_results if not r.success)
    json_ok = sum(1 for r in all_results if r.json_valid)
    avg_ms = sum(r.elapsed_ms for r in all_results if r.success and r.elapsed_ms > 0) // max(1, passed)

    print(f"  Tests passed:     {passed}/{len(all_results)}")
    print(f"  JSON parseable:   {json_ok}/{len(all_results)}")
    print(f"  Avg latency:      {avg_ms}ms (successful calls only)")
    print()

    # Find the sweet spot
    working_tests = [r for r in all_results if r.success and r.json_valid]
    if working_tests:
        fastest = min(working_tests, key=lambda r: r.elapsed_ms)
        slowest = max(working_tests, key=lambda r: r.elapsed_ms)
        print(f"  Fastest success:  {fastest.name} at {fastest.elapsed_ms}ms")
        print(f"  Slowest success:  {slowest.name} at {slowest.elapsed_ms}ms")

    # Recommendations
    print()
    print("── RECOMMENDATIONS FOR YOUR PROJECT ──")
    timeout_worked = [r for r in timeout_results if r.success]
    if timeout_worked:
        min_timeout = min(r.elapsed_ms for r in timeout_worked)
        print(f"  Minimum working timeout: {min_timeout}ms — set MICRO_TIMEOUT to {int(min_timeout * 1.5 / 1000) + 1}s")
    else:
        print("  ✗ No timeout worked — check if Ollama is under memory pressure")

    np_worked = [r for r in np_results if r.success and r.json_valid]
    if np_worked:
        best_np = max(np_worked, key=lambda r: r.output_chars)
        print(f"  Best num_predict:  Use {best_np.name.split(':')[1].strip()} for richest output")
    
    if any(r.name.startswith("Parallel") for r in all_results):
        par_test = [r for r in all_results if r.name.startswith("Parallel")][0]
        if "Speedup: 1.0" in par_test.content_quality or "Speedup: 0." in par_test.content_quality:
            print("  Parallel calls:   Ollama serializes on your hardware — run agents SEQUENTIALLY")
            print("                    This avoids resource contention and timeouts")
        else:
            print("  Parallel calls:   Ollama handles concurrency — keep PARALLEL_ENABLED = True")

    print()
    print("── RAW RESULTS (for debugging) ──")
    for r in all_results:
        if r.output:
            print(f"  {r.name}: {json.dumps(r.output, ensure_ascii=False)[:200]}")


if __name__ == "__main__":
    asyncio.run(run_all())
