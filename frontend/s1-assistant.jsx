import { useState, useEffect, useCallback } from "react";

/*
 * S1 Query Assistant v3 — Frontend
 * Calls FastAPI backend at API_BASE (default: same origin /api)
 * When running standalone in Claude artifacts, falls back to demo mode.
 *
 * New in v3:
 * - Validation status + confidence score on every query
 * - Intent JSON viewer (shows what the model extracted)
 * - Analyst feedback buttons (valid/noisy/broken/promote)
 * - Backend-powered threat feeds (cached in SQLite)
 * - Schema-aware query generation
 */

const API_BASE = window.location.port === "8000" ? "" : "http://localhost:8000";
const API = (path) => `${API_BASE}${path}`;

// ═══ Fallback data for demo mode (when backend unavailable) ═══
const DEMO_MODE_NOTICE = "Backend unavailable — running in demo mode. Connect to http://localhost:8000 for full features.";

// Syntax highlighting for S1QL
function hl(c) {
  if (!c) return "";
  return c
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/(\/\/[^\n]*)/g, '<span class="cm">$1</span>')
    .replace(/\b(AND|OR|NOT|IN|BY)\b/g, '<span class="kw">$1</span>')
    .replace(/\b(event\.\w[\w.]*|src\.\w[\w.]*|tgt\.\w[\w.]*|dst\.\w[\w.]*|url\.\w[\w.]*|agent\.\w[\w.]*|endpoint\.\w[\w.]*|registry\.\w[\w.]*|task\.\w[\w.]*|cmdScript\.\w[\w.]*|osSrc\.\w[\w.]*|module\.\w[\w.]*)\b/g, '<span class="fd">$1</span>')
    .replace(/\b(contains|contains:anycase|in:anycase|in:matchcase|matches)\b/g, '<span class="op">$1</span>')
    .replace(/(["'][^"']*["'])/g, '<span class="st">$1</span>')
    .replace(/(\| columns|\| group|\| sort|\| limit)/g, '<span class="kw">$1</span>');
}

const SV = {
  CRITICAL: { bg: "rgba(239,68,68,.1)", c: "#ef4444" },
  HIGH: { bg: "rgba(249,115,22,.08)", c: "#f97316" },
  MEDIUM: { bg: "rgba(234,179,8,.07)", c: "#eab308" },
  LOW: { bg: "rgba(34,197,94,.07)", c: "#22c55e" },
};
const VS = {
  PASS: { bg: "rgba(34,197,94,.08)", c: "#22c55e", icon: "✓" },
  PASS_WITH_WARNINGS: { bg: "rgba(234,179,8,.07)", c: "#eab308", icon: "⚠" },
  BLOCKED: { bg: "rgba(239,68,68,.08)", c: "#ef4444", icon: "✗" },
};

const CATS = ["All","Command-And-Control","Credential-Access","Execution","Persistence","Defense-Evasion","Exfiltration","Privilege-Escalation","Lateral-Movement","Discovery","User-Behavior"];

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=DM+Sans:wght@300;400;500;600;700;800&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#05070e;--bg2:#090c18;--bg3:#0d1120;--bg4:#111730;--bdr:#1a1f3a;--bdr2:#4f46e5;--tx:#dfe3f0;--tx2:#6b7294;--tx3:#3e4468;--ac:#4f46e5;--acg:rgba(79,70,229,.25);--grn:#10b981;--red:#ef4444;--org:#f59e0b;--ylw:#fbbf24;--cyn:#06b6d4}
body{background:var(--bg);color:var(--tx);font-family:'DM Sans',sans-serif}
.app{max-width:1160px;margin:0 auto;min-height:100vh;padding:0 16px}
.hdr{padding:24px 0 18px;border-bottom:1px solid var(--bdr);margin-bottom:18px;display:flex;justify-content:space-between;align-items:flex-end}
.hdr h1{font-size:22px;font-weight:800;letter-spacing:-.3px;color:#818cf8}
.hdr .right{display:flex;align-items:center;gap:8px}
.health{padding:3px 10px;border-radius:12px;font-size:10px;font-weight:600;display:flex;align-items:center;gap:4px}
.health.ok{background:rgba(16,185,129,.08);color:var(--grn);border:1px solid rgba(16,185,129,.2)}
.health.warn{background:rgba(245,158,11,.06);color:var(--org);border:1px solid rgba(245,158,11,.2)}
.dot{width:5px;height:5px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.tabs{display:flex;gap:2px;background:var(--bg2);padding:2px;border-radius:8px;margin-bottom:18px;border:1px solid var(--bdr)}
.tab{flex:1;padding:8px 10px;background:0;border:0;color:var(--tx2);font-family:inherit;font-size:11.5px;font-weight:500;cursor:pointer;border-radius:6px;transition:all .15s;white-space:nowrap}
.tab:hover{color:var(--tx);background:var(--bg4)}
.tab.on{background:var(--ac);color:#fff;font-weight:600}
h2.sec{font-size:18px;font-weight:700;margin-bottom:2px}
p.sub{color:var(--tx2);font-size:12px;margin-bottom:14px}
.modes{display:flex;gap:5px;margin-bottom:12px}
.mbtn{padding:6px 14px;border-radius:6px;border:1px solid var(--bdr);background:var(--bg3);color:var(--tx2);font-family:inherit;font-size:11px;cursor:pointer;transition:all .12s}
.mbtn:hover{border-color:var(--ac);color:var(--tx)}
.mbtn.on{background:var(--ac);border-color:var(--ac);color:#fff}
textarea{width:100%;min-height:72px;padding:12px;background:var(--bg4);border:1px solid var(--bdr);border-radius:8px;color:var(--tx);font-family:inherit;font-size:12.5px;resize:vertical;outline:0;transition:border .15s}
textarea:focus{border-color:var(--ac);box-shadow:0 0 0 2px var(--acg)}
textarea::placeholder{color:var(--tx3)}
.gbtn{padding:10px 22px;background:var(--ac);border:0;border-radius:8px;color:#fff;font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .15s;margin-top:10px}
.gbtn:hover{box-shadow:0 3px 16px var(--acg)}
.gbtn:disabled{opacity:.4;cursor:not-allowed}
.spin{width:12px;height:12px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:sp .5s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.card{background:var(--bg3);border:1px solid var(--bdr);border-radius:10px;margin-top:14px;overflow:hidden}
.banner{padding:9px 14px;font-size:11px;font-weight:500;display:flex;align-items:center;gap:6px;border-bottom:1px solid var(--bdr)}
.banner.grn{background:rgba(16,185,129,.05);color:var(--grn)}
.banner.ylw{background:rgba(245,158,11,.04);color:var(--org)}
.warn{margin:8px 12px;padding:8px 12px;background:rgba(245,158,11,.04);border:1px solid rgba(245,158,11,.15);border-radius:6px;font-size:10px;color:var(--org)}
.itags{display:flex;gap:4px;flex-wrap:wrap;padding:8px 14px}
.itag{padding:2px 7px;border-radius:4px;font-size:9px;font-weight:600;font-family:'IBM Plex Mono',monospace}
.qhdr{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--bdr)}
.qhdr h3{font-size:13px;font-weight:600}
.sev{padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;font-family:'IBM Plex Mono',monospace}
.vbadge{padding:2px 8px;border-radius:3px;font-size:9px;font-weight:600;font-family:'IBM Plex Mono',monospace;display:inline-flex;align-items:center;gap:3px}
.conf{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;padding:2px 8px;border-radius:3px;background:rgba(79,70,229,.08);color:#818cf8}
.cpbtn{padding:4px 10px;background:0;border:1px solid var(--bdr);border-radius:4px;color:var(--tx2);font-family:inherit;font-size:10px;cursor:pointer;transition:all .12s}
.cpbtn:hover{border-color:var(--ac);color:var(--tx)}
.cpbtn.ok{border-color:var(--grn);color:var(--grn)}
.qcode{padding:14px;background:var(--bg);font-family:'IBM Plex Mono',monospace;font-size:11.5px;line-height:1.65;color:#b0b8d4;white-space:pre-wrap;word-break:break-all;overflow-x:auto;max-height:400px;overflow-y:auto}
.qcode .cm{color:var(--tx3)} .qcode .kw{color:var(--grn)} .qcode .st{color:var(--ylw)} .qcode .fd{color:#67e8f9} .qcode .op{color:#fca5a5}
.exp{padding:12px 14px;border-top:1px solid var(--bdr)}
.exp h4{font-size:12px;font-weight:600;margin-bottom:4px}
.exp p{font-size:11px;color:var(--tx2);line-height:1.55}
.meta{display:flex;gap:16px;padding:12px 14px;border-top:1px solid var(--bdr);flex-wrap:wrap}
.meta-s{flex:1;min-width:160px}
.meta-s h4{font-size:11px;font-weight:600;margin-bottom:5px}
.mtag{display:inline-block;padding:1px 6px;background:rgba(99,102,241,.1);color:#818cf8;border-radius:3px;font-size:9px;font-weight:600;font-family:'IBM Plex Mono',monospace;margin:1px}
.notes{font-size:10px;color:var(--tx2);line-height:1.6}
.fb-row{display:flex;gap:6px;padding:10px 14px;border-top:1px solid var(--bdr);align-items:center}
.fb-btn{padding:5px 12px;border-radius:5px;border:1px solid var(--bdr);background:var(--bg4);color:var(--tx2);font-family:inherit;font-size:10px;cursor:pointer;transition:all .12s}
.fb-btn:hover{border-color:var(--ac);color:var(--tx)}
.fb-btn.sent{border-color:var(--grn);color:var(--grn);cursor:default}
.intent-box{margin:8px 14px;padding:10px;background:var(--bg);border-radius:6px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#818cf8;max-height:150px;overflow-y:auto;white-space:pre-wrap}
.search{flex:1;min-width:160px;padding:8px 12px;background:var(--bg4);border:1px solid var(--bdr);border-radius:7px;color:var(--tx);font-family:inherit;font-size:11px;outline:0}
.search:focus{border-color:var(--ac)} .search::placeholder{color:var(--tx3)}
.sel{padding:8px 12px;background:var(--bg4);border:1px solid var(--bdr);border-radius:7px;color:var(--tx);font-family:inherit;font-size:11px;cursor:pointer}
.tcard{background:var(--bg3);border:1px solid var(--bdr);border-radius:8px;padding:12px 14px;margin-bottom:6px;transition:border .12s}
.tcard:hover{border-color:rgba(79,70,229,.25)}
.ttop{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.tinfo{flex:1}
.tbadges{display:flex;gap:4px;margin-bottom:5px;flex-wrap:wrap}
.tcard h3{font-size:13px;font-weight:600;margin-bottom:2px}
.tcard .desc{font-size:10px;color:var(--tx2);line-height:1.4;margin-bottom:5px}
.gqbtn{padding:6px 12px;background:var(--ac);border:0;border-radius:6px;color:#fff;font-family:inherit;font-size:10px;font-weight:600;cursor:pointer;white-space:nowrap}
.pills{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px}
.pill{padding:4px 10px;border-radius:6px;border:1px solid var(--bdr);background:0;color:var(--tx2);font-family:inherit;font-size:10px;cursor:pointer;transition:all .12s}
.pill:hover{border-color:var(--ac);color:var(--tx)} .pill.on{background:var(--ac);border-color:var(--ac);color:#fff}
.lgrp{margin-bottom:16px} .lgrp h3{font-size:9px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--tx3);margin-bottom:6px}
.litem{background:var(--bg3);border:1px solid var(--bdr);border-radius:7px;margin-bottom:4px;overflow:hidden}
.lhdr{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;cursor:pointer}
.lhdr h4{font-size:12px;font-weight:600;display:inline} .lhdr p{font-size:10px;color:var(--tx2);margin-top:2px}
.ptag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:8px;font-weight:600;margin-right:5px;background:rgba(99,102,241,.08);color:#818cf8}
.lbody{padding:0 12px 12px;border-top:1px solid var(--bdr)}
.hitem{background:var(--bg3);border:1px solid var(--bdr);border-radius:8px;margin-bottom:5px;overflow:hidden}
.hhdr{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;cursor:pointer} .hhdr:hover{background:var(--bg4)}
.htbadge{padding:2px 6px;border-radius:3px;font-size:8px;font-weight:700;font-family:'IBM Plex Mono',monospace}
.hprev{font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;margin:0 8px}
.htime{font-size:9px;color:var(--tx3)}
.demo-banner{background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.15);border-radius:7px;padding:8px 14px;margin-bottom:14px;font-size:10px;color:var(--org);display:flex;align-items:center;gap:6px}
@media(max-width:768px){.meta{flex-direction:column}.ttop{flex-direction:column}.hdr{flex-direction:column;align-items:flex-start;gap:8px}}
`;

export default function App() {
  const [tab, setTab] = useState("gen");
  const [input, setInput] = useState("");
  const [mode, setMode] = useState("plain");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [expH, setExpH] = useState(null);
  const [libCat, setLibCat] = useState("All");
  const [libExp, setLibExp] = useState(null);
  const [library, setLibrary] = useState([]);
  const [threats, setThreats] = useState([]);
  const [tSearch, setTSearch] = useState("");
  const [tSrc, setTSrc] = useState("All");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(null);
  const [health, setHealth] = useState(null);
  const [demo, setDemo] = useState(false);
  const [showIntent, setShowIntent] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(null);

  // Check backend health on mount
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(API("/api/health"));
        if (r.ok) { setHealth(await r.json()); setDemo(false); }
        else setDemo(true);
      } catch { setDemo(true); }
    })();
  }, []);

  // Load library
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(API("/api/library"));
        if (r.ok) setLibrary(await r.json());
      } catch {}
    })();
  }, []);

  // Load threats
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(API("/api/threats?limit=60"));
        if (r.ok) setThreats(await r.json());
      } catch {}
    })();
  }, []);

  // Load history
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(API("/api/history?limit=50"));
        if (r.ok) setHistory(await r.json());
      } catch {}
    })();
  }, []);

  const cp = useCallback((t, id) => {
    navigator.clipboard.writeText(t);
    setCopied(id);
    setTimeout(() => setCopied(null), 1800);
  }, []);

  // Generate query via backend
  const gen = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    setResult(null);
    setFeedbackSent(null);
    setShowIntent(false);
    try {
      const r = await fetch(API("/api/generate"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: input.trim(), mode: mode === "url" ? "url" : "auto" }),
      });
      if (r.ok) {
        const data = await r.json();
        setResult(data);
        // Refresh history
        try {
          const h = await fetch(API("/api/history?limit=50"));
          if (h.ok) setHistory(await h.json());
        } catch {}
      }
    } catch (e) {
      setResult({ type: "error", query: "// Backend unavailable", severity: "LOW", explanation: String(e), warnings: ["Connect backend at localhost:8000"], validation: { status: "BLOCKED", confidence: 0 }, confidence: 0 });
    }
    setLoading(false);
  }, [input, mode]);

  // Generate from threat
  const genFromThreat = useCallback(async (t) => {
    try {
      const r = await fetch(API(`/api/threats/${t.id}/query`), { method: "POST" });
      if (r.ok) {
        const data = await r.json();
        setResult({ type: "threat", query: data.query, validation: data.validation, severity: t.severity, explanation: `From ${data.source}: ${data.title}`, mitre: t.mitre || [], warnings: [], confidence: data.validation?.confidence || 0 });
        setTab("gen");
      }
    } catch {}
  }, []);

  // Submit feedback
  const sendFeedback = useCallback(async (verdict) => {
    if (!result?.query_hash) return;
    try {
      await fetch(API("/api/feedback"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query_hash: result.query_hash, verdict }),
      });
      setFeedbackSent(verdict);
    } catch {}
  }, [result]);

  // Filter library
  const filtLib = library.filter(q => libCat === "All" || q.category === libCat);
  const gLib = {};
  filtLib.forEach(q => { if (!gLib[q.category]) gLib[q.category] = []; gLib[q.category].push(q); });

  // Filter threats
  const filtT = threats.filter(t => {
    if (tSrc !== "All" && t.source !== tSrc) return false;
    if (tSearch && !t.title.toLowerCase().includes(tSearch.toLowerCase())) return false;
    return true;
  });
  const fSrcs = [...new Set(threats.map(t => t.source))];

  const v = result?.validation || {};

  return (
    <><style>{CSS}</style><div className="app">
      {/* Header */}
      <div className="hdr">
        <div>
          <h1>S1 Query Assistant</h1>
          <p style={{color:"var(--tx2)",fontSize:11,marginTop:2}}>SentinelOne Deep Visibility · AB InBev SOC</p>
        </div>
        <div className="right">
          {health && <span className={`health ${health.ollama?.includes("connected")?"ok":"warn"}`}>
            <span className="dot"/>{health.ollama?.includes("connected")?"Phi-4-mini connected":"Fallback mode"}
          </span>}
          {health && <span className="health ok"><span className="dot"/>{health.library_queries} queries · {health.threat_entries} threats</span>}
        </div>
      </div>

      {demo && <div className="demo-banner">⚠ {DEMO_MODE_NOTICE}</div>}

      {/* Tabs */}
      <div className="tabs">
        {[["gen","⚡ Generator"],["lib",`📚 Library (${library.length||70})`],["threats",`🔥 Threats (${threats.length})`],["history",`📋 History (${history.length})`],["star","🛡 STAR"]].map(([id,l])=>
          <button key={id} className={`tab ${tab===id?"on":""}`} onClick={()=>setTab(id)}>{l}</button>
        )}
      </div>

      {/* ═══ GENERATOR ═══ */}
      {tab==="gen"&&<div>
        <h2 className="sec">Query Generator</h2>
        <p className="sub">Describe your hunt → validated S1QL with confidence score</p>
        <div className="modes">
          <button className={`mbtn ${mode==="plain"?"on":""}`} onClick={()=>setMode("plain")}>⚡ Plain English</button>
          <button className={`mbtn ${mode==="url"?"on":""}`} onClick={()=>setMode("url")}>🔗 Threat URL</button>
        </div>
        <textarea value={input} onChange={e=>setInput(e.target.value)}
          placeholder={mode==="url"?"Paste a threat report URL...":"Describe what you want to hunt, or paste IOCs...\n\nExamples:\n• unsigned processes from AppData on Windows\n• ransomware behavioral detection\n• Paste SHA256, IPs, domains — auto-detected as IOC mode"}
          onKeyDown={e=>{if(e.key==="Enter"&&(e.ctrlKey||e.metaKey))gen();}} />
        <button className="gbtn" onClick={gen} disabled={loading||!input.trim()}>
          {loading?<><span className="spin"/>Generating...</>:<>⚡ Generate Query</>}
        </button>

        {result && result.type !== "error" && <div className="card">
          {/* IOC Banner */}
          {result.ioc_summary?.total > 0 && <div className="banner grn">
            🔍 {result.type==="url"?"URL parsed":"IOC mode"} — {result.ioc_summary.total} IOCs found
            {result.url_title && ` · ${result.url_title}`}
          </div>}

          {/* Validation + Confidence Banner */}
          <div className="banner" style={{background:VS[v.status]?.bg,color:VS[v.status]?.c,justifyContent:"space-between"}}>
            <span><span className="vbadge" style={{background:VS[v.status]?.bg,color:VS[v.status]?.c}}>
              {VS[v.status]?.icon} {v.status?.replace(/_/g," ")}
            </span> Preflight validation</span>
            <span className="conf">{Math.round((result.confidence||0)*100)}% confidence</span>
          </div>

          {/* Warnings */}
          {(result.warnings?.length > 0 || v.errors?.length > 0) && <div className="warn">
            {v.errors?.map((e,i)=><div key={i}>✗ {e}</div>)}
            {result.warnings?.map((w,i)=><div key={i}>⚠ {w}</div>)}
          </div>}

          {/* IOC Tags */}
          {result.ioc_summary?.total > 0 && <div className="itags">
            {result.ioc_summary.sha256>0&&<span className="itag" style={{background:"rgba(99,102,241,.1)",color:"#818cf8"}}>{result.ioc_summary.sha256} SHA256</span>}
            {result.ioc_summary.md5>0&&<span className="itag" style={{background:"rgba(6,182,212,.08)",color:"var(--cyn)"}}>{result.ioc_summary.md5} MD5</span>}
            {result.ioc_summary.ips>0&&<span className="itag" style={{background:"rgba(16,185,129,.08)",color:"var(--grn)"}}>{result.ioc_summary.ips} IPs</span>}
            {result.ioc_summary.domains>0&&<span className="itag" style={{background:"rgba(251,191,36,.08)",color:"var(--ylw)"}}>{result.ioc_summary.domains} Domains</span>}
            {result.ioc_summary.paths>0&&<span className="itag" style={{background:"rgba(245,158,11,.08)",color:"var(--org)"}}>{result.ioc_summary.paths} Paths</span>}
            {result.ioc_summary.registry>0&&<span className="itag" style={{background:"rgba(239,68,68,.08)",color:"var(--red)"}}>{result.ioc_summary.registry} Registry</span>}
          </div>}

          {/* Query */}
          <div className="qhdr">
            <h3>Generated Query</h3>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span className="sev" style={{background:SV[result.severity]?.bg,color:SV[result.severity]?.c}}>{result.severity}</span>
              <button className={`cpbtn ${copied==="m"?"ok":""}`} onClick={()=>cp(result.query,"m")}>{copied==="m"?"✓ Copied":"📋 Copy"}</button>
            </div>
          </div>
          <div className="qcode" dangerouslySetInnerHTML={{__html:hl(result.query)}} />

          {/* Explanation */}
          {result.explanation && <div className="exp"><h4>What this query looks for</h4><p>{result.explanation}</p></div>}

          {/* MITRE + Notes */}
          {(result.mitre?.length>0||result.notes?.length>0)&&<div className="meta">
            {result.mitre?.length>0&&<div className="meta-s"><h4>MITRE ATT&CK</h4><div>{result.mitre.map(m=><span key={m} className="mtag">{m}</span>)}</div></div>}
            {result.notes?.length>0&&<div className="meta-s"><h4>Notes</h4><div className="notes">{result.notes.map((n,i)=><div key={i}>{i+1}. {n}</div>)}</div></div>}
          </div>}

          {/* Intent JSON (toggle) */}
          {result.intent_json && <div style={{padding:"0 14px 8px"}}>
            <button className="mbtn" style={{fontSize:9}} onClick={()=>setShowIntent(!showIntent)}>
              {showIntent?"▲ Hide":"▼ Show"} Intent JSON (what the model extracted)
            </button>
            {showIntent && <div className="intent-box">{JSON.stringify(result.intent_json, null, 2)}</div>}
          </div>}

          {/* STAR Rule */}
          {result.star_rule && <div style={{padding:"10px 14px",borderTop:"1px solid var(--bdr)"}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
              <h4 style={{fontSize:12,fontWeight:600}}>STAR Custom Rule</h4>
              <button className={`cpbtn ${copied==="sr"?"ok":""}`} onClick={()=>cp(result.star_rule,"sr")}>{copied==="sr"?"✓":"📋"}</button>
            </div>
            <div className="qcode" style={{maxHeight:180}} dangerouslySetInnerHTML={{__html:hl(result.star_rule)}} />
          </div>}

          {/* Feedback */}
          {result.query_hash && <div className="fb-row">
            <span style={{fontSize:10,color:"var(--tx2)",marginRight:6}}>Rate this query:</span>
            {["useful","valid","noisy","invalid"].map(v=>
              <button key={v} className={`fb-btn ${feedbackSent===v?"sent":""}`}
                onClick={()=>sendFeedback(v)} disabled={!!feedbackSent}>
                {v==="useful"?"👍":v==="valid"?"✓":v==="noisy"?"📢":v==="invalid"?"❌":""} {v}
              </button>
            )}
            {feedbackSent && <span style={{fontSize:9,color:"var(--grn)",marginLeft:4}}>Recorded ✓</span>}
          </div>}
        </div>}

        {/* Error fallback */}
        {result?.type==="error" && <div className="card">
          <div className="banner ylw">⚠ {result.explanation}</div>
          <div className="warn">{result.warnings?.map((w,i)=><div key={i}>• {w}</div>)}</div>
        </div>}
      </div>}

      {/* ═══ LIBRARY ═══ */}
      {tab==="lib"&&<div>
        <h2 className="sec">Query Library</h2>
        <p className="sub">{library.length} pre-built S1QL queries — MITRE-mapped, platform-tagged</p>
        <div className="pills">{CATS.map(c=><button key={c} className={`pill ${libCat===c?"on":""}`} onClick={()=>setLibCat(c)}>{c==="All"?"All":c.replace(/-/g," ")}</button>)}</div>
        {Object.entries(gLib).map(([cat,qs])=><div key={cat} className="lgrp"><h3>{cat.replace(/-/g," ")} — {qs.length}</h3>
          {qs.map(q=><div key={q.id} className="litem">
            <div className="lhdr" onClick={()=>setLibExp(libExp===q.id?null:q.id)}>
              <div style={{flex:1}}>
                <span className="ptag">{q.platform}</span><h4>{q.title}</h4>
                <p>{q.description}</p>
              </div>
              <div style={{display:"flex",gap:5}}>
                <button className={`cpbtn ${copied===q.id?"ok":""}`} onClick={e=>{e.stopPropagation();cp(q.query,q.id)}}>{copied===q.id?"✓":"📋"}</button>
                <span style={{color:"var(--tx3)",fontSize:14}}>{libExp===q.id?"▲":"▼"}</span>
              </div>
            </div>
            {libExp===q.id&&<div className="lbody">
              <div style={{marginTop:5}}>{(typeof q.mitre==="string"?JSON.parse(q.mitre):q.mitre||[]).map(m=><span key={m} className="mtag">{m}</span>)}</div>
              <div className="qcode" style={{borderRadius:5,marginTop:8,maxHeight:250}} dangerouslySetInnerHTML={{__html:hl(q.query)}} />
            </div>}
          </div>)}
        </div>)}
      </div>}

      {/* ═══ THREATS ═══ */}
      {tab==="threats"&&<div>
        <h2 className="sec">Threat Intel</h2>
        <p className="sub">Live feeds — CISA KEV, ThreatFox, Feodo, MalwareBazaar, URLhaus</p>
        <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
          <input className="search" placeholder="🔍 Search..." value={tSearch} onChange={e=>setTSearch(e.target.value)} />
          <select className="sel" value={tSrc} onChange={e=>setTSrc(e.target.value)}>
            <option value="All">All Sources</option>
            {fSrcs.map(s=><option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div style={{color:"var(--tx3)",fontSize:10,marginBottom:8}}>{filtT.length} threats</div>
        {filtT.map(t=><div key={t.id} className="tcard">
          <div className="ttop">
            <div className="tinfo">
              <div className="tbadges">
                <span className="sev" style={{background:SV[t.severity]?.bg,color:SV[t.severity]?.c}}>{t.severity}</span>
                <span className="sev" style={{background:"rgba(99,102,241,.08)",color:"#818cf8"}}>{t.source}</span>
              </div>
              <h3>{t.title}</h3>
              <p className="desc">{t.description}</p>
              <div>{(t.mitre||[]).map(m=><span key={m} className="mtag">{m}</span>)}</div>
            </div>
            <button className="gqbtn" onClick={()=>genFromThreat(t)}>⚡ Query</button>
          </div>
        </div>)}
      </div>}

      {/* ═══ HISTORY ═══ */}
      {tab==="history"&&<div>
        <h2 className="sec">Query History</h2>
        <p className="sub">Team-shared, persisted in database</p>
        {!history.length&&<div style={{padding:30,textAlign:"center",color:"var(--tx3)",fontSize:11}}>No queries yet.</div>}
        {history.map(h=><div key={h.id} className="hitem">
          <div className="hhdr" onClick={()=>setExpH(expH===h.id?null:h.id)}>
            <div style={{display:"flex",alignItems:"center",flex:1,minWidth:0}}>
              <span className="htbadge" style={{
                background:h.input_type==="url"?"rgba(168,85,247,.1)":h.input_type==="ioc"?"rgba(16,185,129,.08)":"rgba(99,102,241,.08)",
                color:h.input_type==="url"?"#c084fc":h.input_type==="ioc"?"var(--grn)":"#818cf8"
              }}>{h.input_type?.toUpperCase()}</span>
              <span className="hprev">{h.input_text}</span>
            </div>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span className="conf">{Math.round((h.confidence||0)*100)}%</span>
              <span className="htime">{h.created_at?.slice(0,16)}</span>
            </div>
          </div>
          {expH===h.id&&<div style={{padding:"0 14px 12px"}}>
            <div style={{display:"flex",justifyContent:"space-between",padding:"6px 0"}}>
              <span style={{fontSize:11,fontWeight:600}}>S1QL Query</span>
              <div style={{display:"flex",gap:4}}>
                <span className="vbadge" style={{background:VS[h.validation_status]?.bg||"",color:VS[h.validation_status]?.c||""}}>{VS[h.validation_status]?.icon} {h.validation_status}</span>
                <button className={`cpbtn ${copied===`h${h.id}`?"ok":""}`} onClick={()=>cp(h.query_text,`h${h.id}`)}>{copied===`h${h.id}`?"✓":"📋"}</button>
              </div>
            </div>
            <div className="qcode" style={{borderRadius:5,maxHeight:220}} dangerouslySetInnerHTML={{__html:hl(h.query_text)}} />
          </div>}
        </div>)}
      </div>}

      {/* ═══ STAR RULES ═══ */}
      {tab==="star"&&<div>
        <h2 className="sec">STAR Custom Rule Generator</h2>
        <p className="sub">Broader field coverage for continuous detection</p>
        <textarea value={input} onChange={e=>setInput(e.target.value)} placeholder="Paste IOCs (hashes, IPs, domains, paths)..." style={{minHeight:90}} />
        <button className="gbtn" onClick={()=>{setMode("plain");gen();}} disabled={!input.trim()}>🛡 Generate Rule</button>
        {result?.star_rule && tab==="star" && <div className="card">
          <div className="qhdr"><h3>STAR Rule</h3><button className={`cpbtn ${copied==="sc"?"ok":""}`} onClick={()=>cp(result.star_rule,"sc")}>{copied==="sc"?"✓":"📋"}</button></div>
          <div className="qcode" dangerouslySetInnerHTML={{__html:hl(result.star_rule)}} />
        </div>}
      </div>}

      <div style={{padding:"24px 0 12px",textAlign:"center",color:"var(--tx3)",fontSize:9}}>
        S1 Query Assistant v3 · Phi-4-mini · {library.length||70} Queries · ThreatOlls Ready
      </div>
    </div></>
  );
}
