# Athena

**local Ollama Phi mini based theat hunting copilot**

Entirely free. Self-hosted. Low resource.

## What It Does

- **Natural Language → S1QL**: Describe what you want to hunt → get validated S1QL
- **IOC Extraction**: Paste hashes, IPs, domains → multi-block hunt query + STAR rule
- **URL Parsing**: Paste a threat report URL → IOCs extracted → query generated
- **70-Query Library**: Pre-built, MITRE-mapped, platform-tagged, editable
- **Live Threat Feeds**: CISA KEV, ThreatFox, Feodo, MalwareBazaar, URLhaus (all free)
- **Schema Validation**: Every query checked against your tenant's field dictionary
- **Confidence Scoring**: Analysts see how reliable each query is
- **Feedback Loop**: Analysts rate queries → system learns which are gold/noisy/broken

## Architecture

```
Analyst Input → Intent Extractor (Phi-4-mini) → Deterministic Compiler → Validator → S1QL
                                                                                    ↓
                                                                              SQLite (history,
                                                                              feedback, feeds)
```

**Key principle**: The LLM never writes S1QL. It only extracts structured intent.
The compiler generates queries deterministically. The validator checks them.

## Stack

| Component | Technology | Cost |
|-----------|-----------|------|
| Backend | FastAPI + SQLite | Free |
| LLM | Phi-4-mini via Ollama | Free (MIT license) |
| Threat Feeds | CISA, abuse.ch APIs | Free |
| Frontend | React | Free |

**Resource usage**: ~3GB RAM peak, <3GB disk. Ollama auto-unloads after 5min idle.

## Quick Start

```bash
# 1. Clone and setup
git clone <your-repo> && cd s1-assistant
make setup

# 2. Install Ollama + Phi-4-mini (optional but recommended)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi4-mini

# 3. Start
make run

# 4. Open API docs
open http://localhost:8000/docs

# 5. Add feed sync to crontab
crontab -e
# Add: 0 */6 * * * cd /path/to/s1-assistant/backend && python feed_fetcher.py
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/generate` | Main: NL/IOC/URL → S1QL + validation |
| POST | `/api/generate/iocs` | Structured IOCs → S1QL (ThreatOlls) |
| GET | `/api/library` | Query library (filterable) |
| GET | `/api/threats` | Cached threat feed entries |
| POST | `/api/threats/{id}/query` | Generate from threat entry |
| GET | `/api/history` | Team query history |
| POST | `/api/feedback` | Analyst verdict |
| POST | `/api/validate` | Validate arbitrary S1QL |
| GET | `/api/schema` | Current schema registry |
| GET | `/api/health` | System health check |

## Customization

### Schema Registry
Edit `backend/schema_registry.json` to match your SentinelOne tenant:
1. Open S1 console → Deep Visibility → use autocomplete to verify fields
2. Update the JSON file
3. Hit `POST /api/schema/reload`

### Query Library
Queries are in SQLite. Edit via the API or directly:
```bash
sqlite3 data/s1assistant.db "UPDATE query_library SET query='...' WHERE id='c1'"
```

### Suppressions
Add environment-specific suppressions:
```bash
curl -X POST http://localhost:8000/api/suppressions \
  -H "Content-Type: application/json" \
  -d '{"suppression_type":"process_name","value":"our_internal_updater.exe","scope":"global"}'
```

## Maintenance

| Task | Frequency | Time |
|------|-----------|------|
| Schema registry update | Quarterly | 30 min |
| Review analyst feedback | Weekly | 15 min |
| Promote good queries | Monthly | 30 min |
| Check feed cron log | Monthly | 5 min |
| **Total monthly** | | **~2 hours** |
