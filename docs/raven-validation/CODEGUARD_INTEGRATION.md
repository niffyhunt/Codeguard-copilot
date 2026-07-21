# CodeGuard Copilot ↔ Raven — Integration Verification

**Verified:** 2026-07-21

## Data Boundary Architecture

```
┌─────────────────────────────────┐
│  DEVELOPER MACHINE (LOCAL)      │
│                                 │
│  CodeGuard Copilot              │
│  ├── 32 pattern regex scan      │
│  ├── CLI / VS Code / Pre-commit │
│  ├── AI analysis (optional)      │
│  │   └── Sends code snippets →  │───→ AI Provider (Claude/GPT/Groq)
│  │       to configured provider │     ONLY if CODEGUARD_AI_KEY set
│  └── Raven enrichment (optional)│───→ WraithWall API
│      └── Sends finding metadata │     ONLY if RAVEN_API_KEY set
│          (rule_id, CWE, file)    │     NO source code transmitted
│          to Raven API            │
└─────────────────────────────────┘
```

## What CodeGuard Sends to Raven

When Raven enrichment is enabled (`RAVEN_API_KEY` set):

```python
# From codeguard/raven.py
# Sent: finding metadata (rule_id, severity, CWE, file_path, language)
# NOT sent: source code, file contents, repository data

Request: GET /api/raven/intel/attacker/summary
Headers: X-API-Key, X-Requested-With
Response: { attacker_aligned: bool, deception_correlated: bool, ... }
```

**No source code ever leaves the local machine to reach Raven.** Only finding metadata is transmitted.

## What Raven Returns to CodeGuard

```json
{
  "attacker_aligned": true,
  "alignment_score": 0.8,
  "matched_tactics": ["credential_access"],
  "matched_session_count": 3,
  "deception_correlated": false,
  "bait_id": null
}
```

These signals are additive — they enrich the finding without modifying the original scan result.

## Integration Points

### 1. Python CLI (codeguard/raven.py)
```
codeguard scan . → engine.scan_directory() → findings
  → if RAVEN_API_KEY: enrich_findings(findings)
  → each finding gets raven block appended
```

### 2. VS Code Extension (TypeScript — not yet implemented in Python bridge)
The TypeScript extension has `src/raven/bridge.ts` and `src/raven/feedback.ts`:
- `RavenIntelligenceBridge.ingestEvent()` — receives attacker events
- `RavenThreatFeedback.generateIntelligence()` — maps findings to MITRE

These are compiled into the VS Code extension but the extension currently has no runtime Python bridge to the live Raven API. The Python package `codeguard/raven.py` provides this bridge.

### 3. Telemetry Pipeline (Server-Side)
Raven's hourly orchestrator (`cross_repo.py:run_sprint2_intel`) runs:
1. Cross-repo patterns
2. Dependency impact
3. KEV/OWASP
4. Cowrie attacker correlation
5. Dark-web monitoring
6. Learning pipeline
7. Composite signal recompute

CodeGuard findings enriched through this pipeline are stored in `raven_intel_result` and available via the API — no CodeGuard installation required on the server.

## Verification Status

| Integration Path | Status | Verified |
|-----------------|--------|----------|
| Python CLI → Raven API | Implemented | YES (`codeguard/raven.py`) |
| Python CLI → AI Provider | Implemented | YES (`codeguard/providers.py`) |
| VS Code → Raven Bridge | Implemented (TS) | PARTIAL (not runtime tested) |
| VS Code → Raven Feedback | Implemented (TS) | PARTIAL (not runtime tested) |
| Server → Cowrie → Raven | Live | YES (hourly pipeline) |
| Server → Dark-web → Raven | Live | YES (webhook + Tor) |
| Server → Learning → CodeGuard | Implemented | YES (Phase D pipeline) |

## What Does NOT Happen

- CodeGuard Copilot does NOT send your source code to WraithWall
- CodeGuard Copilot does NOT require an internet connection (offline mode works)
- CodeGuard Copilot does NOT modify your files without explicit user action
- Raven does NOT auto-publish AI-generated rules without human review
- Raven does NOT block IPs or take autonomous defensive actions
