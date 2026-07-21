# RAVEN — Verified Architecture

**Status:** Documented from code audit. All components verified against source.

## System Composition

```
                    ┌──────────────────────────────────┐
                    │        WRAITHWALL (Flask)         │
                    │                                  │
  ┌─────────────────┤  main.py (14,500 lines)           │
  │                 │  APScheduler (12 jobs)            │
  │                 │  PostgreSQL (SQLAlchemy)          │
  │                 │  Redis (caching + state)          │
  │                 └──────────────┬───────────────────┘
  │                                │
  │    ┌───────────────────────────┼───────────────────────────┐
  │    │                           │                           │
  │    ▼                           ▼                           ▼
  │ ┌──────────┐          ┌───────────────────┐       ┌──────────────┐
  │ │ COWRIE   │          │  RAVEN ENGINE     │       │ BREACH       │
  │ │ INTEL    │          │  wraith_raven/    │       │ MONITOR      │
  │ │ ──────── │          │  ──────────────── │       │ ─────────    │
  │ │ 2222 LOC │          │  24 files         │       │ 5001:5001    │
  │ │ Session  │          │  • intel.py       │       │ HIBP API     │
  │ │ pipeline │          │  • cross_repo.py  │       │ paste scans  │
  │ │ 6 events │          │  • codeguard.py   │       │ GitHub scans │
  │ │ 10 steps │          │  • models.py      │       │ Telegram bot │
  │ │ MITRE    │          │  • router.py      │       └──────────────┘
  │ │ mapping  │          │  • 5 phase modules│
  │ └────┬─────┘          └────────┬──────────┘
  │      │                         │
  │      │   ┌─────────────────────┼─────────────────────┐
  │      │   │                     │                     │
  │      ▼   ▼                     ▼                     ▼
  │ ┌──────────────────────────────────────────────────────────┐
  │ │            SATELLITE INTELLIGENCE ENGINES                │
  │ │                                                          │
  │ │  campaign_correlator.py  behavioral_dna.py              │
  │ │  asn_intelligence.py     bgp_monitor.py                 │
  │ │  spectra_ioc.py          credential_propagation.py      │
  │ │  deception_event_bus.py  canary_service.py              │
  │ │  forge_infra.py          unison_score.py                │
  │ │  fusion_stix.py          recalibration.py               │
  │ │  chronos_temporal.py     replay_tty.py                  │
  │ │  fingerprint_corpus.py   live_events.py                 │
  │ └──────────────────────────────────────────────────────────┘
  │
  │                        ┌──────────────────────────┐
  │                        │  CODEGUARD COPILOT       │
  │                        │  ─────────────────────   │
  │                        │  /home/deploy/           │
  │                        │  codeguard-copilot/      │
  │                        │                          │
  │                        │  • VS Code extension     │
  │                        │  • Python CLI (pip)      │
  │                        │  • 32 patterns (JSON)    │
  │                        │  • Raven bridge (API)    │
  │                        │  • AI providers          │
  │                        └──────────┬───────────────┘
  │                                   │
  │                  HTTP API         │ RAVEN_API_KEY
  │                  ────────         │
  │                  Optional         ▼
  │              ┌──────────────────────────────┐
  │              │  RAVEN API (/api/raven/)     │
  │              │  ──────────────────────────  │
  │              │  /intel/finding/:id/signals  │
  │              │  /intel/attacker/summary     │
  │              │  /intel/breach/summary       │
  │              │  /intel/systemic             │
  │              │  /intel/dependencies         │
  │              │  /intel/kev                  │
  │              │  /intel/phasec/summary       │
  │              │  /intel/learning/summary     │
  │              └──────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────────────┐
│           COWRIE HONEYPOT VPS (217.76.55.55)         │
│                                                      │
│  cowrie-honeypot (SSH:2222, Telnet:2223)             │
│  cowrie-shipper → Redis cowrie:log                   │
│  malware-worker → VirusTotal analysis                │
│  Tor daemon (9050)                                   │
│  deception-web (HTTP honeypot)                       │
│  BTCPay Server                                       │
└──────────────────────────────────────────────────────┘
```

## Data Flow (Verified)

### 1. Code → Finding (CodeGuard)

```
Developer code → CodeGuard scanner → 32 pattern regex match → Finding
```

**Path:** `codeguard/engine.py:CodeGuardEngine.scan_file()`
**Output:** `Finding` object with rule_id, severity, file, line, CWE, fix

### 2. Finding → Intelligence (Raven)

```
Finding → composite_priority_signals() → 10 signal sources:
  ├── systemic (cross_repo.py) — cross-repo fingerprint ≥3 repos
  ├── regression (intel.py) — previously resolved, returned
  ├── threat_weight (intel.py) — path-based severity adjustment
  ├── baseline_anomaly (intel.py) — statistical deviation
  ├── kev_status (cross_repo.py) — CISA KEV CVE match
  ├── owasp_category (cross_repo.py) — CWE→OWASP mapping
  ├── attacker_aligned (cross_repo_attacker.py) — cowrie session correlation
  ├── deception_correlated (cross_repo_attacker.py) — HoneyFS bait match
  ├── breach_aligned (cross_repo_phaseb.py) — breach-monitor data match
  └── lure_triggered (cross_repo_phasec.py) — canary credential trigger
→ Composite priority (base severity + elevation sum)
```

### 3. Attacker → Code (Cowrie → Raven)

```
Attacker hits SSH:2222 → Cowrie logs → shipper → Redis
  → cowrie_intelligence.py pipeline (10 steps)
  → Session stored: cowrie_completed:{sid}
  → MITRE mapped, IOC extracted, threat scored
  → cross_repo_attacker.py reads sessions
  → Maps CWE→MITRE for each Raven finding
  → Stores attacker_aligned signals
```

### 4. Dark-Web → Code (Telegram/Onion → Raven)

```
Telegram channel post → webhook → _process_channel_breach_check()
  → 23 keyword scan + domain match
  → raven_intel_result (darkweb)
  → cross_repo_phaseb.py correlation
  → breach_aligned signal per finding

.onion forum → Tor SOCKS5 → darkweb_tor.py scrape
  → 30 keyword scan + domain match
  → raven_intel_result (onion)
  → Same breach pipeline
```

### 5. Learning → Detection (Pipeline D)

```
breach data + cowrie sessions + findings
  → cross_repo_phase_d.py:
     D.1: credential pattern extraction (12 regex)
     D.2: attacker→code correlation (tool→CWE mapping)
     D.3: CodeGuard pattern generation (auto-rules)
     D.4: threat-to-code mapping database
  → New detection patterns
  → Feed back into CodeGuard pattern library
```

## What Is Deterministic vs AI-Assisted

| Category | Deterministic | AI-Assisted |
|----------|--------------|-------------|
| Pattern detection | 32 regex patterns | — |
| KEV matching | CVE cross-ref | — |
| OWASP mapping | CWE→OWASP table | — |
| Cross-repo detection | Fingerprint clustering | — |
| Dependency impact | BFS graph traversal | — |
| Attacker correlation | CWE→MITRE mapping | — |
| Deception correlation | File path matching | — |
| Composite scoring | Signal sum + cap | — |
| Cowrie session analysis | — | Groq/Claude/GPT (optional) |
| CodeGuard AI deep scan | — | Claude/GPT/Groq (optional) |
| Threat explanation | — | AI provider (optional) |

## Scheduler (12 hourly jobs)

```python
# main.py:14210-14222
retrain_models        weekly
mimicry_engine        every 4h
breach_scan_cycle     every 6h
bgp_monitor           every 15min
paste_monitor         every 2h
github_monitor        every 4h
daily_digest          8:00 UTC
canarytokens_alerts   every 15min
trial_billing         hourly
webhook_retries       every 1min
payment_poll          every 5min
raven_cross_repo      hourly  ← Sprint 2+3+A+B+C+D pipeline
raven_kev_refresh     weekly
```
