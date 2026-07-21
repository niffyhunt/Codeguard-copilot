# RAVEN — Capability Status Matrix

**Verified:** 2026-07-21 against commit `2b67780` (main branch)
**Method:** Source code audit + runtime verification where Redis/DB available

## Core Intelligence Engine

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Repository registration | YES | YES | YES | YES | `wraith_raven/router.py:56-135` |
| Clone + scan | YES | YES | YES | YES | `_clone_and_scan()` at line 610 |
| Deterministic fingerprinting | YES | YES | YES | YES | SHA-256 per `repo+file+line+check` |
| RavenScan CLI integration | YES | YES | PARTIAL | YES | Imports `ravenscan` at scan time, 42 source files |
| CodeGuard pattern scanning | YES | YES | YES | YES | 15 patterns, `codeguard.py:7-175` |
| Findings storage | YES | YES | YES | YES | `raven_finding` table, 2 repos live |
| Finding status updates | YES | YES | YES | YES | open/resolved/false_positive/wont_fix |
| Webhook intake (GitHub) | YES | YES | VERIFIED | YES | `POST /api/raven/hooks/github` |

## Sprint 1 (intel.py)

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Regression detection | YES | YES | YES | YES | `intel.py:25-48`, test covered |
| Baseline anomaly | YES | YES | YES | YES | `intel.py:55-89`, statistical deviation |
| Root cause clustering | YES | YES | YES | YES | `intel.py:96-119`, CWE+directory grouping |
| Threat surface weighting | YES | YES | YES | YES | `intel.py:126-155`, path-based adjustment |
| Commit correlation | YES | YES | PARTIAL | YES | `intel.py:169-216`, requires git in clone dir |
| Complexity trending | YES | YES | YES | YES | `intel.py:223-248`, file-level metrics |

## Sprint 2 (cross_repo.py + phase modules)

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Cross-repo pattern detection | YES | YES | YES | YES | 3+ repo threshold, shared cause inference |
| Dependency graph BFS | YES | YES | YES | YES | `raven_intel_graph`, version-hashed |
| CISA KEV matching | YES | YES | YES | YES | Weekly cached, CVE matching, 1 match live |
| OWASP Top 10 mapping | YES | YES | YES | YES | Deterministic CWE→OWASP table |
| Composite priority scoring | YES | YES | YES | YES | 10 signals, elevation system |
| Signal-based finding filter | YES | YES | YES | YES | `?kev=1&systemic=1&min_elevation=2` |

## Phase A — Cowrie Attacker Bridge

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Cowrie session reading | YES | YES | YES | YES | Reads `cowrie_completed:*` Redis keys |
| Attacker alignment scoring | YES | YES | YES | YES | CWE→MITRE mapping, 21 CWEs covered |
| Deception correlation | YES | YES | YES | YES | HoneyFS bait path matching |
| Per-finding attacker signals | YES | YES | YES | YES | Stored in `raven_intel_result` |

## Phase 3 — Live Attacker Telemetry

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| IOC→dependency annotation | YES | YES | YES | YES | Package extraction from URLs/commands |
| Campaign→repo risk scoring | YES | YES | PARTIAL | YES | MITRE stage overlap scoring |
| Behavioral→vuln mapping | YES | YES | YES | YES | 10 behavior→CWE, 12 tool→check |

## Phase B — API Integrations

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| GreyNoise IP classification | YES | YES | NOT LIVE | YES (code) | `asn_intelligence.py:_enrich_greynoise` |
| Censys cert transparency | YES | YES | NOT LIVE | YES (code) | `asn_intelligence.py:_enrich_censys` |
| Breach→campaign correlation | YES | YES | YES | YES | `cross_repo_phaseb.py` |
| Domain-wide breach search | YES | YES | YES | YES | Breach-monitor API proxy |

## Phase C — Dark-Web + Campaign

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Telegram breach monitoring | YES | YES | YES | YES | Webhook-based, 23 keywords |
| .onion dark-web scanning | YES | YES | YES | YES | Tor SOCKS5, 1/8 sources live |
| Credential lure→Raven bridge | YES | YES | YES | YES | Canary trigger path matching |
| ATT&CK Navigator export | YES | YES | YES | YES | Layer JSON, v5.1 format |
| Kill-chain rendering data | YES | YES | YES | YES | Campaign→stage timeline |

## Phase D — Learning Pipeline

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| Credential pattern extraction | YES | YES | YES | YES | 12 regex from breach data |
| Attacker→code correlation | YES | YES | YES | YES | Tool→CWE mapping, 12 tools |
| CodeGuard pattern generation | YES | YES | YES | YES | New rules from learned data |
| Threat-to-code mapping | YES | YES | YES | YES | 10 MITRE stages mapped |

## Infrastructure

| Capability | Exists | Executed | Verified | Prod Ready | Evidence |
|-----------|--------|----------|----------|------------|----------|
| PostgreSQL persistence | YES | YES | YES | YES | `raven_intel_result` + 7 tables |
| Redis caching/state | YES | YES | YES | YES | Cowrie sessions, blocklists |
| APScheduler (hourly) | YES | YES | YES | YES | 12 jobs registered |
| Telegram alerts | YES | YES | YES | YES | Sprint2+Phase reports |
| API authentication | YES | YES | YES | YES | Session + API key |
| Dashboard (web) | YES | YES | YES | YES | `templates/raven-dashboard.html` |

## What Does NOT Exist

| Claimed/Expected | Status | Evidence |
|-----------------|--------|----------|
| RAG-based knowledge retrieval | DOES NOT EXIST | No vector store, no embeddings, no retrieval pipeline |
| Embedding generation | DOES NOT EXIST | No embedding model imported anywhere in Raven |
| Semantic search | DOES NOT EXIST | Pattern matching only, no vector search |
| AI Concierge for Raven | SEPARATE SYSTEM | `ai_concierge/` exists but not wired to Raven |
| Autonomous response actions | DOES NOT EXIST | All actions require explicit user confirmation |
| Multi-tenant campaigns | DOES NOT EXIST | Campaigns are global, not tenant-scoped |
| Full shell emulation | PARTIAL | Cowrie has HoneyFS but limited command emulation |
| Real-time attack blocking | DOES NOT EXIST | CRYSTAL triage gates alerts, doesn't auto-block |

## Test Coverage

| Area | Tests | Status |
|------|-------|--------|
| Sprint 2 (core) | 38 | PASSING |
| Phase A (cowrie bridge) | 16 | PASSING |
| Phase 3 (telemetry) | 13 | PASSING |
| Phase B (API integrations) | 10 | PASSING |
| Phase C (dark-web) | 13 | PASSING |
| Phase D (learning) | 14 | PASSING |
| CodeGuard Copilot (Python) | 17 | PASSING |
| **TOTAL** | **121** | **ALL PASSING** |
