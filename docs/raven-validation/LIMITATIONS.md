# RAVEN — Limitations

**Mandatory disclosure.** These are the known limitations of the current system as verified on 2026-07-21.

## Structural Limitations

### 1. Single Honeypot Instance
Raven's attacker intelligence derives from ONE Cowrie honeypot on ONE IP at ONE provider (Contabo). This means:
- No geographic attack pattern comparison
- No cross-provider infrastructure reuse detection
- Single point of data collection
- Attacker behavior may not generalize to all threat actors

### 2. Repository Scale Requirement
Cross-repo systemic pattern detection requires ≥3 repositories. With fewer repos:
- Systemic patterns = 0 (cannot fire)
- The compound value of cross-repo intelligence is not visible at small scale
- Value proposition scales with repository count

### 3. Redis TTL-Based Eviction
All cowrie session data lives in Redis with 30-day TTL:
- Historical analysis beyond 30 days is impossible
- No cold storage or archival pipeline exists
- Campaign data older than 7 days is evicted
- No TimescaleDB/InfluxDB time-series storage

### 4. No RAG System
Contrary to what "AI-powered intelligence" might imply:
- No vector database (FAISS, ChromaDB, Pinecone)
- No embedding generation pipeline
- No semantic retrieval
- No knowledge base with chunked documents
- The "intelligence" is deterministic signal correlation, not LLM-based reasoning
- This is a design choice, not a bug — but it must be documented honestly

### 5. AI Is Optional and Non-Critical
- All 10 composite priority signals are deterministic
- AI (Groq/Claude/GPT) is used only for Cowrie session enrichment
- AI can fail without affecting the scoring pipeline
- CodeGuard Copilot works fully offline without AI
- "AI-powered" in marketing must not imply AI is required

### 6. No Autonomous Actions
- CRYSTAL triage gates alerts but never auto-blocks
- All "response" actions require human approval
- No automated firewall rules, no auto-ban
- This is intentional security design

### 7. Telegram Bot Polling Limitation
The breach-monitor's Telegram bot uses long-polling (getUpdates), not webhooks:
- Can miss messages during connection drops
- Polling loop runs in a gunicorn worker thread
- No guaranteed message delivery

### 8. .onion Source Availability
- 1 of 8 configured .onion sources is reachable at any time
- Tor hidden services are inherently unreliable
- Scraping depends on external infrastructure we don't control
- Expect low yield from .onion monitoring relative to Telegram

### 9. Python Package Maturity
CodeGuard Copilot Python package is v0.2.0:
- 17 unit tests (not comprehensive)
- Not battle-tested in production CI/CD
- No TypeScript→Python parity guarantees
- Pattern JSON is the shared source of truth

### 10. VS Code Extension Status
- Fixed bugs exist in the codebase (committed but not compiled due to npm network issues)
- Not published to VS Code Marketplace
- JetBrains support is scaffolding only (pattern export, no plugin)

### 11. No Multi-Tenancy
- Campaigns are global across all WraithWall users
- No customer/tenant isolation in intelligence data
- All Raven APIs share the same PostgreSQL instance

### 12. Dashboard Limited to Server-Rendered HTML
- No Vue/React frontend for Raven
- Dashboard is a single Jinja template (479 lines)
- No real-time WebSocket updates
- No mobile-responsive design

### 13. Test Coverage Gaps
- 169 tests for Raven (good coverage of intelligence modules)
- 17 tests for CodeGuard Copilot Python (basic coverage)
- No integration tests between CodeGuard and Raven
- No end-to-end test from Cowrie attack → CodeGuard finding elevation
- No load/stress tests

### 14. Documentation Gaps
- No OpenAPI/Swagger specification
- No architectural decision records (ADRs)
- API docs exist only in the Help tab (not searchable)
- No deployment guide for CodeGuard Copilot

## What Is NOT Planned

The following capabilities are explicitly NOT on the roadmap:
- Real-time autonomous attack blocking (security risk)
- LLM-based code modification without human review
- Sending source code to external AI providers without explicit opt-in
- Sharing attacker intelligence across tenants without explicit consent
