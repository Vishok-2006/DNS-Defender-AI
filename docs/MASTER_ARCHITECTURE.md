# DNS Defender AI — Master Architecture Document

**Version:** 3.0.0  
**Last Updated:** 2026-11-20  
**Project:** Final Year Placement Project

---

## 1. System Overview

DNS Defender AI is a cybersecurity monitoring platform that captures live DNS traffic, analyzes it using a Random Forest classifier combined with behavioral rules, and presents results in a professional SOC dashboard. It can optionally sinkhole malicious domains at the resolver level.

### 1.1 High-Level Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ LAN Clients │────▶│ dnsmasq DNS  │────▶│ Query Log       │
│             │     │ Resolver     │     │ (/var/log/...)  │
└─────────────┘     └──────────────┘     └────────┬────────┘
                                                   │
                            ┌──────────────────────┘
                            ▼
                   ┌─────────────────┐
                   │ FastAPI Backend │
                   │ • Log Tailer    │
                   │ • ML Pipeline   │
                   │ • PostgreSQL    │
                   │ • WebSocket Hub │
                   └────────┬────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       ┌──────────┐  ┌──────────┐  ┌──────────┐
       │ Frontend │  │ Blocking │  │ API Docs │
       │ (React)  │  │ (dnsmasq)│  │ (/docs)  │
       └──────────┘  └──────────┘  └──────────┘
```

---

## 2. Technology Stack

### 2.1 Backend
| Component | Version | Purpose |
|-----------|---------|---------|
| FastAPI | 0.110.0 | REST API + WebSocket server |
| Uvicorn | 0.28.0 | ASGI server (single worker) |
| SQLAlchemy | 2.0.28 | ORM for PostgreSQL/SQLite |
| PostgreSQL | 16 (Docker) | Production database |
| SQLite | 3.x | Development/test database |
| scikit-learn | 1.4.1.post1 | Random Forest inference |
| joblib | 1.3.2 | Model serialization |
| tldextract | 5.1.2 | Public suffix list parsing |
| scapy | 2.5.0 | Optional packet capture |
| httpx | 0.27.0 | NVIDIA NIM API client |
| pydantic | 2.6.4 | Request/response validation |

### 2.2 Frontend
| Component | Version | Purpose |
|-----------|---------|---------|
| React | 19.0.1 | UI framework |
| Vite | 8.3.0 | Build tool + dev server |
| Tailwind CSS | 4.3.3 | Utility-first styling |
| Recharts | 3.10.1 | Data visualization |
| TypeScript | 7.0.2 | Type safety |
| Vitest | 5.1.0 | Unit testing |

### 2.3 Infrastructure
| Component | Version | Purpose |
|-----------|---------|---------|
| Docker | 24.x | Containerization |
| Docker Compose | 2.x | Multi-service orchestration |
| nginx | 1.27 | Static file serving + API/WS proxy |
| dnsmasq | 2.91 | DNS resolver + sinkhole |
| tini | 0.19 | Init system for containers |

---

## 3. Database Schema

### 3.1 Core Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `dns_events` | Raw DNS queries | id, timestamp, src_ip, domain, query_type, response_code, source, blocked |
| `feature_vectors` | Extracted features per event | id, event_id (FK), entropy, digit_ratio, domain_len, features (JSON) |
| `ml_predictions` | Model output per event | id, event_id (FK), risk_score, is_malicious, classification, category, model_prob, rule_score, model_ver |
| `security_alerts` | Aggregated alerts | id, prediction_id (FK), domain, client_ip, category, classification, severity, status, risk_score, reasons (JSON), analyst_notes, analysis (JSON), occurrences, blocked, created_at, last_seen |
| `blocked_domains` | Sinkholed domains | domain (PK), reason, source, blocked_at |
| `allowlisted_domain` | Analyst exemptions | domain (PK), reason, added_at |
| `user_accounts` | Reserved for RBAC | id, username, password_hash, role, created_at |

### 3.2 Indexes
- `dns_events`: `timestamp`, `src_ip`, `domain`
- `ml_predictions`: `timestamp`, `event_id`
- `security_alerts`: `severity`, `status`, `last_seen`, composite `(domain, client_ip, last_seen)` for dedup
- `feature_vectors`: `event_id`

---

## 4. Backend Architecture

### 4.1 Application Factory Pattern

```python
# app/main.py → create_app(cfg: Settings) → FastAPI
```
- No global state; engine, session_factory, detector, service, hub created per-app
- Lifespan context manager handles startup/shutdown
- Single uvicorn worker (behavioral trackers + WebSocket hub live in memory)

### 4.2 Core Services

| Module | Responsibility |
|--------|----------------|
| `app/main.py` | FastAPI app factory, route registration, lifespan |
| `app/config.py` | Pydantic Settings (env vars + .env) |
| `app/db.py` | Engine/session factory, SQLite pragmas |
| `app/models.py` | SQLAlchemy ORM models |
| `app/schemas.py` | Pydantic request/response models |
| `app/service.py` | **Core pipeline**: query → features → detect → persist → alert → block |
| `app/classifier.py` | Random Forest + rule engine (noisy-OR combination) |
| `app/features.py` | Lexical + behavioral feature extraction |
| `app/monitor.py` | dnsmasq log tailer (query/result pairing) |
| `app/ingest.py` | Scapy sniffer + Zeek log parser |
| `app/hub.py` | Thread-safe WebSocket fan-out |
| `app/blocking.py` | Atomic blocklist file writer + domain validation |
| `app/stats.py` | Dashboard aggregates (dialect-aware SQL) |
| `app/nim.py` | NVIDIA NIM LLM explanations + offline fallback |
| `app/security.py` | API key dependency + WS auth |

### 4.3 Detection Pipeline

```
DNS Query (domain, client_ip, qtype, rcode)
        │
        ▼
┌───────────────────┐
│ Feature Extraction │
│  • Lexical (14)    │
│  • LM (2)          │
│  • Behavioral (7)  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Random Forest      │
│ P(malicious\|lex)  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Rule Engine        │
│  • Tunnelling      │
│  • Beaconing       │
│  • NXDOMAIN burst  │
│  • Query flood     │
│  • Phishing words  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Noisy-OR Combine  │
│ risk = 1 - Π(1-s) │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Thresholds        │
│ benign < 0.45     │
│ suspicious < 0.79 │
│ malicious ≥ 0.79  │
└─────────┬─────────┘
          │
          ▼
   Classification + Severity + Category + Reasons
```

---

## 5. Frontend Architecture

### 5.1 Current State (Single-Page Dashboard)
- File: `frontend/src/App.tsx` (~210 lines)
- Components: `Card`, `Stat`, `Pill`, inline tables/charts
- State: `useState` for health, stats, alerts, queries, blocked domains
- WebSockets: Custom `useSocket` hook with auto-reconnect
- API: `api.ts` with fetch wrapper + API key handling

### 5.2 Target Architecture (Multi-Page SOC Dashboard)
```
App Shell (persistent)
├── Sidebar Navigation
│   ├── OVERVIEW
│   │   └── Command Center
│   ├── MONITORING
│   │   ├── Live DNS Traffic
│   │   ├── Network Clients
│   │   └── DNS Resolver
│   ├── THREAT INTELLIGENCE
│   │   ├── Threat Detection
│   │   ├── Domain Intelligence
│   │   └── AI Analysis
│   ├── SECURITY
│   │   ├── Alerts
│   │   ├── Blocklist
│   │   └── Allowlist
│   ├── ANALYTICS
│   │   ├── Traffic Analytics
│   │   ├── Threat Analytics
│   │   └── Reports
│   ├── SYSTEM
│   │   ├── ML Model Performance
│   │   └── System Health
│   └── ADMINISTRATION
│       ├── User Management
│       └── Settings
├── Top Navigation
│   ├── Breadcrumb
│   ├── Global Search
│   ├── Live Status
│   ├── Notifications
│   ├── User Profile
│   └── Theme/Settings
└── Main Content Area
    ├── Page Header (title, description, actions, filters)
    └── Content (charts, tables, forms, detail views)
```

### 5.3 Design System (4 Themes)
1. **Midnight SOC** (dark, blue accents) — default
2. **Arctic Light** (light, cool tones)
3. **Matrix** (dark, green monospace)
4. **Nebula** (dark, purple gradients)

**Features:**
- Dark/Light/System modes
- Custom accent colors
- Compact/Comfortable density
- Persistent theme selection (localStorage)
- Reduced motion preference
- Sidebar collapse state
- Font scaling

---

## 6. DNS Integration

### 6.1 Resolver (dnsmasq)
- Runs in dedicated container (`dns-resolver`)
- Logs queries to shared volume `dns_logs`
- Reads blocklist from shared volume `dns_rules` (`/rules/blocked.conf`)
- Blocklist format: `server=/domain/` (NXDOMAIN for domain + subdomains)
- Reloads on SIGHUP (watcher in entrypoint.sh)
- Health check: `dig @127.0.0.1 health.check.local`

### 6.2 Backend Integration
- `CAPTURE_MODE=dnsmasq` (default in Docker)
- `DnsmasqTailer` tails `/var/log/dnsmasq/queries.log`
- Pairs query lines with reply lines → extracts NXDOMAIN
- Handles log rotation, truncation, partial lines
- `SCAPY` mode: raw packet capture (queries only, no response codes)
- `OFF` mode: API/import only

### 6.3 Blocking Flow
```
POST /api/v1/domains/block {domain, reason}
        │
        ▼
DefenderService.block_domain()
        │
        ├── Validate (regex, not trusted, not allowlisted)
        ├── Write to PostgreSQL (blocked_domains)
        ├── Update in-memory cache
        ├── Atomic write to /rules/blocked.conf
        └── dnsmasq receives SIGHUP → reloads blocklist
```

---

## 7. AI/ML Pipeline

### 7.1 Model Artifact
- File: `backend/models/dga_rf.joblib` (~17.9 MB)
- Contents: `{model, lm, features, thresholds, sklearn_version}`
- Model: `RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_leaf=20, class_weight='balanced')`
- Language Model: Character trigram LM (benign labels only, cross-fitted)
- Features: 14 lexical + 2 LM = 16 total

### 7.2 Training Data
- Dataset: chrmor/DGA_domains_dataset (674,837 rows)
- 337,500 DGA (25 families) + 337,337 benign (Alexa)
- Split: 70/15/15 random + 6 held-out families + 5-fold CV

### 7.3 Performance (from model_card.json)

| Metric | Random Split (test) | Unseen Families |
|--------|---------------------|-----------------|
| ROC-AUC | 0.965 | 0.795 |
| Accuracy | 91.0% | 72.1% |
| Precision (malicious) | 98.7% | 98.4% |
| Recall (malicious) | 78.4% | 49.7% |
| FPR | 1.0% | 0.9% |

### 7.4 Per-Family Recall (Unseen, Malicious Threshold)
| Family | Recall |
|--------|--------|
| ramnit | 95.5% |
| necurs | 91.2% |
| pykspa | 67.7% |
| conficker | 37.7% |
| gozi | 6.0% |
| suppobox | ~0% |

### 7.5 Detection Categories
| Category | Source |
|----------|--------|
| DGA (algorithmically generated domain) | RF model |
| DNS Tunnelling / Exfiltration | Rules (label length, encoding, TXT ratio) |
| NXDOMAIN Burst (DGA activity) | Rules (client NXDOMAIN burst) |
| Phishing-style Domain | Rules (lure words + hyphens) |
| Malicious Beaconing | Rules (regular intervals) |
| Anomalous DNS Behaviour | Fallback |
| Benign | No signals |

---

## 8. API Endpoints

### 8.1 Health & Config
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/health` | No | Service status, model loaded, DB, monitor |
| GET | `/api/v1/settings` | Yes | Runtime policy (alert_only, auto_block, thresholds) |
| PATCH | `/api/v1/settings` | Yes | Update runtime policy |

### 8.2 Dashboard Data
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/stats` | Yes | Overview + timeseries + top domains |
| GET | `/api/v1/queries` | Yes | Paginated DNS events with predictions |
| GET | `/api/v1/alerts` | Yes | Paginated alerts with filters |

### 8.3 DNS Operations
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/dns/test-query` | Yes | Analyze a domain (persists + WS push) |
| POST | `/api/v1/dns/simulate` | Yes | Demo scenarios (benign/dga/tunnelling/phishing) |
| POST | `/api/v1/import/zeek` | Yes | Import Zeek dns.log |

### 8.4 Alert Management
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/alerts/{id}` | Yes | Alert detail |
| PATCH | `/api/v1/alerts/{id}` | Yes | Update status/notes |
| POST | `/api/v1/alerts/{id}/analyze` | Yes | LLM explanation (NVIDIA NIM or offline) |

### 8.5 Block/Allow Lists
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/domains/blocklist` | Yes | List blocked domains |
| POST | `/api/v1/domains/block` | Yes | Block domain (sinkhole) |
| POST | `/api/v1/domains/unblock` | Yes | Unblock domain |
| GET | `/api/v1/domains/allowlist` | Yes | List allowlisted + trusted |
| POST | `/api/v1/domains/allowlist` | Yes | Add to allowlist |
| POST | `/api/v1/domains/allowlist/remove` | Yes | Remove from allowlist |

### 8.6 Reports
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/reports/alerts.csv` | Yes | Export alerts CSV |

### 8.7 WebSockets
| Path | Channel | Description |
|------|---------|-------------|
| `/ws/alerts` | alerts | New/updated alerts |
| `/ws/traffic` | traffic | Every DNS query |

---

## 9. Security Model

### 9.1 Authentication
- **Shared API Key** (`API_KEY` env var) — protects all `/api/v1/*` except `/health`
- Passed via `X-API-Key` header or `?api_key=` query param (WebSocket)
- No per-user accounts in current release (`user_accounts` table reserved)

### 9.2 Authorization (Future RBAC)
| Role | Permissions |
|------|-------------|
| Administrator | All endpoints, user management, system config |
| Security Analyst | Read/write alerts, block/allow domains, view analytics |
| Viewer | Read-only access to dashboards, alerts, queries |

**Enforced at backend**, not just hidden in frontend.

### 9.3 Security Controls
- Strict domain validation (regex) before writing resolver config
- Trusted infrastructure roots never blockable
- Allowlist overrides detection
- CORS restricted to configured origins
- `API_KEY` required for LAN exposure
- `ALERT_ONLY_MODE=true` by default (no auto-blocking)
- NVIDIA API key never exposed to frontend
- Password hashing reserved for future user accounts

---

## 10. Docker Deployment

### 10.1 Services
```yaml
postgres:      # PostgreSQL 16 Alpine
dns-resolver:  # dnsmasq + entrypoint watcher
backend:       # FastAPI (uvicorn, 1 worker)
frontend:      # nginx + React SPA
```

### 10.2 Volumes
- `pgdata` → PostgreSQL data
- `dns_logs` → dnsmasq query log (shared resolver→backend)
- `dns_rules` → blocked.conf (shared backend→resolver)

### 10.3 Health Checks
- postgres: `pg_isready`
- dns-resolver: `dig health.check.local`
- backend: `GET /api/v1/health`
- frontend: `wget /`

### 10.4 Network
- Backend binds to `127.0.0.1:8000` (unless API_KEY set)
- Frontend proxies `/api/*` and `/ws/*` to backend
- DNS resolver exposes port 53 (UDP/TCP) on configured bind IP

---

## 11. Key Invariants & Constraints

1. **Single Backend Worker** — Behavioral trackers and WebSocket hub are in-process
2. **DB is Source of Truth** — Blocklist file rebuilt from DB on startup
3. **No Fake Data** — All dashboard values from real API/database
4. **Model Must Load** — Production requires `dga_rf.joblib` with matching sklearn version
5. **Retention Policy** — Events pruned after `RETENTION_DAYS` (default 7); alerts preserved
6. **DNS Port 53** — Requires root/CAP_NET_BIND_SERVICE or `DNS_PORT=5353` for dev
7. **Trusted Roots** — CDN/vendor domains capped at 5% lexical score; rules still apply

---

## 12. Known Limitations

1. **Dictionary-word DGAs** (gozi, suppobox) — not detectable from name alone
2. **Short random names** — can score below threshold
3. **Behavioral state in memory** — resets on restart (alerts persist in DB)
4. **Rules unevaluated** — tunnelling/beaconing/NXDOMAIN/phishing are heuristics
5. **Single-worker only** — horizontal scaling requires shared state (Redis)
6. **No per-user RBAC yet** — shared API key only

---

## 13. File Ownership Map

| Area | Files | Owner Agent |
|------|-------|-------------|
| Frontend App Shell | `src/App.tsx`, `src/main.tsx`, `src/api.ts` | frontend-specialist |
| Design System | `src/theme/`, `src/components/ui/`, `tailwind.config.js` | design-system-specialist |
| Dashboard Pages | `src/pages/*/`, `src/components/*/` | frontend-specialist |
| Backend Core | `app/main.py`, `app/config.py`, `app/db.py` | backend-specialist |
| Database | `app/models.py`, migrations | database-specialist |
| Detection Pipeline | `app/service.py`, `app/classifier.py`, `app/features.py` | ai-ml-specialist |
| DNS Integration | `app/monitor.py`, `app/ingest.py`, `app/blocking.py`, `dns-resolver/*` | dns-integration-specialist |
| Security | `app/security.py`, `app/schemas.py` validation | security-specialist |
| Testing | `tests/*`, `frontend/src/*.test.tsx` | qa-testing-specialist |
| Infrastructure | `docker-compose.yml`, `Dockerfile*`, `nginx.conf`, `run.sh` | backend-specialist + frontend-specialist |

---

## 14. Extension Points

1. **Additional ML Models** — Drop-in replacement in `train.py` (Gradient Boosting available)
2. **New Detection Rules** — Add to `classifier.py:_rules()`
3. **New API Endpoints** — Add to `main.py` with proper auth dependency
4. **New Frontend Pages** — Add route + sidebar entry + page component
5. **Custom Themes** — Extend design token system
6. **External Threat Intel** — Enrich alerts via API in `service.py`
7. **Multi-user RBAC** — Implement `user_accounts` + JWT/session auth