# DNS Defender AI — Agent Assignments

**Version:** 1.0  
**Created:** 2026-11-20  
**Master Agent:** Chief Software Architect / Master Orchestrator

---

## Agent Roster

| # | Agent ID | Specialization | File |
|---|----------|----------------|------|
| 1 | `frontend-specialist` | Frontend application, pages, components, routing | `.claude/agents/frontend-specialist.md` |
| 2 | `design-system-specialist` | Design system, themes, tokens, UI components | `.claude/agents/design-system-specialist.md` |
| 3 | `backend-specialist` | FastAPI backend, API endpoints, integration | `.claude/agents/backend-specialist.md` |
| 4 | `database-specialist` | PostgreSQL schema, migrations, queries, performance | `.claude/agents/database-specialist.md` |
| 5 | `ai-ml-specialist` | Random Forest, feature extraction, detection rules, model | `.claude/agents/ai-ml-specialist.md` |
| 6 | `dns-integration-specialist` | dnsmasq, log tailer, blocking, real-time events | `.claude/agents/dns-integration-specialist.md` |
| 7 | `security-specialist` | Auth, RBAC, input validation, secrets, hardening | `.claude/agents/security-specialist.md` |
| 8 | `qa-testing-specialist` | Unit, integration, E2E tests, quality gates | `.claude/agents/qa-testing-specialist.md` |

---

## File Ownership Boundaries

### Frontend Specialist — EXCLUSIVE OWNERSHIP
```
frontend/
├── src/
│   ├── App.tsx                 ← App shell, routing, providers
│   ├── main.tsx                ← Entry point
│   ├── api.ts                  ← API client, WebSocket hook
│   ├── index.css               ← Global styles, Tailwind imports
│   ├── routes.tsx              ← Route definitions
│   ├── pages/                  ← ALL PAGE COMPONENTS
│   │   ├── CommandCenter.tsx
│   │   ├── LiveDNSTraffic.tsx
│   │   ├── ThreatDetection.tsx
│   │   ├── AlertManagement.tsx
│   │   ├── DomainIntelligence.tsx
│   │   ├── AIAnalysis.tsx
│   │   ├── NetworkClients.tsx
│   │   ├── TrafficAnalytics.tsx
│   │   ├── ThreatAnalytics.tsx
│   │   ├── Reports.tsx
│   │   ├── MLModelPerformance.tsx
│   │   ├── SystemHealth.tsx
│   │   └── Settings/
│   │       ├── Appearance.tsx
│   │       ├── DNSConfig.tsx
│   │       ├── AIConfig.tsx
│   │       ├── Notifications.tsx
│   │       ├── Security.tsx
│   │       ├── UsersRoles.tsx
│   │       ├── DataRetention.tsx
│   │       └── SystemConfig.tsx
│   ├── components/
│   │   ├── layout/             ← Shell, Sidebar, TopNav, Breadcrumbs
│   │   ├── ui/                 ← Reusable (Button, Table, Modal, Toast, etc.)
│   │   ├── charts/             ← Chart wrappers
│   │   ├── forms/              ← Form components
│   │   └── feedback/           ← Loading, Empty, Error, Toasts
│   ├── hooks/                  ← Custom hooks (useAuth, useTheme, etc.)
│   ├── context/                ← React context (Auth, Theme, Settings)
│   ├── utils/                  ← Helpers (formatters, validators)
│   └── types/                  ← TypeScript interfaces
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.js          ← Co-owned with Design System
└── Dockerfile
```

### Design System Specialist — EXCLUSIVE OWNERSHIP
```
frontend/
├── src/
│   ├── theme/
│   │   ├── ThemeProvider.tsx
│   │   ├── themes/
│   │   │   ├── midnight-soc.ts
│   │   │   ├── arctic-light.ts
│   │   │   ├── matrix.ts
│   │   │   └── nebula.ts
│   │   ├── tokens/
│   │   │   ├── colors.ts
│   │   │   ├── spacing.ts
│   │   │   ├── typography.ts
│   │   │   ├── shadows.ts
│   │   │   ├── borders.ts
│   │   │   ├── transitions.ts
│   │   │   └── z-index.ts
│   │   ├── ThemeContext.tsx
│   │   ├── useTheme.ts
│   │   └── css-variables.ts    ← CSS custom properties generation
│   ├── components/ui/          ← Base UI components (co-owned)
│   │   ├── Button.tsx
│   │   ├── Input.tsx
│   │   ├── Select.tsx
│   │   ├── Table.tsx
│   │   ├── Modal.tsx
│   │   ├── Dropdown.tsx
│   │   ├── Toast.tsx
│   │   ├── Tooltip.tsx
│   │   ├── Badge.tsx
│   │   ├── Card.tsx
│   │   ├── Avatar.tsx
│   │   ├── Icon.tsx
│   │   └── ...
│   └── styles/
│       └── globals.css         ← Base styles, CSS variables
├── tailwind.config.js          ← Design token integration
└── postcss.config.js
```

### Backend Specialist — EXCLUSIVE OWNERSHIP
```
backend/
├── app/
│   ├── main.py                 ← App factory, routes, lifespan
│   ├── config.py               ← Settings (Pydantic)
│   ├── db.py                   ← Engine, session factory
│   ├── schemas.py              ← Request/Response models
│   ├── service.py              ← Core pipeline (co-owned with AI/ML)
│   ├── hub.py                  ← WebSocket hub
│   ├── stats.py                ← Dashboard aggregates
│   ├── nim.py                  ← NVIDIA NIM client
│   ├── security.py             ← API key auth (co-owned with Security)
│   ├── monitor.py              ← DNS log tailer (co-owned with DNS)
│   ├── ingest.py               ← Scapy/Zeek (co-owned with DNS)
│   ├── blocking.py             ← Blocklist file (co-owned with DNS)
│   └── __init__.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
└── models/
    ├── dga_rf.joblib
    └── model_card.json
```

### Database Specialist — EXCLUSIVE OWNERSHIP
```
backend/
├── app/
│   ├── models.py               ← SQLAlchemy ORM models
│   └── db.py                   ← Engine config (co-owned)
├── migrations/                 ← Alembic migrations (TO BE CREATED)
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
└── scripts/
    └── db_*.py                 ← Maintenance scripts
```

### AI/ML Specialist — EXCLUSIVE OWNERSHIP
```
backend/
├── app/
│   ├── classifier.py           ← Detector, rules, noisy-OR
│   ├── features.py             ← Lexical + behavioral features
│   └── service.py              ← Pipeline (co-owned with Backend)
├── models/
│   └── dga_rf.joblib           ← Model artifact (read-only)
├── ml-training/
│   ├── train.py                ← Training script
│   ├── compare_models.py       ← Model comparison
│   └── requirements.txt
└── docs/
    └── model_card.json         ← Model documentation
```

### DNS Integration Specialist — EXCLUSIVE OWNERSHIP
```
backend/
├── app/
│   ├── monitor.py              ← DnsmasqLogParser, DnsmasqTailer
│   ├── ingest.py               ← ScapySniffer, parse_zeek_dns_log
│   └── blocking.py             ← BlocklistFile, valid_domain
dns-resolver/
├── dnsmasq.conf
├── entrypoint.sh
├── Dockerfile
└── scripts/
    └── simulate-traffic.sh     ← Test traffic generator
```

### Security Specialist — EXCLUSIVE OWNERSHIP
```
backend/
├── app/
│   ├── security.py             ← API key, WS auth, password hashing
│   ├── schemas.py              ← Input validation (co-owned)
│   └── models.py               ← UserAccount (co-owned with DB)
├── tests/
│   └── test_security.py        ← Security tests (TO BE CREATED)
└── docs/
    └── SECURITY.md             ← Security documentation (TO BE CREATED)
```

### QA/Testing Specialist — EXCLUSIVE OWNERSHIP
```
tests/
├── conftest.py
├── test_api.py
├── test_features_and_classifier.py
├── test_monitor_ingest_blocking.py
├── test_security.py            ← TO BE CREATED
├── test_database.py            ← TO BE CREATED
├── test_integration.py         ← TO BE CREATED
├── test_frontend/              ← Frontend tests
│   ├── App.test.tsx
│   └── components/
├── requirements.txt
└── pytest.ini

frontend/
├── src/
│   └── **/*.test.tsx           ← Component tests (co-owned)
```

---

## Cross-Cutting Concerns (Shared Responsibility)

| Concern | Primary Owner | Collaborators |
|---------|---------------|---------------|
| **API Contracts** | Backend | Frontend, AI/ML, DNS |
| **WebSocket Events** | Backend | Frontend, DNS |
| **Database Schema** | Database | Backend, AI/ML |
| **Detection Pipeline** | AI/ML | Backend, DNS |
| **Blocking Flow** | DNS | Backend, Security |
| **Theme/Design Tokens** | Design System | Frontend |
| **Authentication** | Security | Backend, Frontend |
| **RBAC** | Security | Backend, Database, Frontend |
| **Test Infrastructure** | QA | All |
| **Docker/Deploy** | Backend | Frontend, DNS |
| **Settings Persistence** | Backend | Database, Frontend, Security |

---

## Development Stages & Agent Activation

### STAGE A — AUDIT (Week 1, Days 1-2)
| Agent | Task | Deliverable |
|-------|------|-------------|
| Master | Full project audit | `PROJECT_AUDIT.md` ✅ |
| All | Review assigned components | Component audit notes |

### STAGE B — ARCHITECTURE (Week 1, Days 3-4)
| Agent | Task | Deliverable |
|-------|------|-------------|
| Master | Define API contracts, DB ownership, design tokens, component interfaces, integration boundaries | `IMPLEMENTATION_PLAN.md` |
| Design System | Define theme tokens, component API | `design-tokens.json`, component specs |
| Database | Review schema, plan migrations | Migration plan |
| Backend | Document API contracts | OpenAPI spec updates |
| Security | Define RBAC matrix | RBAC spec |

### STAGE C — IMPLEMENTATION (Week 2-4)
| Phase | Agents Active | Coordination |
|-------|---------------|--------------|
| **C1: Design System** | Design System | Master reviews tokens before UI work |
| **C2: App Shell** | Frontend + Design System | Shared component library |
| **C3: Core Pages** | Frontend | Backend APIs must be stable |
| **C4: Backend Enhancements** | Backend + AI/ML + DNS + Security | API changes coordinated |
| **C5: Database** | Database | Migrations reviewed by Master |
| **C6: Settings/RBAC** | Backend + Security + Database + Frontend | Joint integration |

### STAGE D — REVIEW (Continuous)
Every completed task:
1. Agent submits changed files + test results
2. Master inspects code quality, architecture compliance
3. Master runs relevant tests
4. Master checks for regressions, security implications
5. Master verifies API/DB compatibility
6. **Master approves or rejects with specific corrections**

### STAGE E — INTEGRATION (Week 5)
| Agent | Task |
|-------|------|
| Master | Integrate all approved components |
| Frontend | Verify routes, imports, API calls |
| Backend | Verify DB, WS, DNS integration |
| QA | Run full test suite |

### STAGE F — FINAL VERIFICATION (Week 5-6)
| Agent | Task |
|-------|------|
| Master | Run all quality gates, generate `FINAL_VERIFICATION_REPORT.md` |
| QA | Execute test matrix, report results |
| All | Fix any gate failures |

---

## Communication Protocol

### Task Assignment (Master → Agent)
```markdown
## Task: [Title]
**Agent:** [agent-id]
**Priority:** High/Medium/Low
**Dependencies:** [other tasks/agents]
**Inputs:** [files, specs, contracts]
**Expected Outputs:** [files, tests, documentation]
**Acceptance Criteria:** [specific, testable]
**Deadline:** [date]
```

### Completion Report (Agent → Master)
```markdown
## Task Complete: [Title]
**Agent:** [agent-id]
**Files Changed:** [list]
**Tests Added/Modified:** [list]
**Test Results:** [pass/fail, output]
**Known Issues:** [any deviations]
**Breaking Changes:** [none / list]
**Documentation Updated:** [files]
```

### Review Feedback (Master → Agent)
```markdown
## Review: [Task Title]
**Status:** APPROVED / CHANGES_REQUESTED / REJECTED
**Findings:**
- [ ] Architecture compliance
- [ ] Code quality
- [ ] Test coverage
- [ ] Security
- [ ] Performance
- [ ] API/DB compatibility
**Required Changes:** [specific]
**Blocking:** [yes/no]
```

---

## Escalation Path

1. **Agent → Master**: Technical blockers, scope changes, conflicts
2. **Master → Agent**: Architecture decisions, priority changes, rejections
3. **Cross-Agent Conflicts**: Master arbitrates, defines ownership
4. **Quality Gate Failures**: Master identifies responsible component, delegates fix

---

## Quality Standards (All Agents)

### Code
- Type hints on all public functions
- Docstrings for classes and complex functions
- No `any` types without justification
- No hardcoded secrets or credentials
- No `console.log` / `print` in production code
- Error handling with specific exceptions

### Tests
- Unit tests for all new functions
- Integration tests for API endpoints
- Frontend: render + interaction tests
- Mock external dependencies
- Test failure conditions, not just happy path

### Documentation
- Update relevant `.md` files with changes
- API changes → OpenAPI annotations
- Schema changes → migration + model docs
- New components → Storybook/usage examples

### Git
- Feature branches per task
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)
- PR description with testing evidence
- No direct pushes to main