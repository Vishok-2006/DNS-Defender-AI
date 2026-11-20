# DNS Defender AI — Implementation Plan

**Version:** 1.0  
**Created:** 2026-11-20  
**Master Agent:** Chief Software Architect  
**Based on:** `MASTER_ARCHITECTURE.md`, `PROJECT_AUDIT.md`, `AGENT_ASSIGNMENTS.md`

---

## Plan Overview

| Phase | Duration | Focus | Agents |
|-------|----------|-------|--------|
| **0** | Week 1, Days 1-2 | Audit & Architecture | Master (all review) |
| **1** | Week 1, Days 3-5 | Design System Foundation | Design System |
| **2** | Week 2 | App Shell & Routing | Frontend + Design System |
| **3** | Week 2-3 | Core Dashboard Pages | Frontend |
| **4** | Week 3 | Threat Intelligence Pages | Frontend + AI/ML |
| **5** | Week 3-4 | Security & Analytics Pages | Frontend + Backend |
| **6** | Week 4 | System & Settings Pages | Frontend + Backend + Security |
| **7** | Week 4-5 | Backend Enhancements | Backend + Database + Security + DNS + AI/ML |
| **8** | Week 5 | Integration & Testing | All + QA |
| **9** | Week 5-6 | Quality Gates & Verification | Master + QA |

**Total Estimated Duration:** 6 weeks  
**Critical Path:** Design System → App Shell → Pages (Frontend) + Backend Enhancements (parallel)

---

## Phase 0: Audit & Architecture (COMPLETE)

### Deliverables ✅
- [x] `docs/MASTER_ARCHITECTURE.md` — Complete system architecture
- [x] `docs/PROJECT_AUDIT.md` — Comprehensive audit with scores
- [x] `docs/AGENT_ASSIGNMENTS.md` — Agent roles, ownership, stages
- [x] `docs/IMPLEMENTATION_PLAN.md` — This document
- [x] `.claude/agents/*.md` — 8 specialist agent definitions
- [x] `CLAUDE.md` — Project-wide rules

---

## Phase 1: Design System Foundation (Week 1, Days 3-5)

### Agent: `design-system-specialist`

### Objectives
Create a complete, reusable enterprise design system with 4 themes that all frontend components will consume.

### Tasks

| # | Task | Description | Acceptance Criteria |
|---|------|-------------|---------------------|
| 1.1 | **Design Tokens** | Define all tokens: colors, spacing, typography, shadows, borders, transitions, z-index | `src/theme/tokens/*.ts` complete, TypeScript types |
| 1.2 | **Theme Definitions** | Create 4 themes: Midnight SOC, Arctic Light, Matrix, Nebula | `src/theme/themes/*.ts` with complete token overrides |
| 1.3 | **CSS Variables Generation** | Runtime CSS custom properties from tokens | `src/theme/css-variables.ts` generates `:root` and `[data-theme]` rules |
| 1.4 | **Theme Provider** | React Context + Provider with persistence (localStorage) | `ThemeProvider` wraps app, `useTheme` hook, system preference detection |
| 1.5 | **Tailwind Integration** | Map tokens to Tailwind config (v4 syntax) | `tailwind.config.js` uses design tokens, `theme.extend` |
| 1.6 | **Base UI Components** | Button, Input, Select, Table, Card, Badge, Avatar, Icon, Tooltip, Toast, Modal, Dropdown | All components in `src/components/ui/`, fully themed, accessible |
| 1.7 | **Chart Theme** | Recharts theme configuration per theme | `src/theme/charts.ts` with theme-aware colors, grid, tooltip styles |
| 1.8 | **Responsive Breakpoints** | Mobile-first breakpoints, sidebar drawer behavior | `tokens/breakpoints.ts`, CSS utilities |
| 1.9 | **Density Modes** | Compact / Comfortable spacing scales | Token override for density, persisted |
| 1.10 | **Reduced Motion** | Respect `prefers-reduced-motion` | Transitions disabled when preferred |

### Dependencies
- None (foundational)

### Outputs
```
frontend/src/theme/
├── ThemeProvider.tsx
├── ThemeContext.tsx
├── useTheme.ts
├── css-variables.ts
├── charts.ts
├── tokens/
│   ├── colors.ts
│   ├── spacing.ts
│   ├── typography.ts
│   ├── shadows.ts
│   ├── borders.ts
│   ├── transitions.ts
│   ├── z-index.ts
│   └── breakpoints.ts
├── themes/
│   ├── midnight-soc.ts
│   ├── arctic-light.ts
│   ├── matrix.ts
│   └── nebula.ts
└── index.ts (exports)

frontend/src/components/ui/
├── Button.tsx
├── Input.tsx
├── Select.tsx
├── Table.tsx
├── Card.tsx
├── Badge.tsx
├── Avatar.tsx
├── Icon.tsx
├── Tooltip.tsx
├── Toast.tsx
├── ToastContainer.tsx
├── Modal.tsx
├── Dropdown.tsx
├── Tabs.tsx
├── Pagination.tsx
├── LoadingSpinner.tsx
├── EmptyState.tsx
├── ErrorState.tsx
└── index.ts

frontend/tailwind.config.js (updated)
frontend/postcss.config.js
```

### Quality Gates
- [ ] All components render in all 4 themes
- [ ] Theme switching works without reload
- [ ] Persistence works across sessions
- [ ] System preference detection works
- [ ] Reduced motion respected
- [ ] Mobile drawer works
- [ ] TypeScript strict mode passes
- [ ] Component tests pass (Vitest)

---

## Phase 2: App Shell & Routing (Week 2)

### Agents: `frontend-specialist` + `design-system-specialist`

### Objectives
Build the persistent application shell with sidebar navigation, top navigation, routing, and layout system.

### Tasks

| # | Task | Description | Acceptance Criteria |
|---|------|-------------|---------------------|
| 2.1 | **Route Configuration** | Define all routes with lazy loading | `src/routes.tsx` with 11 page routes + settings sub-routes |
| 2.2 | **Sidebar Component** | Collapsible, grouped nav, icons, tooltips, active state, mobile drawer | `Sidebar.tsx` with all 6 groups, keyboard accessible |
| 2.3 | **Top Navigation** | Breadcrumbs, global search, live status, notifications, user menu, theme toggle | `TopNav.tsx` with all elements |
| 2.4 | **App Layout** | Shell component composing Sidebar + TopNav + Main Content | `AppShell.tsx` responsive, proper CSS Grid/Flex |
| 2.5 | **Routing Integration** | React Router v6, outlet for pages, 404 handling | `App.tsx` uses `AppShell`, `Routes`, `Navigate` |
| 2.6 | **Navigation State** | Sidebar collapse persisted, active route highlighted | localStorage + URL sync |
| 2.7 | **Mobile Responsiveness** | Breakpoint at 1024px, drawer overlay, swipe gestures | Works on 375px-1920px widths |
| 2.8 | **Global Search** | Command palette (Cmd+K), searches domains, alerts, clients | `GlobalSearch.tsx` with debounced API calls |
| 2.9 | **Live Status Indicators** | WebSocket connection pills, monitor status, model status | Real-time in TopNav |
| 2.10 | **Notification System** | Toast container, notification bell, mark read, persist | `useNotifications` hook + `NotificationBell.tsx` |
| 2.11 | **User Profile Menu** | Avatar, name, role, theme shortcut, settings, logout | `UserMenu.tsx` |

### Dependencies
- Phase 1 complete (design system, UI components)

### Outputs
```
frontend/src/
├── routes.tsx
├── App.tsx (refactored)
├── components/
│   ├── layout/
│   │   ├── AppShell.tsx
│   │   ├── Sidebar.tsx
│   │   ├── SidebarGroup.tsx
│   │   ├── SidebarItem.tsx
│   │   ├── TopNav.tsx
│   │   ├── Breadcrumbs.tsx
│   │   ├── GlobalSearch.tsx
│   │   ├── LiveStatusIndicators.tsx
│   │   ├── NotificationBell.tsx
│   │   ├── UserMenu.tsx
│   │   └── MobileDrawer.tsx
│   └── ...
├── hooks/
│   ├── useSidebar.ts
│   ├── useTheme.ts (from design system)
│   ├── useNotifications.ts
│   └── useGlobalSearch.ts
└── context/
    ├── AuthContext.tsx
    ├── ThemeContext.tsx (from design system)
    └── SettingsContext.tsx
```

### Quality Gates
- [ ] All 11 routes accessible via sidebar
- [ ] Sidebar collapse/expand persists
- [ ] Mobile drawer opens/closes correctly
- [ ] Breadcrumbs show correct hierarchy
- [ ] Global search opens on Cmd+K
- [ ] Theme toggle in TopNav works
- [ ] Notifications appear and persist
- [ ] WebSocket status reflects real connection
- [ ] Keyboard navigation works (Tab, Enter, Escape)
- [ ] No layout shift on theme change

---

## Phase 3: Core Dashboard Pages (Week 2-3)

### Agent: `frontend-specialist`

### Objectives
Implement the 4 core monitoring pages with real data from backend APIs.

### Pages & Tasks

#### 3.1 Command Center (Overview) — `/`
| Task | Description |
|------|-------------|
| 3.1.1 | Page layout with header, stats grid, charts, tables |
| 3.1.2 | Stats cards: Queries 24h, Clients, Malicious, Suspicious, Open Alerts, Blocked Domains |
| 3.1.3 | DNS Traffic Chart (AreaChart: queries + alerts/hour, 24-48h) |
| 3.1.4 | Threat Activity Chart (BarChart: detections by category) |
| 3.1.5 | Top Queried Domains table (pagination, sort) |
| 3.1.6 | Top Suspicious Domains table |
| 3.1.7 | Recent Security Events feed (WebSocket) |
| 3.1.8 | Client Activity summary |
| 3.1.9 | Resolver Health panel |
| 3.1.10 | Date range selector (last 1h, 6h, 24h, 7d, custom) |

#### 3.2 Live DNS Traffic — `/monitoring/live-traffic`
| Task | Description |
|------|-------------|
| 3.2.1 | Real-time event stream table (WebSocket `/ws/traffic`) |
| 3.2.2 | Columns: Time, Client IP, Domain, Type, Rcode, Classification, Risk, Actions |
| 3.2.3 | Search (domain, client IP), Filter (classification, response code), Sort |
| 3.2.4 | Pagination (50/100/200 per page) |
| 3.2.5 | Row click → Detail modal (raw event, features, prediction) |
| 3.2.6 | Connection status badge (connected/reconnecting/disconnected) |
| 3.2.7 | Pause/resume live stream toggle |
| 3.2.8 | Export current view to CSV |

#### 3.3 Network Clients — `/monitoring/clients`
| Task | Description |
|------|-------------|
| 3.3.1 | Client list table: IP, Hostname, Query Count, Suspicious, Threats, Last Seen |
| 3.3.2 | Search/filter by IP, hostname, threat count |
| 3.3.3 | Click → Client Detail page with query history, threat timeline |
| 3.3.4 | Hostname resolution (reverse DNS lookup via backend) |

#### 3.4 DNS Resolver — `/monitoring/resolver`
| Task | Description |
|------|-------------|
| 3.4.1 | Resolver status (health check, uptime, queries/sec) |
| 3.4.2 | Upstream servers configuration display |
| 3.4.3 | Blocklist status (count, last updated, sync status) |
| 3.4.4 | Query log tail (last 100 lines) |
| 3.4.5 | Cache statistics (hits, misses, size) |

### Dependencies
- Phase 2 complete (routing, shell)
- Backend APIs stable (`/api/v1/stats`, `/queries`, `/alerts`, `/ws/traffic`)

### API Requirements (Backend must support)
```
GET /api/v1/stats?hours=24           → Overview stats + timeseries + top_domains
GET /api/v1/queries?limit=50&search=&classification=&page=1
GET /api/v1/alerts?limit=50&severity=&status=
GET /api/v1/domains/blocklist
GET /api/v1/settings
WS  /ws/traffic                      → Real-time DNS events
WS  /ws/alerts                       → Real-time alerts
```

### Outputs
```
frontend/src/pages/
├── CommandCenter.tsx
├── monitoring/
│   ├── LiveDNSTraffic.tsx
│   ├── NetworkClients.tsx
│   ├── ClientDetail.tsx
│   └── DNSResolver.tsx
```

### Quality Gates
- [ ] All data from real APIs (no mock data)
- [ ] Loading skeletons while fetching
- [ ] Empty states with helpful messages
- [ ] Error states with retry buttons
- [ ] WebSocket reconnection handled gracefully
- [ ] Tables sort, filter, paginate correctly
- [ ] Date range updates all charts/tables
- [ ] Export CSV generates valid file
- [ ] Responsive on mobile (stacked cards)
- [ ] Accessible (ARIA labels, keyboard nav)

---

## Phase 4: Threat Intelligence Pages (Week 3)

### Agent: `frontend-specialist` (with `ai-ml-specialist` for AI Analysis)

### Pages & Tasks

#### 4.1 Threat Detection — `/threat-intelligence/detection`
| Task | Description |
|------|-------------|
| 4.1.1 | Alert list with severity, category, risk score, client, domain |
| 4.1.2 | Filter by severity (critical/high/medium/low), status, category |
| 4.1.3 | Search by domain, client IP, category |
| 4.1.4 | Row click → Detail panel with evidence, timeline, related queries |
| 4.1.5 | Detection category breakdown chart |
| 4.1.6 | Risk score distribution histogram |

#### 4.2 Domain Intelligence — `/threat-intelligence/domain-intelligence`
| Task | Description |
|------|-------------|
| 4.2.1 | Domain search input (debounced, autocomplete from API) |
| 4.2.2 | Domain detail: reputation, DNS history, query frequency, client distribution |
| 4.2.3 | Threat history timeline |
| 4.2.4 | Detection evidence (lexical features, behavioral features, rules triggered) |
| 4.2.5 | Blocklist/Allowlist status badges with quick actions |
| 4.2.6 | Related domains (same clients, similar patterns) |

#### 4.3 AI Analysis — `/threat-intelligence/ai-analysis`
| Task | Description |
|------|-------------|
| 4.3.1 | Random Forest model info (version, thresholds, feature importance chart) |
| 4.3.2 | Single domain analysis form (shows lexical features, RF prob, rule scores) |
| 4.3.3 | Model prediction breakdown (lexical vs behavioral contribution) |
| 4.3.4 | Feature importance visualization (bar chart from model_card.json) |
| 4.3.5 | Threat category explanations |
| 4.3.6 | Confidence score interpretation guide |
| 4.3.7 | Analysis history (recent analyzed alerts with LLM explanations) |
| 4.3.8 | Model health status (loaded, latency, version) |

### Dependencies
- Phase 3 complete
- Backend: `/api/v1/alerts/{id}/analyze`, `/api/v1/health` (model info)

### API Requirements
```
GET /api/v1/alerts?limit=100&severity=&status=&category=
GET /api/v1/alerts/{id}                 → Full alert with analysis
POST /api/v1/alerts/{id}/analyze        → Trigger LLM explanation
GET /api/v1/health                      → model_loaded, model_version, thresholds
GET /api/v1/domains/blocklist
GET /api/v1/domains/allowlist
```

### Outputs
```
frontend/src/pages/
├── threat-intelligence/
│   ├── ThreatDetection.tsx
│   ├── DomainIntelligence.tsx
│   └── AIAnalysis.tsx
```

### Quality Gates
- [ ] All threat data from real APIs
- [ ] Domain search works with debounce
- [ ] AI Analysis shows actual model features
- [ ] LLM explanations render correctly (provider badge)
- [ ] Feature importance chart matches model_card.json
- [ ] Real-time updates via WebSocket

---

## Phase 5: Security & Analytics Pages (Week 3-4)

### Agent: `frontend-specialist` + `backend-specialist`

### Pages & Tasks

#### 5.1 Alert Management — `/security/alerts`
| Task | Description |
|------|-------------|
| 5.1.1 | Full alert table with all columns + actions |
| 5.1.2 | Inline status selector (new/investigating/confirmed/resolved/false_positive) |
| 5.1.3 | Analyst notes editable inline |
| 5.1.4 | Bulk actions: select multiple → Block / Allow / Resolve / Export |
| 5.1.5 | Confirmation modals for destructive actions |
| 5.1.6 | Export filtered alerts to CSV |
| 5.1.7 | Severity distribution chart |
| 5.1.8 | Alert timeline (created vs resolved) |

#### 5.2 Blocklist — `/security/blocklist`
| Task | Description |
|------|-------------|
| 5.2.1 | Blocked domains table: domain, reason, source (manual/auto), blocked_at |
| 5.2.2 | Add domain modal (with reason, validation) |
| 5.2.3 | Unblock action with confirmation |
| 5.2.4 | Blocklist sync status with resolver |
| 5.2.5 | Import/Export blocklist (CSV/JSON) |

#### 5.3 Allowlist — `/security/allowlist`
| Task | Description |
|------|-------------|
| 5.3.1 | Allowlisted domains table with reasons |
| 5.3.2 | Add/Remove with modals |
| 5.3.3 | Trusted infrastructure display (read-only) |

#### 5.4 Traffic Analytics — `/analytics/traffic`
| Task | Description |
|------|-------------|
| 5.4.1 | Query volume trends (line chart, configurable range) |
| 5.4.2 | Query type distribution (pie/donut) |
| 5.4.3 | Response code distribution |
| 5.4.4 | Top clients by volume |
| 5.4.5 | NXDOMAIN analysis (rate, top domains, clients) |
| 5.4.6 | Date range picker (presets + custom) |
| 5.4.7 | Export chart data CSV |

#### 5.5 Threat Analytics — `/analytics/threats`
| Task | Description |
|------|-------------|
| 5.5.1 | Threat trends over time (stacked area by category) |
| 5.5.2 | Detection category breakdown |
| 5.5.3 | Severity distribution |
| 5.5.4 | Client risk scoring (top risky clients) |
| 5.5.5 | DGA activity indicators |
| 5.5.6 | DNS tunnelling indicators |
| 5.5.7 | Geo distribution (if IP geo available) |

#### 5.6 Reports — `/analytics/reports`
| Task | Description |
|------|-------------|
| 5.6.1 | Scheduled report builder (daily/weekly/monthly) |
| 5.6.2 | Report templates: Executive Summary, Technical Detail, Compliance |
| 5.6.3 | Report preview |
| 5.6.4 | Export PDF/CSV |
| 5.6.5 | Email delivery (backend integration) |

### Dependencies
- Phase 3-4 complete
- Backend: Bulk alert actions, report generation endpoints

### API Requirements (New/Extended)
```
PATCH /api/v1/alerts/bulk              → Bulk status update
POST  /api/v1/reports/generate         → Generate report
GET   /api/v1/reports/templates        → List templates
GET   /api/v1/analytics/traffic        → Aggregated traffic data
GET   /api/v1/analytics/threats        → Aggregated threat data
```

### Outputs
```
frontend/src/pages/
├── security/
│   ├── AlertManagement.tsx
│   ├── Blocklist.tsx
│   └── Allowlist.tsx
├── analytics/
│   ├── TrafficAnalytics.tsx
│   ├── ThreatAnalytics.tsx
│   └── Reports.tsx
```

### Quality Gates
- [ ] Bulk actions work with confirmation
- [ ] Block/Allow sync with resolver (verify enforcement)
- [ ] Charts render with real aggregated data
- [ ] Date range affects all charts on page
- [ ] Export generates valid CSV/PDF
- [ ] No fake/hardcoded statistics

---

## Phase 6: System & Settings Pages (Week 4)

### Agents: `frontend-specialist` + `backend-specialist` + `security-specialist`

### Pages & Tasks

#### 6.1 ML Model Performance — `/system/ml-performance`
| Task | Description |
|------|-------------|
| 6.1.1 | Model metadata: name, version, training date, sklearn version |
| 6.1.2 | Performance metrics: Accuracy, Precision, Recall, F1, ROC-AUC |
| 6.1.3 | Confusion matrix visualization |
| 6.1.4 | Prediction distribution (benign/suspicious/malicious) |
| 6.1.5 | Inference latency histogram |
| 6.1.6 | Per-family recall (unseen families) |
| 6.1.7 | Feature importance chart |
| 6.1.8 | Threshold configuration (suspicious/malicious) with live preview |

#### 6.2 System Health — `/system/health`
| Task | Description |
|------|-------------|
| 6.2.1 | Service status cards: Backend, Database, DNS Resolver, Collector, AI Engine, WebSocket |
| 6.2.2 | Resource usage: CPU, Memory, Disk (gauges) |
| 6.2.3 | Application uptime |
| 6.2.4 | Recent service logs (tail) |
| 6.2.5 | Health check history |
| 6.2.6 | Dependency versions |

#### 6.3 Settings — `/settings/*` (7 sub-pages)
| Sub-page | Tasks |
|----------|-------|
| **Appearance** | Theme selector (4 themes + system), Density (compact/comfortable), Font scale, Reduced motion, Sidebar default |
| **Dashboard** | Default time range, Auto-refresh interval, Default page, Chart preferences |
| **DNS Config** | Upstream servers, Capture mode, Port, Bind IP, Log path, Retention days |
| **AI Config** | NVIDIA API key (masked), Model selection, Thresholds, Explanation provider |
| **Notifications** | Alert severity thresholds, Email/webhook config, Digest frequency |
| **Security** | API key management, Session timeout, RBAC roles (future), Audit log |
| **Users & Roles** | User list, Add/edit user, Role assignment, Password reset (future) |
| **Data Retention** | Retention days, Manual prune button, Export before purge |

### Dependencies
- Phase 1 (theme system), Phase 2 (shell)
- Backend: Settings persistence (DB), System metrics endpoints

### API Requirements (New/Extended)
```
GET    /api/v1/settings                 → Current runtime settings
PATCH  /api/v1/settings                 → Update runtime (needs DB persistence)
GET    /api/v1/system/health            → Detailed health + metrics
GET    /api/v1/system/metrics           → CPU, memory, disk
GET    /api/v1/model/info               → Model card data
GET    /api/v1/users                    → User list (future)
POST   /api/v1/users                    → Create user (future)
PATCH  /api/v1/users/{id}               → Update user (future)
```

### Outputs
```
frontend/src/pages/
├── system/
│   ├── MLModelPerformance.tsx
│   └── SystemHealth.tsx
├── settings/
│   ├── Appearance.tsx
│   ├── DashboardPrefs.tsx
│   ├── DNSConfig.tsx
│   ├── AIConfig.tsx
│   ├── Notifications.tsx
│   ├── Security.tsx
│   ├── UsersRoles.tsx
│   ├── DataRetention.tsx
│   └── SystemConfig.tsx
```

### Quality Gates
- [ ] All settings persist to database (survive restart)
- [ ] Theme changes apply immediately
- [ ] Sensitive fields masked (API keys, passwords)
- [ ] System metrics update in real-time
- [ ] Model info matches backend model_card.json
- [ ] No credentials exposed in frontend code

---

## Phase 7: Backend Enhancements (Week 4-5, Parallel with Frontend)

### Agents: `backend-specialist`, `database-specialist`, `security-specialist`, `dns-integration-specialist`, `ai-ml-specialist`

### Objectives
Harden backend, add missing endpoints, implement RBAC, persist settings, improve DNS integration.

### Tasks by Agent

#### Backend Specialist
| # | Task | Description |
|---|------|-------------|
| 7.1 | **Settings Persistence** | Store settings in DB, load on startup, API to CRUD |
| 7.2 | **Bulk Alert Actions** | `PATCH /alerts/bulk` for multi-select operations |
| 7.3 | **Report Generation** | `POST /reports/generate` with templates |
| 7.4 | **System Metrics** | `GET /system/metrics` (CPU, mem, disk via psutil) |
| 7.5 | **Model Info Endpoint** | `GET /model/info` returns model_card.json data |
| 7.6 | **Request Correlation IDs** | Middleware adds `X-Request-ID` to all responses |
| 7.7 | **Rate Limiting** | Per-IP/API-key rate limits on write endpoints |
| 7.8 | **Structured JSON Logging** | Replace basic logging with structlog |
| 7.9 | **OpenAPI Enhancements** | Examples, descriptions, deprecated tags |
| 7.10 | **Graceful Shutdown** | Drain WebSocket connections, finish batch processing |

#### Database Specialist
| # | Task | Description |
|---|------|-------------|
| 7.11 | **Alembic Setup** | Initialize Alembic, create initial migration from models |
| 7.12 | **Settings Table** | `system_settings` table for persisted config |
| 7.13 | **User Accounts** | Complete `user_accounts` with password hashing, roles |
| 7.14 | **Audit Log Table** | `audit_logs` for security-relevant actions |
| 7.15 | **Partitioning Strategy** | Plan for `dns_events` partitioning by time |
| 7.16 | **Index Review** | Add missing indexes, remove unused |
| 7.17 | **Backup Script** | `pg_dump` automation with retention |

#### Security Specialist
| # | Task | Description |
|---|------|-------------|
| 7.18 | **JWT/Session Auth** | Replace API key with JWT (access + refresh tokens) |
| 7.19 | **RBAC Middleware** | Permission checks per endpoint based on role |
| 7.20 | **Permission Matrix** | Admin/Analyst/Viewer → endpoint permissions |
| 7.21 | **Input Sanitization** | Review all validators, add XSS protection |
| 7.22 | **Secrets Audit** | Rotate NVIDIA_API_KEY in .env, ensure not in git |
| 7.23 | **Security Headers** | CSP, HSTS, X-Frame-Options via middleware |
| 7.24 | **Dependency Scan** | Integrate `pip-audit` in CI |

#### DNS Integration Specialist
| # | Task | Description |
|---|------|-------------|
| 7.25 | **Resolver Metrics API** | Expose dnsmasq stats (cache hits, queries, blocked) |
| 7.26 | **Blocklist Sync Verification** | Periodic check that resolver matches DB |
| 7.27 | **Log Rotation Coordination** | Tailer handles rotation signals properly |
| 7.28 | **Client IP Accuracy** | Document Docker vs host network tradeoffs |
| 7.29 | **Demo Traffic Isolation** | Separate source="simulation" from production |

#### AI/ML Specialist
| # | Task | Description |
|---|------|-------------|
| 7.30 | **Model Reload Endpoint** | `POST /model/reload` for zero-downtime model updates |
| 7.31 | **Threshold Tuning UI Support** | Validate and persist threshold changes |
| 7.32 | **Inference Metrics** | Track prediction latency, distribution |
| 7.33 | **Feature Drift Detection** | Monitor feature distributions vs training |
| 7.34 | **Batch Inference Optimization** | Optimize `process_batch` for high throughput |

### Quality Gates
- [ ] All new endpoints have tests
- [ ] Settings survive container restart
- [ ] RBAC enforced at backend (not just frontend)
- [ ] Rate limiting prevents abuse
- [ ] Structured logs parseable
- [ ] Alembic migrations apply cleanly
- [ ] No secrets in code or logs

---

## Phase 8: Integration & Testing (Week 5)

### Agents: All + `qa-testing-specialist` (lead)

### Objectives
Integrate all components, run full test suite, fix issues.

### Tasks

| # | Task | Owner | Description |
|---|------|-------|-------------|
| 8.1 | **Frontend-Backend Integration** | Frontend + Backend | Verify all API calls, WebSocket events, error handling |
| 8.2 | **End-to-End Flow Tests** | QA | Simulate traffic → detection → alert → block → verify |
| 8.3 | **Theme Integration** | Frontend + Design System | All pages in all 4 themes, no hardcoded colors |
| 8.4 | **Responsive Testing** | Frontend | Test 375px, 768px, 1024px, 1440px, 1920px |
| 8.5 | **Accessibility Audit** | QA | WCAG 2.1 AA: contrast, keyboard, ARIA, focus |
| 8.6 | **Performance Testing** | QA | Page load <2s, WS latency <100ms, chart render <500ms |
| 8.7 | **Security Testing** | Security + QA | Auth bypass, injection, XSS, CSRF, rate limit |
| 8.8 | **Docker Integration** | Backend + Frontend | `docker compose up --build` works, health checks pass |
| 8.9 | **Raspberry Pi Compatibility** | Backend | Verify arm64 build, memory usage <512MB |
| 8.10 | **Regression Test Suite** | QA | Run all 65+ backend tests + frontend tests |

### Test Matrix

| Category | Tests | Target |
|----------|-------|--------|
| Backend Unit | 65+ | 100% pass |
| Backend Integration | 20+ | 100% pass |
| Frontend Unit | 20+ | 100% pass |
| Frontend E2E | 15+ | 100% pass |
| API Contract | 30+ | 100% pass |
| WebSocket | 10+ | 100% pass |
| Database | 10+ | 100% pass |
| Security | 15+ | 100% pass |
| Performance | 5+ | Meet thresholds |

### Quality Gates (MANDATORY)
```
GATE 1 - FRONTEND:     Production build succeeds, no import errors, no broken routes, no console errors
GATE 2 - BACKEND:      App starts, APIs respond, validation works, auth works
GATE 3 - DATABASE:     Migrations apply, relationships valid, transactions work
GATE 4 - AI/ML:        Model loads, features extract, predictions valid
GATE 5 - DNS:          Resolver connects, events collected, blocking verified
GATE 6 - SECURITY:     Permissions enforced, secrets protected, validation works
GATE 7 - INTEGRATION:  FE↔BE, BE↔DB, DNS→BE, AI→features, WS→events, stats=DB
GATE 8 - DEPLOYMENT:   Docker valid, services start in order, health checks work
```

---

## Phase 9: Quality Gates & Final Verification (Week 5-6)

### Agent: Master + QA

### Objectives
Run all mandatory quality gates, document results, generate final report.

### Tasks

| # | Task | Description |
|---|------|-------------|
| 9.1 | **Execute Gate 1: Frontend** | `cd frontend && npm run build && npm test` |
| 9.2 | **Execute Gate 2: Backend** | `cd backend && python -m pytest tests/ -v` |
| 9.3 | **Execute Gate 3: Database** | Run migration up/down, test transactions |
| 9.4 | **Execute Gate 4: AI/ML** | Load model, run inference benchmark, verify thresholds |
| 9.5 | **Execute Gate 5: DNS** | Start resolver, send queries, verify blocklist enforcement |
| 9.6 | **Execute Gate 6: Security** | Run security test suite, dependency audit |
| 9.7 | **Execute Gate 7: Integration** | Full stack via docker compose, automated E2E |
| 9.8 | **Execute Gate 8: Deployment** | Clean build, start order, health checks, volumes |
| 9.9 | **Generate Final Report** | `docs/FINAL_VERIFICATION_REPORT.md` with all results |
| 9.10 | **Document Remaining Issues** | Track known limitations, future work |

### Final Verification Report Contents
1. Original project audit summary
2. Architecture changes made
3. Agents created and their contributions
4. Tasks completed by each agent
5. Files modified (with git diff summary)
6. Frontend pages implemented (11 pages + settings)
7. Backend endpoints verified (all 30+ endpoints)
8. Database migrations applied
9. AI model verification (load, inference, metrics)
10. DNS integration verification (resolver, blocking, logs)
11. Authentication/Authorization verification
12. Security test results
13. Frontend test results (unit + E2E)
14. Backend test results (unit + integration)
15. Integration test results
16. Production build results
17. Remaining issues / known limitations
18. Deployment instructions

### Approval Criteria
- [ ] All 8 quality gates PASS
- [ ] Zero critical/high severity findings
- [ ] Final report generated and reviewed
- [ ] Deployment documented

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Frontend scope creep | High | High | Strict page definitions, Master approves additions |
| Design system delays | Medium | High | Phase 1 timeboxed, minimal viable tokens first |
| Backend API changes during FE dev | Medium | Medium | API contracts frozen after Phase 2 |
| Model loading fails on Pi | Low | High | Test arm64 build early, fallback heuristic mode |
| WebSocket scaling issues | Low | Medium | Document single-worker limitation |
| RBAC complexity | Medium | Medium | Phase 7, start with simple roles |
| Docker build failures | Low | High | Test builds in CI each phase |
| Test environment instability | Medium | Medium | Dedicated test DB, mock external services |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Frontend pages complete | 11/11 |
| Backend endpoints functional | 30+/30+ |
| Test pass rate | 100% (all gates) |
| Build time (clean) | <10 min |
| Page load (production) | <2s |
| API response (p95) | <200ms |
| WS message latency | <100ms |
| Model inference (p99) | <50ms |
| Docker image size (backend) | <500MB |
| Docker image size (frontend) | <100MB |
| Memory usage (idle) | <512MB |
| Zero critical security findings | ✅ |

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Master Orchestrator | | | |
| Frontend Specialist | | | |
| Design System Specialist | | | |
| Backend Specialist | | | |
| Database Specialist | | | |
| AI/ML Specialist | | | |
| DNS Integration Specialist | | | |
| Security Specialist | | | |
| QA/Testing Specialist | | | |