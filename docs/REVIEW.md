# Project review: defects found, fixes, and report alignment

Reviewed: `dns-defender-ai-nov-8-2026` (zip) against the project report (`DOC-20261108-WA0001.docx`).
Every defect below was reproduced before being fixed.

## 1. Defects found in the submitted code

| # | Severity | Finding (how it was verified) | Fix |
|---|---|---|---|
| 1 | **Blocker** | `docker-compose*.yml` reference three Dockerfiles (`backend/`, `dns-resolver/`, root) that **do not exist** → `docker compose build` cannot work. | Wrote `backend/Dockerfile`, `dns-resolver/Dockerfile`, `frontend/Dockerfile` (+ nginx config); compose rewritten and validated with `docker compose config`. |
| 2 | **Blocker** | `npm install` fails (`ERESOLVE`): unused `esbuild ^0.25` pin conflicts with Vite 8. | Removed the pin. Clean `npm ci` + build + tests pass. |
| 3 | **Blocker** | `dnsmasq.conf` hard-codes `listen-address=192.168.1.1`; dnsmasq exits with *"failed to create listening socket … Cannot assign requested address"* inside any container. | Container-safe config; port/log/upstreams set by `entrypoint.sh`. Run against real dnsmasq. |
| 4 | **High** | **Blocking never took effect.** `address=` rules are not re-read on SIGHUP (tested: query still resolved; only a restart applied it). Also `pkill` cannot signal a process in another container. | Blocklist is a dnsmasq *servers-file* (re-read on SIGHUP, verified), rewritten atomically; the resolver container's watcher sends SIGHUP on change. Verified end to end: API block → NXDOMAIN for domain + subdomains + TXT; unblock restores. |
| 5 | **High** | **Config injection**: domain strings were written into the resolver config unvalidated (a newline in a "domain" injects arbitrary directives). | Strict regex validation at the API and again at the file writer; tested. |
| 6 | **High** | **Detection did not work.** Node engine scored `xk910zp2a88q093.biz` (NXDOMAIN) as **benign 0.198**; weighted voting made a single strong signal unable to reach the threshold. The project's own DGA-detection pytest failed. | New detector (see §2). |
| 7 | **High** | **ML claims unsupported.** `train.py` used synthetic Gaussian data → 100% accuracy; README claimed "98.4% on 10,000+ benchmarked samples" (no such benchmark exists). The trained model also showed **training/serving skew**: real first-seen DGA domains scored ≈0.4, `stackoverflow.com` 0.33 (top feature was a synthetic behavioural one). | Retrained on a public labelled dataset (675k domains), three evaluation protocols, honest numbers in README. |
| 8 | **High** | **Two disconnected backends.** The dashboard talked to an in-memory Node/Express server; the FastAPI backend had no DB use, never started its log monitor (0 call sites), lacked the endpoints the UI used, and crashed when run as a script (relative import). Dashboard figures were partly fabricated (`total_queries = n*18+1240`, random analytics series, hard-coded Pi telemetry). | One backend (FastAPI + SQLAlchemy/PostgreSQL) with real aggregates; minimal React dashboard. |
| 9 | Medium | Log monitor only parsed query lines → `nxdomain_ratio` was always 0 for live traffic; query types like `HTTPS` not matched. | Parses query + result lines (format captured from real dnsmasq 2.91); handles partial lines, rotation, truncation. |
| 10 | Medium | `special_char_ratio` counted dots, so it measured label count, not special characters. | Replaced by `hyphen_ratio` (as in the report). |
| 11 | Medium | Security hygiene: `CORS *` with credentials, all write endpoints unauthenticated (including *block domain* on a DNS server), default DB password committed in compose/`.env.example`, runtime API-key entry endpoint. | Optional API key on every route + WebSockets, explicit CORS origins, `POSTGRES_PASSWORD` required (compose refuses to start without it), key only via environment. |
| 12 | Medium | `setup-raspberrypi.sh`: runs docker right after `usermod -aG docker` (fails until re-login), no `.env`, fragile `sed` of `resolved.conf`, no `--build`. | Rewritten, `shellcheck`-clean. |
| 13 | Low | Unbounded growth: no retention of events, no log rotation of the dnsmasq log. | `RETENTION_DAYS` pruning; resolver truncates the log past 50 MB (tailer handles truncation). |

Defects I introduced and caught while testing my own work: dnsmasq `port=` in the config overrides `--port`; dnsmasq re-creates its log as `0660`
so the non-root backend could not read it; forests grown to `min_samples_leaf=3` exhausted memory on the full dataset (and were already 15.7 MB on a 120k-row
subsample); regularised to `min_samples_leaf=20`, the full-data model is 17.9 MB.

## 2. What changed architecturally

* **Backend:** FastAPI + SQLAlchemy; tables per report §4.4 (`dns_events`, `feature_vectors`, `ml_predictions`, `security_alerts`, `user_accounts`) + `blocked_domains`, `allowlisted_domains`.
* **ML:** Random Forest on lexical features of the registrable label (same code in training and serving), plus rules for behaviour the dataset cannot teach, combined by noisy-OR. Behavioural features are *not* Random-Forest inputs because no labelled public dataset of them exists; training on synthetic ones is what caused finding 7.
* **Frontend:** one-page React dashboard (stats, charts, check-a-domain, live traffic, alert triage, blocklist). The original 3,700-line, 10-view UI was replaced; it ran on fabricated data.
* **Ingestion:** dnsmasq log (Docker default), Scapy sniffer (optional), Zeek `dns.log` import.

## 3. Alignment with the project report

| Report says | Implementation | Status |
|---|---|---|
| FastAPI, PostgreSQL + SQLAlchemy, Scikit-learn + Joblib, WebSockets, Docker | as specified (`/ws/alerts`) | ✅ |
| Random Forest classifier, cross-validation, precision/recall/F1 | RF; 5-fold CV; metrics in `model_card.json` | ✅ |
| Objective 4: "train and compare suitable classifiers" | `ml-training/compare_models.py` → `docs/model_comparison.json` (4 models) | ✅ |
| Scapy and Zeek capture | Scapy sniffer (queries only) + Zeek importer + dnsmasq log | ✅ (Scapy live sniffing not run here — needs root) |
| ML inference < 50 ms | ≈ 3–5 ms measured (asserted in a test) | ✅ |
| **Next.js + shadcn/ui** frontend | **React 19 + Vite + Tailwind + Recharts** | ⚠️ differs — either update the report text or port the dashboard |
| Features: `query_frequency`, `nxdomain_rate` etc. as model inputs | computed live and used by **rules**; the Random Forest uses lexical features | ⚠️ differs — state this in the report |
| `user_accounts` table / RBAC | table exists; access control is a shared API key | ⚠️ partial |
| dnspython | not used | ⚠️ differs |

Test cases (§6.2): TC-01 `test_tc01_rest_inference…` ✅ · TC-02 `test_tc02_websocket…` ✅ · TC-03 `test_scapy_packet_parsing` ✅ (packet parsing; not a live socket) ·
TC-04 `test_tc04_event_features_prediction_persisted` ✅ (also on PostgreSQL 16) · TC-05 `test_tc05_random_forest_model_loads…` ✅ ·
TC-06 ⚠️ UI tests verify that data flows into the page (jsdom); chart pixels were not visually checked · TC-07 ⚠️ see below.

## 4. Verification performed

| Area | Evidence |
|---|---|
| Unit/API tests | 65 pytest (SQLite) pass; the 20 API tests also pass on **real PostgreSQL 16**; 3 deliberately injected bugs (validation off, NXDOMAIN ignored, auth bypass) are each caught |
| UI | `tsc` clean, production build, 4 vitest render/interaction tests; clean `npm ci` from the lockfile |
| Resolver | real `entrypoint.sh` + `dnsmasq.conf` + dnsmasq 2.91: healthcheck command, upstream forwarding, SIGHUP reload, block/unblock, log format, graceful shutdown, env-injection rejection |
| End to end | resolver → log → monitor → model → DB → API → block → resolver enforcement, driven by `scripts/simulate-traffic.sh` |
| nginx | exact `nginx.conf` with Docker's embedded DNS emulated: static, SPA fallback, REST proxy, **WebSocket upgrade**, and survives an unresolvable backend |
| Docker | `docker compose config` valid (and fails clearly without a password); `hadolint` clean apart from a style note (unpinned `apk` versions); backend image steps reproduced in a clean venv (health check passes, pandas not needed) |

## 5. Not verified — please do before submission

1. **`docker compose up --build` itself.** There is no Docker daemon or Docker Hub access in my environment, so images were not built. Each build step and runtime behaviour was reproduced outside Docker as above, but TC-07 should be run on your machine/Pi once.
2. **Raspberry Pi / arm64 performance** (build time, memory, inference latency). Wheels for the pinned packages exist for aarch64, but I could not test it.
3. **False-positive rate on real home traffic.** Reported numbers are on a public benchmark (Alexa vs. DGA families); real LANs contain hash-like hostnames, IoT names and CDNs. Expect to use the allowlist.
4. **Visual check of the dashboard in a browser** (layout, chart rendering).
5. The report's text still describes the Next.js/shadcn stack — update it or tell me and I will port the UI.
