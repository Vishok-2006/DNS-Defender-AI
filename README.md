# 🛡️ DNS Defender AI

AI-assisted DNS behaviour analysis that detects malicious domains (DGA, DNS tunnelling, NXDOMAIN bursts,
phishing-style names) on a home/lab network and can sinkhole them at the resolver.
Final-year project; designed to run on a Raspberry Pi 4/5 (64-bit OS) or any Linux host.

```
 LAN clients ──DNS──▶ dnsmasq resolver ──▶ query log ──▶ FastAPI backend ──▶ PostgreSQL
                          ▲ (SIGHUP)                        │  Random Forest + rules
                          │                                 ├─ REST  /api/v1/*
                 blocked.conf (servers-file) ◀── block API  └─ WebSocket /ws/alerts, /ws/traffic
                                                                    │
                                               React dashboard (nginx) ◀┘
```

## Quick start (Docker)

```bash
cp .env.example .env
# set POSTGRES_PASSWORD (openssl rand -hex 24) and, recommended, API_KEY
docker compose up -d --build
# dashboard: http://localhost:3000        API docs: http://localhost:8000/docs
./scripts/simulate-traffic.sh 127.0.0.1     # demo: benign + DGA + tunnelling + phishing lookups
```

On a Raspberry Pi, `./scripts/setup-raspberrypi.sh` does all of this (Docker, freeing port 53, generated secrets, LAN-only
firewall rules). Then set your router's DHCP DNS server to the Pi.
If port 53 is taken on a dev machine, use `DNS_PORT=5353` in `.env`.

No traffic source handy? Open the dashboard and use **Demo traffic** — it feeds the same pipeline.

## Running without Docker

```bash
# backend (SQLite, no resolver needed)
python -m venv .venv && . .venv/bin/activate && pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload            # http://localhost:8000/docs
# frontend
cd frontend && npm ci && npm run dev                   # http://localhost:5173 (proxies /api and /ws)
```

## How detection works

`risk = noisy-OR( Random-Forest probability , rule scores )` → **benign / suspicious / malicious**

| Signal | Type | Notes |
|---|---|---|
| Name looks algorithmically generated | **Random Forest** on 14 lexical features | length, Shannon entropy, digit/hyphen/vowel ratios, longest consonant run, digit↔letter switches, subdomain count, label lengths, + character-trigram "naturalness" score (language model of benign names) |
| DNS tunnelling | rule | labels ≥ 40 chars, hex/base32-looking subdomains, TXT-heavy traffic |
| NXDOMAIN burst | rule | ≥ 10 distinct failing lookups from one client in 60 s; per-domain NXDOMAIN ratio |
| Beaconing | rule | very regular inter-arrival times (never alerts on its own) |
| Phishing-style name | rule | several lure words joined with hyphens |
| CDN / vendor infrastructure | allow-logic | `TRUSTED_ROOTS` cap the *lexical* score (hash-like CDN names); rules still apply |

The model scores the **registrable label** (via the public-suffix list), so `www`/CDN prefixes don't cause false positives.
Rules are documented heuristics; they are **not** measured by the dataset below.

### Measured model performance (`backend/models/model_card.json`)

Trained on [chrmor/DGA_domains_dataset](https://github.com/chrmor/DGA_domains_dataset) — 337,500 DGA domains from 25 malware
families + 337,337 benign (Alexa) domains. Cucchiarelli et al., *Expert Systems with Applications* 170 (2021). Reproduce with
`pip install -r ml-training/requirements.txt && python ml-training/train.py`.

| Evaluation | Result |
|---|---|
| Random 70/15/15 split, test n=101,226, threshold 0.5 | acc **91.0%**, precision 95.6%, recall 85.9%, F1 90.5%, ROC-AUC **0.965**, FPR 4.0% |
| Same, "malicious" threshold (0.79, ≤1% FPR on validation) | precision **98.7%**, recall 78.4%, FPR 1.0% |
| 5-fold cross-validation | ROC-AUC 0.9641 ± 0.0004, F1 0.903 ± 0.001 |
| **Six malware families never seen in training** (n=148,467) | ROC-AUC **0.795**; at the malicious threshold: precision 98.4%, recall 49.7%, FPR 0.9% |
| Inference latency (single domain, incl. rules) | ≈ 3–5 ms (requirement: < 50 ms) |

Recall on unseen families: ramnit 95%, necurs 91%, pykspa 68%, conficker 38%, **gozi 6%, suppobox ~0%**.
Model comparison on the same split (`docs/model_comparison.json`): Logistic Regression AUC 0.929, Decision Tree 0.953,
**Random Forest 0.959**, Gradient Boosting 0.966 — Random Forest was kept as specified in the project report; gradient boosting
is marginally better and a drop-in swap in `train.py`.

### Known limitations (please read before a demo or viva)

* Dictionary-word DGA families (gozi, suppobox, matsnu…) look like ordinary names and are essentially **not detectable from
  the name alone**; only behavioural rules can help there.
* Short random names (e.g. `k93jq018zll.biz`) can score below the suspicious threshold.
* Benign data is Alexa-top sites; unusual-but-legitimate names (new brands, hash-named internal hosts) can be flagged —
  use the **Allow** button / allowlist.
* The tunnelling/beaconing/NXDOMAIN/phishing rules are heuristics with no labelled evaluation.
* Behavioural state lives in memory (single worker, resets on restart); alerts and events persist in the database.

## API (all under `/api/v1`; interactive docs at `/docs`)

| Method & path | Purpose |
|---|---|
| `GET /health` | status, model loaded, monitor state |
| `GET /stats`, `GET /queries`, `GET /alerts`, `GET/PATCH /alerts/{id}` | dashboard data and triage |
| `POST /dns/test-query` | analyse a domain (also persists it and pushes WebSocket events) |
| `POST /dns/simulate` | demo scenarios: `benign`, `dga_burst`, `tunnelling`, `phishing` |
| `POST /alerts/{id}/analyze` | explanation (NVIDIA NIM if `NVIDIA_API_KEY` set, else offline rules) |
| `POST /domains/block`, `/domains/unblock`, `GET /domains/blocklist` | resolver sinkhole (NXDOMAIN for the domain **and its subdomains**) |
| `GET/POST /domains/allowlist`, `POST /domains/allowlist/remove` | analyst exemptions |
| `POST /import/zeek` | upload a Zeek `dns.log` (TSV or JSON) as `text/plain` |
| `GET /reports/alerts.csv`, `GET/PATCH /settings` | export; runtime policy |
| `WS /ws/alerts`, `WS /ws/traffic` | live push (add `?api_key=…` when `API_KEY` is set) |

Capture modes (`CAPTURE_MODE`): `dnsmasq` (default in Docker), `scapy` (needs root/`CAP_NET_RAW`; sees queries only, so no
NXDOMAIN information), `off` (API/import only).

## Safety defaults

* **Alert-only** by default. Automatic blocking needs `ALERT_ONLY_MODE=false` **and** `AUTO_BLOCK_CONFIRMED=true`.
* Trusted infrastructure and allowlisted domains can never be blocked. Domain names are strictly validated before being
  written to the resolver config.
* Set `API_KEY` when the dashboard is reachable from a LAN. Never expose port 53 to the internet (open-resolver abuse).
* DNS history is personal data: events are pruned after `RETENTION_DAYS` (default 7).

## Configuration

See `.env.example`. Key variables: `POSTGRES_PASSWORD` (required), `API_KEY`, `DNS_UPSTREAM_SERVERS`, `DNS_PORT`,
`DNS_BIND_IP`, `UI_PORT`, `ALERT_ONLY_MODE`, `RETENTION_DAYS`, `NVIDIA_API_KEY`.

## Tests

```bash
pip install -r tests/requirements.txt && python -m pytest          # 65 tests (SQLite)
TEST_DATABASE_URL=postgresql://user:pass@host/db python -m pytest tests/test_api.py   # same API tests on PostgreSQL
cd frontend && npm test                                              # 4 UI render tests (vitest + jsdom)
```

## Troubleshooting

* **Resolver won't start: port 53 in use** → `systemd-resolved` stub (`setup-raspberrypi.sh` fixes it) or set `DNS_PORT=5353`.
* **All clients appear as one IP** → Docker NAT; for exact client IPs on a Pi use `network_mode: host` for `dns-resolver`.
* **Dashboard says "Model missing – heuristic mode"** → `backend/models/dga_rf.joblib` is missing or was trained with a
  different scikit-learn version (versions are pinned in `requirements.txt`); retrain with `ml-training/train.py`.
* **Blocking says `enforced: false`** → the backend cannot write `DNS_BLOCKLIST_PATH` (check the shared `dns_rules` volume).
