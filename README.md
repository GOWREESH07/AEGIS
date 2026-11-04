# AEGIS v2 — Autonomous Defense Pipeline & Repository AI-Attack Proneness Scanner

> An educational, full-stack security simulation demonstrating a multi-stage agentic cyberattack (**JadePuffer-sim**), an autonomous defense pipeline (**the Council**), and a static **Repository AI-Attack Proneness Scanner ("RepoScan")** mapped to the **OWASP Top 10 for Agentic Applications (2026)** and **MITRE ATLAS**.

**Not real attack tooling.** All stages drive synthetic behavioral patterns against a toy FastAPI service built specifically to receive them. RepoScan performs strictly static analysis and never executes, installs, or imports code from scanned repositories.

---

## Architecture

```
                  ┌──────────────────────────────────────────────────────────────────┐
                  │                      Docker Bridge Networks                      │
                  │                                                                  │
  [Attack Console]─►[Attacker :8003]──►[AEGIS Proxy :8000]──►[Target :8001 / :8002]  │
   [:5173]         │  jadepuffer-sim    │  surveillance + guardrail                   │
                   │  stages 01–09      │  3-analyst Council + human escalation       │
  [Defense Console]─►─────────────────  │  autonomous response + self-healing         │
   [:5174]         │  /ws/defense◄──────┤  incident report export (.md / .pdf)        │
                   │                    │          │                                  │
                   │              [Redis :6379]    ▼ (isolated reposcan_net)          │
                   │                            [RepoScan :8004]                      │
                   │                             3-analyst static scanner             │
                   └──────────────────────────────────────────────────────────────────┘
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| `redis` | internal | Shared state: blocklist, sliding-window counters, token-bucket lateral drops |
| `target` | 8001 / 8002 (internal) | Toy FastAPI target — 12 mock endpoints, `/api/flow/execute`, toy MCP/RAG/package/FS endpoints, TCP `:8002` |
| `aegis` | **8000** | Defense engine + reverse proxy — surveillance, Council, response, self-healing, RepoScan gateway |
| `reposcan` | 8004 (isolated) | Static Repository AI-Attack Proneness Scanner on isolated `reposcan_net` |
| `attacker` | **8003** | JadePuffer-sim API — trigger/stop/monitor stages 01–05 + optional AI stages 06–09 |
| `frontend-attacker` | **5173** | Attack Console — configure and run attacks, live kill-chain view |
| `frontend-defense` | **5174** | AEGIS Defense Console — Live Defense view + **Repo Scan** tab |

---

## Feature 1: Repository AI-Attack Proneness Scanner ("RepoScan")

Paste any public GitHub repository URL (`https://github.com/owner/repo`) into the **REPO SCAN** tab of the Defense Console (`http://localhost:5174`) or call the API directly:

```bash
# Start a scan (or test against built-in fixtures: aegis-demo/vulnerable_repo or aegis-demo/clean_repo)
curl -X POST http://localhost:8000/api/reposcan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/aegis-demo/vulnerable_repo"}'

# Fetch report JSON, Markdown, or PDF
curl http://localhost:8000/api/reposcan/<scan_id>
curl -O http://localhost:8000/api/reposcan/<scan_id>/report.md
curl -O http://localhost:8000/api/reposcan/<scan_id>/report.pdf
```

### Hard Safety Rules Enforced by RepoScan
1. **Static analysis only:** Never executes, installs, builds, or imports anything from the scanned repository (`npm install`, `pip install`, `make`, test runners, or repository scripts are never invoked; verified by unit tests mocking `subprocess`).
2. **Hardened git clone:** Clones with `git clone --depth 1 --no-tags --single-branch`, `GIT_TERMINAL_PROMPT=0`, `-c core.hooksPath=/dev/null`, and `-c submodule.recurse=false` into a temporary directory deleted immediately in a `finally` block.
3. **Strict resource & path limits:** Max repository size **200 MB**, max single file size **2 MB**, skips binary files, never follows symlinks outside the clone root, and enforces a **120-second** clone timeout.
4. **Network isolation:** Runs in its own `reposcan` container on `reposcan_net` with no access to Redis secrets or the attacker/target network.
5. **Hostile data handling:** Repository content is treated strictly as untrusted data. When the optional LLM summary layer (`REPOSCAN_LLM=1`) is enabled, it receives only structured finding metadata JSON and can never change any numerical score.
6. **Optional GitHub Token:** Accepts `GITHUB_TOKEN` via environment variable for higher rate limits without ever logging it.

### Three-Analyst Scoring Formula

RepoScan mirrors the AEGIS Council with three specialized static analysts:

| Analyst | Weight ($w_i$) | Scope |
|---|---:|---|
| **CI/CD & Agent-Workflow Analyst** | `1.5` | `.github/workflows/*.yml`, AI agents running in CI |
| **Supply-Chain Analyst** | `1.0` | `package.json`, `requirements.txt`, `setup.py`, lockfiles, npm/PyPI registries, OSV.dev |
| **AI-Surface Analyst** | `1.5` | Agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`), MCP configs, LLM code sinks, secrets |

Inside each analyst, every triggered check has a severity weight (`critical = 0.45`, `high = 0.30`, `medium = 0.15`, `low = 0.05`) and confidence $c \in [0, 1]$:

$$\text{score}_i = 1 - \prod_{k \in \text{findings}_i} \left(1 - \text{severity}_k \times \text{confidence}_k\right)$$

The overall proneness percentage is the weighted average across the three analysts (`total weight = 4.0`):

$$\text{proneness\_\%} = 100 \times \frac{1.5 \cdot \text{score}_{\text{cicd}} + 1.0 \cdot \text{score}_{\text{supply}} + 1.5 \cdot \text{score}_{\text{ai}}}{4.0}$$

- **Critical Floor:** If any finding has `severity == "critical"`, the overall score is at least **70.0%**.
- **Risk Bands:** `Low < 30%`, `Moderate 30–59%`, `High 60–79%`, `Critical ≥ 80%`.

### Complete Check Catalog & OWASP Top 10 for Agentic Applications (2026) Mapping

| ID | Analyst | Severity | Check Description | OWASP ASI (2026) | Real-World Incident Reference |
|---|---|---|---|---|---|
| **A1** | CI/CD | `critical` | `pull_request_target` / `workflow_run` checking out untrusted PR head and running code | `ASI01`, `ASI03`, `ASI05` | Ultralytics (Dec 2024), tj-actions chain (Mar 2025) |
| **A2** | CI/CD | `critical` | AI agent action (`claude-code-action`, Gemini CLI, Copilot) triggered by `issues`/`issue_comment`/`pull_request_target`/`discussion` with shell/write/edit tools | `ASI01`, `ASI02`, `ASI05` | Clinejection (Feb 2026), "Comment and Control" (Apr 2026) |
| **A3** | CI/CD | `high` | Untrusted `${{ github.event.* }}` text interpolated directly into `run:` or AI `prompt` | `ASI01`, `ASI05` | Clinejection (Feb 2026) |
| **A4** | CI/CD | `high` | AI action configured to allow any non-write user (`allowed_non_write_users: "*"`) | `ASI03`, `ASI09` | "Comment and Control" (Apr 2026) |
| **A5** | CI/CD | `high` | Missing top-level `permissions:` block or `permissions: write-all` | `ASI03` | — |
| **A6** | CI/CD | `medium` | Third-party GitHub Action pinned to mutable tag/branch instead of 40-char SHA | `ASI04` | tj-actions (Mar 2025), trivy-action (Mar 2026) |
| **A7** | CI/CD | `medium` | Low-privilege issue/triage workflow and release workflow sharing `actions/cache` keys | `ASI04`, `ASI06` | Clinejection cache poisoning (Feb 2026) |
| **A8** | CI/CD | `medium` | Publishing secrets (`NPM_TOKEN`, `PYPI_*`, `VSCE_PAT`, cloud keys) exposed at workflow/job scope | `ASI03`, `ASI10` | Ultralytics / cline@2.3.0 |
| **B1** | Supply-Chain | `high` | Lifecycle install hooks (`preinstall`/`install`/`postinstall` in `package.json` or custom `setup.py` install) | `ASI04`, `ASI05` | Shai-Hulud worm (Sep 2025), cline@2.3.0 (Feb 2026) |
| **B2** | Supply-Chain | `high` | **Slopsquatting**: declared dependency does not exist on npm or PyPI (AI-hallucinated package) | `ASI04`, `ASI08` | AI-hallucinated package campaigns (2025–2026) |
| **B3** | Supply-Chain | `medium` | Suspected typosquat (Levenshtein distance ≤ 2 from a popular npm/PyPI package) | `ASI04` | — |
| **B4** | Supply-Chain | `medium`/`high` | Known-vulnerable dependency version detected via **OSV.dev API** (`api.osv.dev/v1/querybatch`) | `ASI04` | — |
| **B5** | Supply-Chain | `medium` | Missing lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`) or unpinned ranges | `ASI04` | Shai-Hulud worm / cline@2.3.0 |
| **B6** | Supply-Chain | `low` | Missing Dependabot / Renovate config and missing `SECURITY.md` | `ASI04` | — |
| **C1** | AI-Surface | `critical` | Agent instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`) containing hidden Unicode (zero-width, bidi overrides `U+202A–U+202E`, tags `U+E0000–U+E007F`) | `ASI01`, `ASI06` | "Rules File Backdoor" (Mar 2025) |
| **C2** | AI-Surface | `high` | Instruction files directing shell execution, remote URL fetch, confirmation bypass, reading `~/.ssh`/`.env`, or "ignore previous instructions" | `ASI01`, `ASI02`, `ASI09` | "Rules File Backdoor" / s1ngularity |
| **C3** | AI-Surface | `high` | MCP configs (`.mcp.json`, `mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`) with unpinned `npx`/`uvx`, auto-approve tools, broad roots, or inline secrets | `ASI02`, `ASI04` | MCP Tool Poisoning (Apr 2025) |
| **C4** | AI-Surface | `high` | LLM output passed to `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`, `child_process.exec`, or raw SQL | `ASI05` | OWASP ASI05 Insecure Code Execution |
| **C5** | AI-Surface | `medium` | User input concatenated into system prompts without delimiter or role separation | `ASI01` | — |
| **C6** | AI-Surface | `medium` | Agent tools exposing shell, filesystem, or network access without allow-list or human confirmation | `ASI02`, `ASI09` | — |
| **C7** | AI-Surface | `medium` | RAG or vector memory stores ingesting external content without sanitization | `ASI06` | Indirect Prompt Injection via RAG |
| **C8** | AI-Surface | `critical` | Hard-coded AI/cloud credentials (`sk-`, `sk-ant-`, `AIza`, `ghp_`, `AKIA`) or committed `.env` files (masked prefix only) | `ASI10` | s1ngularity (Aug 2025) |
| **C9** | AI-Surface | `low` | AI application repository with no prompt-injection tests or evals | `ASI01`, `ASI09` | — |

---

## Attack Stages (JadePuffer-sim)

### Core 5-Stage Kill Chain
1. **01 RECON (`AML.T0006` | `ASI01`)** — Sweep 12 mock endpoints concurrently in <5s.
2. **02 ADAPT (`AML.T0043` | `ASI05`)** — Cycle `application/xml` → `application/json` → `application/octet-stream` against `/api/flow/execute`.
3. **03 AILM (`AML.T0051` | `ASI01`)** — Send prompt/script injection tokens in `X-Forwarded-Context`.
4. **04 LATERAL (`AML.T0029` | `ASI02`)** — TCP socket burst to `target:8002` at 100+ pkt/s; intercepted by AEGIS token-bucket drop + quarantine confirmation.
5. **05 EXEC (`AML.T0048` | `ASI05`)** — Attempt to lock `staging/*.txt` → `*.locked` via `/api/admin`.

### Optional AI-Attack Stages (Feature 4)
6. **06 MCP_POISON (`AML.T0054` | `ASI02`)** — Fake MCP tool registration (`/api/mcp/register`) containing zero-width Unicode and hidden ssh-key theft instructions.
7. **07 RAG_INJECT (`AML.T0051.001` | `ASI06`)** — Indirect prompt injection via external document upload to `/api/rag/ingest`.
8. **08 SLOPSQUAT (`AML.T0010` | `ASI04`)** — Attempt to install AI-hallucinated package `fake-ai-hallucinated-sdk` via `/api/packages/install`.
9. **09 CRED_HARVEST (`AML.T0055` | `ASI10`)** — Attempt to read `~/.claude/credentials.json`, `~/.gemini/oauth_creds.json`, and `.env` via `/api/fs/read` (*resembles s1ngularity, Aug 2025*).

### Stage-to-MITRE ATLAS & OWASP ASI (2026) Event Mapping (`aegis/guardrail.py`)

`aegis/guardrail.py` implements a **heuristic guardrail (rule-based)** combining a fast regex/Unicode matcher with a deterministic weighted-token heuristic scorer behind the pluggable `GuardrailClassifier` protocol (so a learned model can be plugged in later without changing `AIBehaviorAnalyst`). Every `DefenseEvent` and `CouncilVerdict` carries the following verified taxonomy tags:

| Stage | Name | MITRE ATLAS ID | MITRE ATLAS Technique | OWASP ASI ID | OWASP Agentic Top-10 (2026) Category |
|---:|---|---|---|---|---|
| **01** | `RECON` | `AML.T0006` | Active Scanning | `ASI01` | Agent Goal Hijacking & Prompt Injection |
| **02** | `ADAPT` | `AML.T0043` | Craft Adversarial Data | `ASI05` | Insecure Code Execution & Unsafe Output Handling |
| **03** | `AILM` | `AML.T0051` | LLM Prompt Injection | `ASI01` | Agent Goal Hijacking & Prompt Injection |
| **04** | `LATERAL` | `AML.T0029` | Denial of ML Service / Internal Flood | `ASI02` | Excessive Agency & Tool Misuse |
| **05** | `EXEC` | `AML.T0048` | External Harms / Payload Execution | `ASI05` | Insecure Code Execution & Unsafe Output Handling |
| **06** | `MCP_POISON` | `AML.T0054` | LLM Plugin / Tool Compromise | `ASI02` | Excessive Agency & Tool Misuse |
| **07** | `RAG_INJECT` | `AML.T0051.001` | Indirect Prompt Injection | `ASI06` | Memory & Context Poisoning |
| **08** | `SLOPSQUAT` | `AML.T0010` | ML Supply Chain Compromise | `ASI04` | Agentic Supply-Chain & Dependency Compromise |
| **09** | `CRED_HARVEST` | `AML.T0055` | Unsecured Credentials | `ASI10` | Sensitive Data & Credential Exposure |

---

## Evaluation Harness (`eval/harness.py`) & Measured Results

Run the reproducible evaluation suite (`N = 30` trials per condition, 200 benign traffic replay windows, threshold sweep `0.20–0.80`, and analyst ablation):

```bash
python3 eval/harness.py
```

Outputs are written to `eval/results/`:
- `eval/results/trials_n30.csv`
- `eval/results/benign_replay.csv`
- `eval/results/threshold_sweep.csv`
- `eval/results/analyst_ablation.csv`
- `eval/results/summary_metrics.json`
- `eval/results/eval_charts.png`, `threshold_sweep.svg`, `analyst_ablation.svg`

### Measured Evaluation Summary (from actual `eval/harness.py` run)

| Metric | AEGIS Disabled (N=30) | AEGIS Enabled (N=30) |
|---|---:|---:|
| **Attack Success Rate** | `100.0%` | `0.0%` |
| **Kill-Chain Completion Time** | `89.06 ± 8.80 ms` | `82.35 ± 5.66 ms` |
| **Stage 01 (RECON) Detection Latency** | — | `12.34 ± 2.87 ms` |
| **Stage 02 (ADAPT) Detection Latency** | — | `13.56 ± 2.57 ms` |
| **Stage 03 (AILM) Detection Latency** | — | `14.39 ± 2.98 ms` |
| **Stage 04 (LATERAL) Detection Latency** | — | `15.27 ± 3.04 ms` |
| **Stage 05 (EXEC) Detection Latency** | — | `15.21 ± 3.05 ms` |
| **End-to-End Detection-to-Action Latency** | — | `16.47 ± 3.16 ms` |
| **Self-Healing Delta (Run 1 → Mutated Run 2)** | — | `-5.90 ± 1.29 ms` |
| **Benign Traffic Replay (200 windows @ 0.35)** | — | `FPR = 2.00%`, `Precision = 0.9740`, `Recall = 1.0000`, `F1 = 0.9868` |

---

## Running Tests & Docker Stack

```bash
# Run all unit tests (Feature 3 fixes, RepoScan checks & fixtures, Features 4 & 5)
python3 tests/test_feature3_fixes.py -v
python3 tests/test_reposcan.py -v
python3 tests/test_features_4_and_5.py -v

# Build and start all containers
docker compose up --build -d
```
