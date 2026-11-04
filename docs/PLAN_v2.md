# AEGIS v2 — Implementation Plan (`docs/PLAN_v2.md`)

## Overview
AEGIS v2 extends the existing autonomous defense pipeline with five major feature tracks while preserving every existing endpoint, dashboard view, and test. Implementation follows the strict order specified:
**Feature 3 → Feature 1 → Feature 2 → Feature 4 → Feature 5**

---

## Phase 1: Feature 3 — Fix Known Issues from Review

### Goals
1. **Stage 02 ADAPT 967 ms latency outlier**: Profile and eliminate any synchronous/blocking I/O or inter-stage timing artifacts on the async path in `aegis/main.py`, `aegis/healing.py`, `target/main.py` (move XML/JSON parsing to `run_in_executor`), and `frontend-defense/src/hooks/useDefenseWS.js`.
2. **0 ms attacker-side stage timings**: Use `time.perf_counter_ns()` around the full request/response cycle in `attacker/jadepuffer.py` with sub-millisecond decimal precision (`(t1 - t0) / 1_000_000`), and ensure `useAttackerWS.js` + `KillChain.jsx` preserve truthy decimal values (`!== undefined && !== null`).
3. **LATERAL block depends on an AEGIS-confirmed action**: Make Stage 4 (LATERAL) interception depend on an explicit AEGIS token-bucket rate-limit / drop event confirmed via Redis & AEGIS `/api/aegis/blocklist` or `/api/aegis/lateral-status`, rather than an unhandled closed attacker socket.

### Files to Modify / Add
- `attacker/jadepuffer.py` — Replace `time.perf_counter()` with `time.perf_counter_ns()`, wrap full stage request/response lifecycle, verify LATERAL block against AEGIS token-bucket drop confirmation (`ratelimit` / `quarantine` action event).
- `aegis/response.py` — Add token-bucket drop tracking (`aegis:lateral_drop:{source_ip}`) and expose confirmation.
- `aegis/main.py` — Ensure `listen_redis_alerts` records token-bucket drop event and exposes `/api/aegis/lateral-status/{ip}`; ensure non-blocking SQLite/Redis operations on the Stage 2 path.
- `target/main.py` — Offload `ET.fromstring` XML parsing in `/api/flow/execute` to `loop.run_in_executor` and enforce mid-stream token-bucket drop check in `handle_tcp_connection`.
- `frontend-attacker/src/hooks/useAttackerWS.js` — Fix `if (data.detail?.elapsed_ms)` truthiness bug (`!== undefined`).
- `frontend-defense/src/hooks/useDefenseWS.js` — Use `verdict.verdict_ms` directly for stage interception timing without inter-stage sleep pollution.

---

## Phase 2: Feature 1 — Repository AI-Attack Proneness Scanner ("RepoScan")

### Goals
Static-analysis-only scanner that clones a public GitHub repo (or scans a local fixture path for tests) with strict sandboxing, evaluates it using a 3-Analyst Council (`CI/CD & Agent-Workflow Analyst` ×1.5, `Supply-Chain Analyst` ×1.0, `AI-Surface Analyst` ×1.5), maps findings to OWASP Top 10 for Agentic Applications (2026) `ASI01–ASI10` + real incident references, generates deterministic explanations (plus optional LLM summary), and calculates concrete improvements with projected score reductions.

### Files to Add / Modify
- `docker-compose.yml` — Add `reposcan` service on isolated network (`reposcan_net`) connected only to `aegis` (no access to Redis secrets or attacker/target network).
- `reposcan/Dockerfile` & `reposcan/requirements.txt` — Python 3.11 + FastAPI + PyYAML + httpx + aiosqlite + pydantic.
- `reposcan/models.py` — Pydantic models: `Finding`, `CheckResult`, `AnalystBreakdown`, `ImprovementFix`, `RepoScanRequest`, `RepoScanReport`, `CompareReport`.
- `reposcan/cloner.py` — Safe git cloner (`git clone --depth 1 --no-tags --single-branch`, `GIT_TERMINAL_PROMPT=0`, `-c core.hooksPath=/dev/null`, 120s timeout, 200 MB repo limit, 2 MB file limit, binary skip, no external symlinks, URL validation `^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$`).
- `reposcan/data/popular_packages.json` — Top npm and PyPI packages list for Levenshtein typosquatting detection (B3).
- `reposcan/registry.py` — Async npm / PyPI registry existence checker (B2 slopsquatting) and OSV.dev batch vulnerability checker (`https://api.osv.dev/v1/querybatch`, B4) with SQLite `registry_cache`.
- `reposcan/checks/base.py` — Base `RepoCheck` plug-in class (`id`, `analyst`, `severity`, `asi_ids`, `incident_ref`, `run(repo_ctx) -> list[Finding]`).
- `reposcan/checks/cicd_checks.py` — Checks `A1` through `A8` using `yaml.safe_load`:
  - `A1` (critical): `pull_request_target` / `workflow_run` checking out PR head and running code.
  - `A2` (critical): AI agent action (`claude-code-action`, `gemini-cli`, `copilot`, LLM CLI) triggered by `issues`/`issue_comment`/`pull_request_target`/`discussion` with shell/write/edit allowed.
  - `A3` (high): Untrusted `${{ github.event.* }}` interpolated into `run:` or `prompt`.
  - `A4` (high): AI action allowing any user (`allowed_non_write_users: "*"`).
  - `A5` (high): Missing top-level `permissions:` or `permissions: write-all`.
  - `A6` (medium): Third-party actions not pinned to a 40-char commit SHA.
  - `A7` (medium): Low-privilege and release workflows sharing `actions/cache` keys.
  - `A8` (medium): Publishing secrets (`NPM_TOKEN`, `PYPI_*`, `VSCE_PAT`, AWS keys) at workflow/job level.
- `reposcan/checks/supply_chain_checks.py` — Checks `B1` through `B6`:
  - `B1` (high): `preinstall`/`install`/`postinstall` in `package.json` or custom install in `setup.py`.
  - `B2` (high): Slopsquatting — non-existent package on npm/PyPI.
  - `B3` (medium): Typosquatting — Levenshtein distance ≤ 2 from popular package.
  - `B4` (medium/high): Known vulnerable dependencies via OSV.dev API.
  - `B5` (medium): Missing lockfile or unpinned version ranges.
  - `B6` (low): Missing Dependabot/Renovate config and `SECURITY.md`.
- `reposcan/checks/ai_surface_checks.py` — Checks `C1` through `C9`:
  - `C1` (critical): Hidden Unicode (zero-width, bidi overrides `U+202A–U+202E`, `U+2066–U+2069`, Unicode tags `U+E0000–U+E007F`) in instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.github/copilot-instructions.md`).
  - `C2` (high): Instruction files directing shell execution, remote URL fetch, confirmation bypass, reading `~/.ssh`/`.env`, or "ignore previous instructions".
  - `C3` (high): MCP configs (`.mcp.json`, `mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`) with unpinned `npx`/`uvx`, auto-approve, broad filesystem roots, or inline secrets.
  - `C4` (high): LLM output passed to `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`, `child_process.exec`, raw SQL, or unvalidated file writes (Python `ast` + JS/TS parser).
  - `C5` (medium): User input concatenated into system prompts without delimiter/role separation.
  - `C6` (medium): Agent tools exposing shell/filesystem/network without allow-list or human confirmation.
  - `C7` (medium): RAG/memory stores ingesting external content without sanitization.
  - `C8` (critical): Hard-coded AI/cloud credentials (`sk-`, `sk-ant-`, `AIza`, `ghp_`, `AKIA`) or committed `.env` files (masked prefix only).
  - `C9` (low): AI app repository with no prompt-injection tests/evals.
- `reposcan/analysts/cicd_analyst.py`, `reposcan/analysts/supply_chain_analyst.py`, `reposcan/analysts/ai_surface_analyst.py` — Analyst classes computing `1 - Π(1 - severity * confidence)`.
- `reposcan/scorer.py` — Computes weighted average across the 3 analysts (`weights: 1.5, 1.0, 1.5`), applies the critical floor (`≥ 70%` if any `critical` finding), formats the arithmetic string, coverage %, and risk band (`Low < 30`, `Moderate 30–59`, `High 60–79`, `Critical ≥ 80`).
- `reposcan/explainer.py` — Deterministic template explainer + optional `REPOSCAN_LLM=1` explainer that receives only structured JSON findings.
- `reposcan/improvements.py` — Concrete fix generator with snippets/diffs, single-fix re-scoring, sorting by largest score reduction, and "Apply all high-impact fixes" projection.
- `reposcan/report_export.py` — Markdown (`report.md`) and PDF (`report.pdf`) generator.
- `reposcan/storage.py` — SQLite tables (`scans`, `findings`, `registry_cache`) with commit SHA caching.
- `reposcan/main.py` — FastAPI microservice for RepoScan.
- `aegis/main.py` — Proxy `/api/reposcan` endpoints, stream `reposcan.progress`, `reposcan.finding`, `reposcan.done` over `/ws/defense`, store RepoScan findings into `HealingEngine`, and trigger "Simulate against AEGIS" runs against the toy target.
- `frontend-defense/src/components/RepoScanTab.jsx` — New "Repo Scan" tab in Defense Console (URL input, proneness %, risk band, 3 analyst bars + arithmetic, OWASP ASI01–ASI10 heat-row, expandable findings list, improvements list with before/after gauge, Compare mode, and "Simulate against AEGIS" button).
- `tests/fixtures/vulnerable_repo/` & `tests/fixtures/clean_repo/` — Test fixtures scoring `≥ 80%` and `< 20%`.
- `tests/test_reposcan.py` — Unit tests for all checks, hand-verified scorer arithmetic test, and subprocess safety test.

---

## Phase 3: Feature 2 — Evaluation Harness (`eval/harness.py`)

### Goals
Comprehensive reproducible evaluation harness running against the live pipeline or direct simulation harness:
- **N = 30 trials per condition**: AEGIS disabled vs AEGIS enabled with fixed seed list.
- Records attack success rate, time to complete kill chain, per-stage detection latency, end-to-end detection-to-action latency, and self-healing delta (mean ± sd).
- **Benign-traffic replay**: realistic logins, CRUD calls, normal JSON/XML, legitimate bursts; computes false-positive rate, precision, recall, and F1.
- **Threshold sweep**: sweeps Council threshold from `0.20` to `0.80` and plots detection rate vs false-positive rate.
- **Analyst ablation**: drops each analyst in turn and compares AI-Behaviour weight `1.0` vs `1.5`.
- Outputs CSVs and matplotlib charts to `eval/results/`.

### Files to Add / Modify
- `eval/harness.py` — Main evaluation runner + CSV and chart generator.
- `aegis/council.py` & `aegis/main.py` — Support dynamic threshold/weight/ablation config via `/api/aegis/config` for the evaluation harness.

---

## Phase 4: Feature 4 — New Attacker Stages for Recent AI-Based Attacks

### Goals
Add 4 optional synthetic AI-attack stages to JadePuffer-sim (stages 6–9) and corresponding AEGIS detection & interception:
- **Stage 6 (`MCP_POISON` — MCP Tool Poisoning)**: Fake MCP tool metadata with hidden instructions/Unicode sent to `/api/mcp/register`; AEGIS detects and quarantines the tool.
- **Stage 7 (`RAG_INJECT` — Indirect Prompt Injection via Documents)**: Toy RAG endpoint `/api/rag/ingest` receives document with hidden instructions; AEGIS sanitizes and flags it.
- **Stage 8 (`SLOPSQUAT` — Slopsquat Install Attempt)**: Attacker attempts package fetch via `/api/packages/install` with hallucinated package name; AEGIS blocks egress to unknown packages.
- **Stage 9 (`CRED_HARVEST` — Credential Harvest of AI Tool Configs)**: Attacker probes `~/.claude`, `~/.gemini`, `.env` via `/api/fs/read`; AEGIS denies via path ACL (*resembles s1ngularity, Aug 2025*).

### Files to Modify
- `target/main.py` — Add toy endpoints `/api/mcp/register`, `/api/rag/ingest`, `/api/packages/install`, `/api/fs/read`.
- `attacker/jadepuffer.py` & `attacker/config.py` — Add optional stages 6–9 (`_stage_mcp_poison`, `_stage_rag_inject`, `_stage_slopsquat`, `_stage_cred_harvest`).
- `aegis/surveillance.py`, `aegis/council.py`, `aegis/main.py` — Detect and intercept stages 6–9 (path ACL, hidden Unicode in tool metadata, RAG sanitizer, unknown package egress block).
- `frontend-attacker/src/components/AttackConfig.jsx` & `KillChain.jsx` — Support selecting and visualizing the optional AI stages.
- `frontend-defense/src/components/KillChainMap.jsx` & `useDefenseWS.js` — Display optional stages when active or triggered via "Simulate against AEGIS".

---

## Phase 5: Feature 5 — Smaller Improvements

### Goals
1. **Pluggable Heuristic Guardrail (rule-based)**: `aegis/guardrail.py` with `GuardrailClassifier` interface — fast regex path + deterministic weighted-token **heuristic guardrail (rule-based)** used by `AIBehaviorAnalyst` (a learned model can be plugged into the same interface later).
2. **Human Escalation**: Grey-zone (`0.35 <= score < 0.55`) and high-impact verdicts queued in `aegis/escalation.py` for one-click analyst approval/denial in the Defense Console (`/api/aegis/escalations`), with default `provisional_block` while pending and configurable timeout auto-action.
3. **MITRE ATLAS + OWASP ASI Tags**: Attach `atlas_id` and `asi_id` tags to every `DefenseEvent` and render badges in the Defense Console `CouncilPanel`, `DetectionLog`, and `KillChainMap`.
4. **Incident Report Export (Markdown/PDF)**: `GET /api/aegis/incident/{run_id}.md` and `.pdf` (also accessible via `[E] export` in StatusBar) containing timeline, Council scores, actions taken, and signatures learned.

### Files to Add / Modify
- `aegis/guardrail.py` — Pluggable heuristic guardrail (rule-based).
- `aegis/escalation.py` — Human escalation queue manager with timeout default.
- `aegis/incident_report.py` — Markdown and PDF incident report generator.
- `aegis/models.py` & `aegis/main.py` — Add `atlas_tags`, `asi_tags`, escalation endpoints, and incident report export endpoints.
- `frontend-defense/src/components/StatusBar.jsx`, `DetectionLog.jsx`, `EscalationBanner.jsx` — Render ATLAS/ASI tags, escalation approval UI, and `[E]` incident export download.
- `README.md` — Document RepoScan, scoring formula, OWASP ASI check table, safety rules, new stages, and evaluation harness.
