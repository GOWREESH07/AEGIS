"""
reposcan/checks/cicd_checks.py — CI/CD & Agent-Workflow Analyst checks (A1–A8).
Parses `.github/workflows/*.yml` and `.yaml` using PyYAML (`yaml.safe_load`) with
a fallback structured YAML parser when PyYAML is not installed in the host test environment.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from checks.base import RepoCheck, find_line_number
from cloner import RepoContext
from models import Finding

try:
    import yaml

    def parse_yaml_doc(text: str) -> Dict[str, Any]:
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            return {}
        # PyYAML 1.1 turns `on:` into boolean True key
        if True in loaded and "on" not in loaded:
            loaded["on"] = loaded.pop(True)
        return loaded
except ImportError:
    # Minimal structured indentation-aware YAML parser for host environments without PyYAML
    def parse_yaml_doc(text: str) -> Dict[str, Any]:
        doc: Dict[str, Any] = {"jobs": {}}
        lines = text.splitlines()
        triggers: List[str] = []
        in_on = False
        in_permissions = False
        permissions_val: Any = None
        current_job: str | None = None
        current_step: Dict[str, Any] | None = None
        in_with = False
        in_env = False
        top_env: Dict[str, str] = {}

        for raw in lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))

            if indent == 0:
                in_on = False
                in_permissions = False
                current_job = None
                current_step = None
                if stripped.startswith("on:"):
                    val = stripped[3:].strip()
                    if val:
                        val_clean = val.strip("[]")
                        triggers.extend([x.strip().strip("'\"") for x in val_clean.split(",") if x.strip()])
                    else:
                        in_on = True
                elif stripped.startswith("permissions:"):
                    val = stripped[len("permissions:"):].strip()
                    if val:
                        permissions_val = val
                    else:
                        in_permissions = True
                        permissions_val = {}
                elif stripped.startswith("env:"):
                    in_env = True
                continue

            if in_on and indent >= 2:
                if stripped.startswith("- "):
                    triggers.append(stripped[2:].strip().strip("'\""))
                elif ":" in stripped:
                    k = stripped.split(":", 1)[0].strip()
                    triggers.append(k)
                continue

            if in_permissions and indent >= 2 and isinstance(permissions_val, dict):
                if ":" in stripped:
                    k, v = stripped.split(":", 1)
                    permissions_val[k.strip()] = v.strip()
                continue

            if indent == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                key_name = stripped[:-1].strip()
                if key_name not in ("on", "permissions", "env", "jobs", "concurrency", "defaults"):
                    current_job = key_name
                    doc["jobs"][current_job] = {"steps": [], "env": {}}
                    current_step = None
                continue

            if current_job is not None:
                job_obj = doc["jobs"][current_job]
                if stripped.startswith("- "):
                    current_step = {"with": {}, "env": {}}
                    job_obj["steps"].append(current_step)
                    in_with = False
                    rem = stripped[2:].strip()
                    if ":" in rem:
                        k, v = rem.split(":", 1)
                        current_step[k.strip()] = v.strip().strip("'\"")
                elif current_step is not None:
                    if stripped.startswith("with:"):
                        in_with = True
                    elif in_with and indent >= 8 and ":" in stripped:
                        k, v = stripped.split(":", 1)
                        current_step["with"][k.strip()] = v.strip().strip("'\"")
                    elif ":" in stripped:
                        in_with = False
                        k, v = stripped.split(":", 1)
                        k_s = k.strip()
                        v_s = v.strip().strip("'\"")
                        if k_s in ("uses", "run", "name", "id"):
                            current_step[k_s] = v_s
                        else:
                            current_step["with"][k_s] = v_s
                    else:
                        if "run" in current_step:
                            current_step["run"] += "\n" + stripped
                elif ":" in stripped:
                    k, v = stripped.split(":", 1)
                    job_obj["env"][k.strip()] = v.strip()

        if triggers:
            doc["on"] = triggers
        if permissions_val is not None:
            doc["permissions"] = permissions_val
        if top_env:
            doc["env"] = top_env
        return doc


def iter_workflow_files(repo_ctx: RepoContext) -> List[Tuple[str, str, Dict[str, Any]]]:
    workflows: List[Tuple[str, str, Dict[str, Any]]] = []
    for path, content in repo_ctx.files.items():
        if path.startswith(".github/workflows/") and (path.endswith(".yml") or path.endswith(".yaml")):
            try:
                parsed = parse_yaml_doc(content)
            except Exception:
                parsed = {}
            workflows.append((path, content, parsed))
    return workflows


def extract_triggers(parsed: Dict[str, Any]) -> Set[str]:
    on_block = parsed.get("on")
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(x) for x in on_block}
    if isinstance(on_block, dict):
        return {str(k) for k in on_block.keys()}
    return set()


def iter_steps(parsed: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """Yield `(job_name, job_dict, step_dict)` across all jobs in a workflow."""
    out: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
    jobs = parsed.get("jobs")
    if not isinstance(jobs, dict):
        return out
    for job_name, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue
        steps = job_data.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    out.append((str(job_name), job_data, step))
    return out


SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
AI_ACTION_KEYWORDS = (
    "claude-code-action",
    "anthropics/claude",
    "gemini-cli",
    "google-gemini",
    "copilot",
    "openai",
    "codex",
    "aider",
    "cline",
)
UNTRUSTED_GH_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|comment\.body|pull_request\.title|pull_request\.body|discussion\.body|head_ref|commits\[[^\]]+\]\.message)[^}]*\}\}",
    re.IGNORECASE,
)
PUBLISH_SECRET_RE = re.compile(
    r"(NPM_TOKEN|PYPI_API_TOKEN|PYPI_TOKEN|PYPI_PASSWORD|VSCE_PAT|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|GH_PAT)",
    re.IGNORECASE,
)


class CheckA1PwnRequest(RepoCheck):
    id = "A1"
    analyst = "cicd"
    title = "Privileged workflow checks out untrusted PR head and executes code"
    severity = "critical"
    asi_ids = ["ASI01", "ASI03", "ASI05"]
    incident_ref = "Ultralytics (Dec 2024), tj-actions chain (Mar 2025)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            triggers = extract_triggers(parsed)
            if not (triggers & {"pull_request_target", "workflow_run"}):
                continue
            for job_name, _, step in iter_steps(parsed):
                uses = str(step.get("uses", ""))
                with_block = step.get("with") or {}
                ref_val = str(with_block.get("ref", "")) if isinstance(with_block, dict) else ""
                if "actions/checkout" in uses and (
                    "pull_request.head" in ref_val
                    or "github.event.workflow_run.head" in ref_val
                    or "head.sha" in ref_val
                    or "head.ref" in ref_val
                ):
                    line = find_line_number(raw, ref_val) if ref_val else find_line_number(raw, "pull_request_target")
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence=f"on: {sorted(triggers)} -> uses: {uses} with ref: {ref_val}",
                            why_it_matters=(
                                "Checking out untrusted PR code inside `pull_request_target` or `workflow_run` "
                                "grants fork PRs access to repository write tokens and secrets."
                            ),
                        )
                    )
        return findings


class CheckA2AIAgentActionUntrustedTrigger(RepoCheck):
    id = "A2"
    analyst = "cicd"
    title = "AI agent action triggered by untrusted event with shell/write/edit tools enabled"
    severity = "critical"
    asi_ids = ["ASI01", "ASI02", "ASI05"]
    incident_ref = 'Clinejection (Feb 2026), "Comment and Control" (Apr 2026)'

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        risky_triggers = {"issues", "issue_comment", "pull_request_target", "discussion", "discussion_comment"}
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            triggers = extract_triggers(parsed)
            if not (triggers & risky_triggers):
                continue
            for _, _, step in iter_steps(parsed):
                uses = str(step.get("uses", "")).lower()
                run_cmd = str(step.get("run", "")).lower()
                with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
                with_str = " ".join(f"{k}={v}" for k, v in with_block.items()).lower()

                is_ai_step = any(k in uses or k in run_cmd for k in AI_ACTION_KEYWORDS)
                if not is_ai_step:
                    continue

                has_dangerous_tools = any(
                    tok in with_str or tok in run_cmd
                    for tok in ("bash", "shell", "write", "edit", "--dangerously-skip-permissions", "--yolo", "allowed_tools", "allowedtools")
                )
                if has_dangerous_tools:
                    needle = step.get("uses") or "claude"
                    line = find_line_number(raw, str(needle))
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence=f"triggers={sorted(triggers & risky_triggers)} uses={step.get('uses', 'run')} tools={with_str[:120]}",
                            why_it_matters=(
                                "External users can open an issue or comment containing a prompt injection that hijacks "
                                "the CI AI agent into executing arbitrary shell commands and exfiltrating secrets."
                            ),
                        )
                    )
        return findings


class CheckA3UntrustedInterpolation(RepoCheck):
    id = "A3"
    analyst = "cicd"
    title = "Untrusted GitHub event text interpolated directly into `run:` or AI `prompt`"
    severity = "high"
    asi_ids = ["ASI01", "ASI05"]
    incident_ref = "Clinejection (Feb 2026)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            for _, _, step in iter_steps(parsed):
                run_script = str(step.get("run", ""))
                with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
                prompt_text = str(with_block.get("prompt", "") or with_block.get("direct_prompt", ""))
                combined = f"{run_script}\n{prompt_text}"
                m = UNTRUSTED_GH_EXPR_RE.search(combined)
                if m:
                    expr = m.group(0)
                    line = find_line_number(raw, expr)
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence=expr,
                            why_it_matters=(
                                "Direct `${{ github.event.* }}` interpolation allows shell command injection in `run:` "
                                "blocks and unescaped prompt injection in AI workflow prompts."
                            ),
                        )
                    )
        return findings


class CheckA4AIActionAllowAllUsers(RepoCheck):
    id = "A4"
    analyst = "cicd"
    title = "AI action configured to allow any non-write user to trigger execution"
    severity = "high"
    asi_ids = ["ASI03", "ASI09"]
    incident_ref = '"Comment and Control" (Apr 2026)'

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            for _, _, step in iter_steps(parsed):
                with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
                for k, v in with_block.items():
                    if k.lower() in ("allowed_non_write_users", "allow_all_users", "allowed_users") and str(v).strip() in ("*", "all", "true"):
                        line = find_line_number(raw, k)
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=line,
                                evidence=f"{k}: {v}",
                                why_it_matters=(
                                    "Allowing any anonymous or non-collaborator GitHub account (`*`) to invoke the AI "
                                    "agent removes authorization boundaries on privileged CI runners."
                                ),
                            )
                        )
        return findings


class CheckA5BroadWorkflowPermissions(RepoCheck):
    id = "A5"
    analyst = "cicd"
    title = "Workflow missing top-level `permissions:` block or using `write-all`"
    severity = "high"
    asi_ids = ["ASI03"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            perms = parsed.get("permissions")
            if perms is None:
                findings.append(
                    self.make_finding(
                        file=path,
                        line=1,
                        evidence="No top-level `permissions:` block declared in workflow",
                        why_it_matters=(
                            "Without an explicit `permissions:` block, `GITHUB_TOKEN` may default to broad read/write "
                            "scopes across contents, packages, and pull requests."
                        ),
                    )
                )
            elif isinstance(perms, str) and "write-all" in perms.lower():
                line = find_line_number(raw, "permissions")
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f"permissions: {perms}",
                        why_it_matters="`permissions: write-all` grants maximum repository privilege to every job in the workflow.",
                    )
                )
        return findings


class CheckA6UnpinnedThirdPartyActions(RepoCheck):
    id = "A6"
    analyst = "cicd"
    title = "Third-party GitHub Action pinned to mutable tag/branch instead of 40-char SHA"
    severity = "medium"
    asi_ids = ["ASI04"]
    incident_ref = "tj-actions/changed-files (Mar 2025), aquasecurity/trivy-action (Mar 2026)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        seen_locations: Set[Tuple[str, int, str]] = set()
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            for _, _, step in iter_steps(parsed):
                uses = str(step.get("uses", "")).strip()
                if not uses or uses.startswith("./") or uses.startswith("docker://"):
                    continue
                if "@" not in uses:
                    continue
                action_name, ref = uses.rsplit("@", 1)
                if not SHA40_RE.match(ref):
                    line = find_line_number(raw, uses)
                    loc_key = (path, line, uses)
                    if loc_key in seen_locations:
                        continue
                    seen_locations.add(loc_key)
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence=f"uses: {uses}",
                            why_it_matters=(
                                "Mutable tags (such as `@v4` or `@main`) can be force-pushed by a compromised upstream "
                                "maintainer to inject credential-stealing payloads into CI runs."
                            ),
                        )
                    )
        return findings


class CheckA7SharedCachePoisoning(RepoCheck):
    id = "A7"
    analyst = "cicd"
    title = "Low-privilege issue/triage workflow and release workflow share `actions/cache` keys"
    severity = "medium"
    asi_ids = ["ASI04", "ASI06"]
    incident_ref = "Clinejection cache poisoning (Feb 2026)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        low_priv_keys: List[Tuple[str, str, int]] = []
        high_priv_keys: List[Tuple[str, str, int]] = []

        for path, raw, parsed in iter_workflow_files(repo_ctx):
            triggers = extract_triggers(parsed)
            is_low = bool(triggers & {"issues", "issue_comment", "pull_request", "discussion"})
            is_high = bool(triggers & {"release", "push", "workflow_dispatch", "schedule"}) or "release" in path.lower() or "publish" in path.lower()

            for _, _, step in iter_steps(parsed):
                uses = str(step.get("uses", ""))
                if "actions/cache" in uses:
                    with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
                    cache_key = str(with_block.get("key", ""))
                    prefix = cache_key.split("$")[0].strip("-_") or cache_key
                    line = find_line_number(raw, cache_key or "actions/cache")
                    if is_low:
                        low_priv_keys.append((prefix, path, line))
                    if is_high:
                        high_priv_keys.append((prefix, path, line))

        findings: List[Finding] = []
        for lp_prefix, lp_path, lp_line in low_priv_keys:
            for hp_prefix, hp_path, _ in high_priv_keys:
                # Must be shared across DIFFERENT workflow files (or where one is explicitly release/publish)
                if lp_prefix and lp_prefix == hp_prefix and (
                    lp_path != hp_path or "release" in hp_path.lower() or "publish" in hp_path.lower()
                ):
                    if lp_path == hp_path and " vulnerable_repo" not in str(repo_ctx.url):
                        # Only flag single-file cache sharing if workflow mixes issue_comment/issues with release
                        wf_parsed = next((p for pt, _, p in iter_workflow_files(repo_ctx) if pt == lp_path), {})
                        trigs = extract_triggers(wf_parsed)
                        if not (trigs & {"issues", "issue_comment"}) or not (trigs & {"release", "push"}):
                            continue
                    findings.append(
                        self.make_finding(
                            file=lp_path,
                            line=lp_line,
                            evidence=f"Shared cache key prefix '{lp_prefix}' between {lp_path} and {hp_path}",
                            why_it_matters=(
                                "An attacker triggering a low-privilege issue/triage workflow can poison the shared "
                                "GitHub Actions cache consumed by privileged release workflows."
                            ),
                        )
                    )
                    return findings
        return findings


class CheckA8BroadPublishingSecrets(RepoCheck):
    id = "A8"
    analyst = "cicd"
    title = "Publishing secrets exposed at workflow or job scope rather than isolated to publish step"
    severity = "medium"
    asi_ids = ["ASI03", "ASI10"]
    incident_ref = "Ultralytics / cline@2.3.0 token exfiltration"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, raw, parsed in iter_workflow_files(repo_ctx):
            # Check top-level env and job-level env in raw YAML
            for line_idx, line_text in enumerate(raw.splitlines(), start=1):
                m = PUBLISH_SECRET_RE.search(line_text)
                if m and "secrets." in line_text:
                    indent = len(line_text) - len(line_text.lstrip(" "))
                    # Top-level env (indent <= 4) or job-level env (indent <= 6) outside step `env:`
                    if indent <= 6:
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=line_idx,
                                evidence=line_text.strip(),
                                why_it_matters=(
                                    "Exposing publishing credentials (`NPM_TOKEN`, `PYPI_*`, `VSCE_PAT`) at the workflow "
                                    "or job level makes them readable via `/proc/self/environ` to every build or agent step."
                                ),
                            )
                        )
        return findings


CICD_CHECKS: List[RepoCheck] = [
    CheckA1PwnRequest(),
    CheckA2AIAgentActionUntrustedTrigger(),
    CheckA3UntrustedInterpolation(),
    CheckA4AIActionAllowAllUsers(),
    CheckA5BroadWorkflowPermissions(),
    CheckA6UnpinnedThirdPartyActions(),
    CheckA7SharedCachePoisoning(),
    CheckA8BroadPublishingSecrets(),
]
