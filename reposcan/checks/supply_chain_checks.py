"""
reposcan/checks/supply_chain_checks.py — Supply-Chain Analyst checks (B1–B6).
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

from checks.base import RepoCheck, find_line_number
from cloner import RepoContext
from models import Finding
from registry import RegistryClient, find_typosquat_match


LOCKFILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
}

REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*(?:([=<>!~]+)\s*([A-Za-z0-9_.*+-]+))?")


def extract_npm_dependencies(repo_ctx: RepoContext) -> List[Tuple[str, str, str, int]]:
    """Return list of `(file_path, pkg_name, version_spec, line_number)` from package.json files."""
    deps: List[Tuple[str, str, str, int]] = []
    for path, content in repo_ctx.files.items():
        if path.endswith("package.json"):
            try:
                data = json.loads(content)
            except Exception:
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                sec_dict = data.get(section)
                if isinstance(sec_dict, dict):
                    for pkg, ver in sec_dict.items():
                        line = find_line_number(content, f'"{pkg}"')
                        deps.append((path, str(pkg), str(ver), line))
    return deps


def extract_pypi_dependencies(repo_ctx: RepoContext) -> List[Tuple[str, str, str, int]]:
    """Return list of `(file_path, pkg_name, version_spec, line_number)` from requirements*.txt."""
    deps: List[Tuple[str, str, str, int]] = []
    for path, content in repo_ctx.files.items():
        fname = path.rsplit("/", 1)[-1]
        if fname.startswith("requirements") and fname.endswith(".txt"):
            for idx, raw_line in enumerate(content.splitlines(), start=1):
                line = raw_line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                # Strip extras like redis[asyncio]
                base_line = re.sub(r"\[[^\]]+\]", "", line)
                m = REQ_LINE_RE.match(base_line)
                if m:
                    pkg = m.group(1)
                    op = m.group(2) or ""
                    ver = m.group(3) or ""
                    deps.append((path, pkg, f"{op}{ver}", idx))
    return deps


class CheckB1InstallScripts(RepoCheck):
    id = "B1"
    analyst = "supply_chain"
    title = "Lifecycle install hooks (`preinstall`/`install`/`postinstall` or custom `setup.py` install)"
    severity = "high"
    asi_ids = ["ASI04", "ASI05"]
    incident_ref = "Shai-Hulud worm (Sep 2025), cline@2.3.0 (Feb 2026)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            if path.endswith("package.json"):
                try:
                    data = json.loads(content)
                except Exception:
                    continue
                scripts = data.get("scripts")
                if isinstance(scripts, dict):
                    for hook in ("preinstall", "install", "postinstall"):
                        if hook in scripts and str(scripts[hook]).strip():
                            cmd = str(scripts[hook]).strip()
                            line = find_line_number(content, f'"{hook}"')
                            findings.append(
                                self.make_finding(
                                    file=path,
                                    line=line,
                                    evidence=f'"{hook}": "{cmd}"',
                                    why_it_matters=(
                                        f"`{hook}` lifecycle scripts execute arbitrary shell commands automatically "
                                        "during `npm install`, enabling credential harvesting and worm propagation."
                                    ),
                                )
                            )
            elif path.endswith("setup.py"):
                if "cmdclass" in content and ("install" in content or "develop" in content):
                    line = find_line_number(content, "cmdclass")
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence="cmdclass={... custom install command ...}",
                            why_it_matters=(
                                "Custom `cmdclass` install hooks in `setup.py` execute arbitrary Python code "
                                "at package installation time."
                            ),
                        )
                    )
        return findings


class CheckB2Slopsquatting(RepoCheck):
    id = "B2"
    analyst = "supply_chain"
    title = "Slopsquatting risk: declared dependency does not exist on npm or PyPI"
    severity = "high"
    asi_ids = ["ASI04", "ASI08"]
    incident_ref = "AI-hallucinated package slopsquatting campaigns (2025–2026)"

    def __init__(self, registry_client: Optional[RegistryClient] = None):
        self.registry = registry_client or RegistryClient()

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, pkg, ver, line in extract_npm_dependencies(repo_ctx):
            if not self.registry.check_package_exists("npm", pkg):
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f'"{pkg}": "{ver}" (404 Not Found on registry.npmjs.org)',
                        why_it_matters=(
                            f"Package `{pkg}` is not registered on npm. Attackers monitor AI-hallucinated package "
                            "names and register them with malicious payloads ('slopsquatting')."
                        ),
                    )
                )
        for path, pkg, ver, line in extract_pypi_dependencies(repo_ctx):
            if not self.registry.check_package_exists("pypi", pkg):
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f"{pkg}{ver} (404 Not Found on pypi.org)",
                        why_it_matters=(
                            f"Package `{pkg}` does not exist on PyPI. An attacker can claim this hallucinated "
                            "package name to compromise developer or CI environments."
                        ),
                    )
                )
        return findings


class CheckB3Typosquatting(RepoCheck):
    id = "B3"
    analyst = "supply_chain"
    title = "Suspected typosquat dependency (Levenshtein distance ≤ 2 from popular package)"
    severity = "medium"
    asi_ids = ["ASI04"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, pkg, ver, line in extract_npm_dependencies(repo_ctx):
            match = find_typosquat_match("npm", pkg)
            if match:
                pop_pkg, dist = match
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f'"{pkg}": "{ver}" (edit distance {dist} from "{pop_pkg}")',
                        why_it_matters=(
                            f"`{pkg}` is within Levenshtein distance {dist} of popular npm package `{pop_pkg}`, "
                            "a common indicator of typosquatting."
                        ),
                    )
                )
        for path, pkg, ver, line in extract_pypi_dependencies(repo_ctx):
            match = find_typosquat_match("pypi", pkg)
            if match:
                pop_pkg, dist = match
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f'{pkg}{ver} (edit distance {dist} from "{pop_pkg}")',
                        why_it_matters=(
                            f"`{pkg}` is within Levenshtein distance {dist} of popular PyPI package `{pop_pkg}`, "
                            "a common indicator of typosquatting."
                        ),
                    )
                )
        return findings


class CheckB4VulnerableDependencies(RepoCheck):
    id = "B4"
    analyst = "supply_chain"
    title = "Known-vulnerable dependency version detected via OSV.dev"
    severity = "high"
    asi_ids = ["ASI04"]
    incident_ref = None

    def __init__(self, registry_client: Optional[RegistryClient] = None):
        self.registry = registry_client or RegistryClient()

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        queries: List[Dict[str, str]] = []
        loc_map: Dict[Tuple[str, str, str], Tuple[str, int]] = {}

        for path, pkg, ver, line in extract_npm_dependencies(repo_ctx):
            clean_ver = ver.lstrip("^~>=< ")
            if clean_ver and clean_ver[0].isdigit():
                queries.append({"ecosystem": "npm", "name": pkg, "version": clean_ver})
                loc_map[("npm", pkg.lower(), clean_ver)] = (path, line)

        for path, pkg, ver, line in extract_pypi_dependencies(repo_ctx):
            clean_ver = ver.lstrip("=<>!~ ")
            if clean_ver and clean_ver[0].isdigit():
                queries.append({"ecosystem": "PyPI", "name": pkg, "version": clean_ver})
                loc_map[("pypi", pkg.lower(), clean_ver)] = (path, line)

        vulns = self.registry.query_osv_batch(queries)
        findings: List[Finding] = []
        for v in vulns:
            eco = v["ecosystem"].lower()
            name = v["name"]
            ver = v["version"]
            path, line = loc_map.get((eco, name.lower(), ver), ("requirements.txt", 1))
            sev = "high" if float(v.get("cvss", 7.5)) >= 7.0 else "medium"
            findings.append(
                self.make_finding(
                    file=path,
                    line=line,
                    evidence=f"{name}@{ver} -> {v['id']} ({v['summary']}, CVSS {v.get('cvss', 7.5)})",
                    why_it_matters=(
                        f"Dependency `{name}` version `{ver}` has a known advisory `{v['id']}` reported by OSV.dev."
                    ),
                    severity_override=sev,
                )
            )
        return findings


class CheckB5MissingLockfileOrUnpinned(RepoCheck):
    id = "B5"
    analyst = "supply_chain"
    title = "Missing dependency lockfile or unpinned dependency version ranges"
    severity = "medium"
    asi_ids = ["ASI04"]
    incident_ref = "Shai-Hulud worm / cline@2.3.0"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        has_manifest = any(
            p.endswith("package.json") or p.endswith("requirements.txt") or p.endswith("pyproject.toml")
            for p in repo_ctx.files
        )
        has_lockfile = any(p.rsplit("/", 1)[-1] in LOCKFILES for p in repo_ctx.files)

        if has_manifest and not has_lockfile:
            manifest_file = next(
                (p for p in repo_ctx.files if p.endswith("package.json") or p.endswith("requirements.txt") or p.endswith("pyproject.toml")),
                "package.json",
            )
            findings.append(
                self.make_finding(
                    file=manifest_file,
                    line=1,
                    evidence=f"No lockfile ({', '.join(sorted(LOCKFILES))}) found in repository",
                    why_it_matters=(
                        "Without a committed lockfile, installs resolve the latest transitive versions at build time, "
                        "exposing CI and developers to newly published malicious releases."
                    ),
                )
            )

        for path, pkg, ver, line in extract_npm_dependencies(repo_ctx):
            if ver.strip() in ("*", "latest") or ver.strip().startswith("^") or ver.strip().startswith("~"):
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f'"{pkg}": "{ver}"',
                        why_it_matters="Unpinned npm version range allows automatic upgrades to potentially compromised minor/patch releases.",
                    )
                )
                break

        for path, pkg, ver, line in extract_pypi_dependencies(repo_ctx):
            if not ver or ver.startswith(">=") or ver == "*":
                findings.append(
                    self.make_finding(
                        file=path,
                        line=line,
                        evidence=f"{pkg}{ver}",
                        why_it_matters="Unpinned Python dependency specification allows floating installs without hash or version pinning.",
                    )
                )
                break

        return findings


class CheckB6MissingDependabotAndSecurityMd(RepoCheck):
    id = "B6"
    analyst = "supply_chain"
    title = "Missing automated dependency update config (Dependabot/Renovate) and `SECURITY.md`"
    severity = "low"
    asi_ids = ["ASI04"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        file_set = {p.lower() for p in repo_ctx.files.keys()}
        has_updater = any(
            p in file_set
            for p in (
                ".github/dependabot.yml",
                ".github/dependabot.yaml",
                "renovate.json",
                ".github/renovate.json",
            )
        )
        has_security_md = any(p.endswith("security.md") for p in file_set)
        if not has_updater and not has_security_md:
            return [
                self.make_finding(
                    file="README.md" if "readme.md" in file_set else ".",
                    line=1,
                    evidence="Neither `.github/dependabot.yml` / `renovate.json` nor `SECURITY.md` present",
                    why_it_matters=(
                        "Lack of automated dependency hygiene and a vulnerability disclosure policy delays "
                        "remediation when upstream dependencies are compromised."
                    ),
                )
            ]
        return []


def build_supply_chain_checks(registry_client: Optional[RegistryClient] = None) -> List[RepoCheck]:
    reg = registry_client or RegistryClient()
    return [
        CheckB1InstallScripts(),
        CheckB2Slopsquatting(reg),
        CheckB3Typosquatting(),
        CheckB4VulnerableDependencies(reg),
        CheckB5MissingLockfileOrUnpinned(),
        CheckB6MissingDependabotAndSecurityMd(),
    ]
