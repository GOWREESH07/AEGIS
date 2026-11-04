"""
reposcan/checks/ai_surface_checks.py — AI-Surface Analyst checks (C1–C9).
"""
from __future__ import annotations

import ast
import json
import re
from typing import Dict, List, Set, Tuple

from checks.base import RepoCheck, find_line_number
from cloner import RepoContext
from models import Finding


INSTRUCTION_FILE_NAMES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
}

MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
}

# Zero-width characters, Bidi overrides (U+202A–U+202E, U+2066–U+2069), and Unicode tags (U+E0000–U+E007F)
ZERO_WIDTH_CODEPOINTS = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE
}


def is_hidden_unicode_char(ch: str) -> bool:
    cp = ord(ch)
    if cp in ZERO_WIDTH_CODEPOINTS:
        return True
    if 0x202A <= cp <= 0x202E:
        return True
    if 0x2066 <= cp <= 0x2069:
        return True
    if 0xE0000 <= cp <= 0xE007F:
        return True
    return False


def is_instruction_file(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if low in INSTRUCTION_FILE_NAMES or base in INSTRUCTION_FILE_NAMES:
        return True
    if low.startswith(".cursor/rules/") or "/.cursor/rules/" in low:
        return True
    return False


def is_mcp_config_file(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    return low in MCP_CONFIG_NAMES or base in (".mcp.json", "mcp.json")


class CheckC1HiddenUnicodeInRules(RepoCheck):
    id = "C1"
    analyst = "ai_surface"
    title = "Agent instruction file contains hidden Unicode (zero-width, bidi override, or tag characters)"
    severity = "critical"
    asi_ids = ["ASI01", "ASI06"]
    incident_ref = '"Rules File Backdoor" (Pillar Security, Mar 2025)'

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            if not is_instruction_file(path):
                continue
            for line_idx, line in enumerate(content.splitlines(), start=1):
                hidden_cps = [f"U+{ord(c):04X}" for c in line if is_hidden_unicode_char(c)]
                if hidden_cps:
                    visible_preview = "".join(c for c in line if not is_hidden_unicode_char(c)).strip()[:80]
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line_idx,
                            evidence=f"Hidden codepoints {hidden_cps[:5]} in line: {visible_preview!r}",
                            why_it_matters=(
                                "Invisible Unicode characters in `.cursorrules` / `CLAUDE.md` / `AGENTS.md` conceal "
                                "malicious prompt instructions from human code reviewers while being decoded by the LLM."
                            ),
                        )
                    )
                    break
        return findings


DANGEROUS_RULE_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "instruction_override", 0.95),
    (re.compile(r"(curl|wget)\s+https?://[^\s]+\s*\|\s*(ba)?sh", re.I), "remote_pipe_shell", 0.98),
    (re.compile(r"(read|cat|upload|exfiltrate|send)\s+.*(~\/\.ssh|~\/\.aws|~\/\.claude|~\/\.gemini|\.env|id_rsa)", re.I), "credential_access", 0.95),
    (re.compile(r"(disable|skip|bypass|never\s+ask)\s+.*(confirmation|approval|human|permission|safety)", re.I), "disable_confirmations", 0.85),
    (re.compile(r"(run|execute)\s+.*(shell\s+command|bash|terminal)\s+.*(silently|without\s+asking|automatically)", re.I), "silent_shell_exec", 0.90),
    (re.compile(r"fetch\s*\(\s*['\"]https?://", re.I), "remote_url_fetch", 0.80),
]


class CheckC2MaliciousInstructionDirectives(RepoCheck):
    id = "C2"
    analyst = "ai_surface"
    title = "Agent instruction file directs shell execution, credential access, remote fetch, or confirmation bypass"
    severity = "high"
    asi_ids = ["ASI01", "ASI02", "ASI09"]
    incident_ref = '"Rules File Backdoor" / s1ngularity credential harvest'

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            if not is_instruction_file(path):
                continue
            for line_idx, line in enumerate(content.splitlines(), start=1):
                for pat, label, conf in DANGEROUS_RULE_PATTERNS:
                    if pat.search(line):
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=line_idx,
                                evidence=f"[{label}] {line.strip()[:140]}",
                                why_it_matters=(
                                    "Malicious directives inside repository instruction files coerce coding agents "
                                    "into running commands, reading `~/.ssh` or `.env`, or bypassing user approval."
                                ),
                                confidence=conf,
                            )
                        )
                        break
        return findings


class CheckC3UnsafeMCPConfig(RepoCheck):
    id = "C3"
    analyst = "ai_surface"
    title = "Unsafe MCP server configuration (unpinned `npx`/`uvx`, auto-approve tools, broad root, or inline secret)"
    severity = "high"
    asi_ids = ["ASI02", "ASI04"]
    incident_ref = "MCP Tool Poisoning & Rug-Pull attacks (Invariant Labs, Apr 2025)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            if not is_mcp_config_file(path):
                continue
            try:
                data = json.loads(content)
            except Exception:
                continue
            servers = data.get("mcpServers") or data.get("servers") or {}
            if not isinstance(servers, dict):
                continue
            for srv_name, srv_cfg in servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                cmd = str(srv_cfg.get("command", ""))
                args = [str(a) for a in (srv_cfg.get("args") or [])]
                args_joined = " ".join(args)
                auto_approve = srv_cfg.get("autoApprove") or srv_cfg.get("alwaysAllow") or []
                env_block = srv_cfg.get("env") if isinstance(srv_cfg.get("env"), dict) else {}

                reasons: List[str] = []
                # 1. Unpinned npx / uvx package
                if cmd in ("npx", "uvx"):
                    pkg_args = [a for a in args if not a.startswith("-")]
                    for pa in pkg_args:
                        # Unpinned if no @version or @latest
                        if "@" not in pa.lstrip("@") or pa.endswith("@latest"):
                            reasons.append(f"unpinned `{cmd} {pa}`")
                # 2. Auto-approve tools
                if auto_approve:
                    reasons.append(f"autoApprove={auto_approve}")
                # 3. Broad filesystem root
                if any(a in ("/", "/Users", "/home", "/etc", "C:\\") for a in args):
                    reasons.append("broad filesystem root granted")
                # 4. Inline secrets in env
                for ek, ev in env_block.items():
                    ev_s = str(ev)
                    if any(k in ek.upper() for k in ("KEY", "TOKEN", "SECRET", "PASSWORD")) and not ev_s.startswith("$"):
                        masked = ev_s[:6] + "***" if len(ev_s) > 6 else "***"
                        reasons.append(f"inline secret {ek}={masked}")

                if reasons:
                    line = find_line_number(content, f'"{srv_name}"')
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=line,
                            evidence=f'mcpServers.{srv_name}: {", ".join(reasons)} ({cmd} {args_joined[:80]})',
                            why_it_matters=(
                                "Unpinned MCP servers with auto-approved tools or broad filesystem roots allow "
                                "upstream tool poisoning and silent host compromise without user confirmation."
                            ),
                        )
                    )
        return findings


LLM_VAR_RE = re.compile(
    r"(llm|response|completion|agent_output|model_output|ai_output|generated_code|tool_args|chat_result|gpt|claude)",
    re.I,
)


class CheckC4LLMOutputToDangerousSink(RepoCheck):
    id = "C4"
    analyst = "ai_surface"
    title = "LLM output passed directly to `eval`, `exec`, `subprocess(shell=True)`, `os.system`, or raw SQL"
    severity = "high"
    asi_ids = ["ASI05"]
    incident_ref = "OWASP ASI05 Insecure Code Execution"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            if path.endswith(".py"):
                findings.extend(self._scan_python_ast(path, content))
            elif path.endswith((".js", ".ts", ".jsx", ".tsx")):
                findings.extend(self._scan_js(path, content))
        return findings

    def _scan_python_ast(self, path: str, content: str) -> List[Finding]:
        out: List[Finding] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return out

        lines = content.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                base = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                # Only treat `builtins.eval`/`builtins.exec` or `os.system`/`subprocess.*` as dangerous sinks,
                # never arbitrary object methods like `self._sandbox.process.exec()`
                if base:
                    func_name = f"{base}.{node.func.attr}"
                elif node.func.attr == "execute":
                    func_name = "execute"

            lineno = getattr(node, "lineno", 1)
            src_line = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else func_name

            # Check eval / exec / os.system
            if func_name in ("eval", "exec", "builtins.eval", "builtins.exec", "os.system"):
                arg_str = ast.unparse(node) if hasattr(ast, "unparse") else src_line
                if LLM_VAR_RE.search(arg_str) or LLM_VAR_RE.search(src_line):
                    out.append(
                        self.make_finding(
                            file=path,
                            line=lineno,
                            evidence=src_line,
                            why_it_matters=(
                                f"Passing unvalidated LLM output into `{func_name}()` lets a prompt injection "
                                "achieve immediate arbitrary remote code execution (RCE)."
                            ),
                        )
                    )
            # Check subprocess.*(..., shell=True)
            elif func_name.startswith("subprocess."):
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if has_shell_true:
                    out.append(
                        self.make_finding(
                            file=path,
                            line=lineno,
                            evidence=src_line,
                            why_it_matters=(
                                "`subprocess` invoked with `shell=True` enables command injection when arguments "
                                "contain LLM-generated or user-controlled strings."
                            ),
                        )
                    )
            # Check raw SQL cursor.execute(f"SELECT ... {llm_response}")
            elif func_name.endswith(".execute") and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                    if LLM_VAR_RE.search(src_line) or "select " in src_line.lower() or "delete " in src_line.lower():
                        out.append(
                            self.make_finding(
                                file=path,
                                line=lineno,
                                evidence=src_line,
                                why_it_matters="Interpolating LLM or user strings into raw SQL `.execute()` enables SQL injection.",
                            )
                        )
        return out

    def _scan_js(self, path: str, content: str) -> List[Finding]:
        out: List[Finding] = []
        js_sink_re = re.compile(r"\b(eval|child_process\.exec|execSync)\s*\(([^)]+)\)")
        for idx, line in enumerate(content.splitlines(), start=1):
            m = js_sink_re.search(line)
            if m and LLM_VAR_RE.search(m.group(2)):
                out.append(
                    self.make_finding(
                        file=path,
                        line=idx,
                        evidence=line.strip(),
                        why_it_matters=f"Passing LLM output to JS `{m.group(1)}()` enables arbitrary code/command execution.",
                    )
                )
        return out


class CheckC5PromptConcatenation(RepoCheck):
    id = "C5"
    analyst = "ai_surface"
    title = "User input concatenated directly into system prompt without delimiter or role separation"
    severity = "medium"
    asi_ids = ["ASI01"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        concat_re = re.compile(
            r"(system_prompt|system_message|role['\"]?\s*:\s*['\"]system['\"])[^\n]*(?:\+|f['\"].*\{(user_input|query|request|prompt|message)\})",
            re.I,
        )
        for path, content in repo_ctx.files.items():
            if not path.endswith((".py", ".js", ".ts")):
                continue
            for idx, line in enumerate(content.splitlines(), start=1):
                if concat_re.search(line):
                    findings.append(
                        self.make_finding(
                            file=path,
                            line=idx,
                            evidence=line.strip(),
                            why_it_matters=(
                                "Concatenating untrusted user input directly into the `system` prompt collapses "
                                "the instruction hierarchy and makes prompt injection trivial."
                            ),
                        )
                    )
        return findings


class CheckC6UnconfirmedAgentTools(RepoCheck):
    id = "C6"
    analyst = "ai_surface"
    title = "Agent tool exposes shell, filesystem, or network access without allow-list or human confirmation"
    severity = "medium"
    asi_ids = ["ASI02", "ASI09"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        tool_dec_re = re.compile(r"@(?:tool|function_tool|agent\.tool)|StructuredTool\.from_function", re.I)
        danger_body_re = re.compile(r"\b(subprocess\.|os\.system|os\.remove|shutil\.rmtree|open\([^)]*['\"]w['\"])")
        for path, content in repo_ctx.files.items():
            if not path.endswith(".py"):
                continue
            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                if tool_dec_re.search(line):
                    window = "\n".join(lines[idx - 1 : min(len(lines), idx + 18)])
                    if danger_body_re.search(window) and "confirm" not in window.lower() and "allowlist" not in window.lower():
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=idx,
                                evidence=line.strip(),
                                why_it_matters=(
                                    "Agent tools that execute shell commands or modify files without an allow-list "
                                    "or human-in-the-loop confirmation can be abused via indirect prompt injection."
                                ),
                            )
                        )
        return findings


class CheckC7UnsanitizedRAGIngestion(RepoCheck):
    id = "C7"
    analyst = "ai_surface"
    title = "RAG or vector memory store ingests external content without sanitization"
    severity = "medium"
    asi_ids = ["ASI06"]
    incident_ref = "Indirect Prompt Injection via RAG poisoning"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        rag_re = re.compile(r"\.(add_documents|add_texts|from_documents|upsert)\s*\(")
        for path, content in repo_ctx.files.items():
            if not path.endswith((".py", ".js", ".ts")):
                continue
            if rag_re.search(content) and "sanitize" not in content.lower() and "clean" not in content.lower():
                for idx, line in enumerate(content.splitlines(), start=1):
                    if rag_re.search(line):
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=idx,
                                evidence=line.strip(),
                                why_it_matters=(
                                    "Ingesting external documents or web pages into a vector store without stripping "
                                    "instruction-override payloads enables persistent RAG memory poisoning."
                                ),
                            )
                        )
                        break
        return findings


SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{12,})"), "Anthropic API Key"),
    (re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{16,})"), "OpenAI API Key"),
    (re.compile(r"\b(AIza[0-9A-Za-z_-]{20,})"), "Google Gemini/Cloud API Key"),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{20,})"), "GitHub Personal Access Token"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key ID"),
]


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return secret[:3] + "***REDACTED***"
    return f"{secret[:7]}...REDACTED"


class CheckC8HardcodedCredentialsOrEnv(RepoCheck):
    id = "C8"
    analyst = "ai_surface"
    title = "Hard-coded AI/cloud credential or committed `.env` file"
    severity = "critical"
    asi_ids = ["ASI10"]
    incident_ref = "s1ngularity credential harvest (Aug 2025)"

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        findings: List[Finding] = []
        for path, content in repo_ctx.files.items():
            base = path.rsplit("/", 1)[-1]
            if base == ".env" or (base.startswith(".env.") and not base.endswith((".example", ".sample", ".template"))):
                findings.append(
                    self.make_finding(
                        file=path,
                        line=1,
                        evidence=f"Committed environment file `{path}`",
                        why_it_matters="Committed `.env` files expose live API keys and secrets to anyone cloning the repository.",
                    )
                )
                continue

            # Skip unit test files testing secret redaction/sanitization or dummy example keys
            lower_path = path.lower()
            is_test_file = (
                lower_path.startswith(("test/", "tests/"))
                or "/test/" in lower_path
                or "/tests/" in lower_path
                or ".test." in lower_path
                or ".spec." in lower_path
                or base.startswith("test_")
            )
            if is_test_file:
                continue

            for idx, line in enumerate(content.splitlines(), start=1):
                for pat, label in SECRET_PATTERNS:
                    m = pat.search(line)
                    if m:
                        raw_secret = m.group(1)
                        if "EXAMPLE" in raw_secret or "DUMMY" in raw_secret.upper():
                            continue
                        masked = mask_secret(raw_secret)
                        findings.append(
                            self.make_finding(
                                file=path,
                                line=idx,
                                evidence=f"{label}: {masked}",
                                why_it_matters=(
                                    f"Hard-coded {label} (`{masked}`) allows immediate unauthorized LLM API consumption "
                                    "or cloud infrastructure compromise."
                                ),
                            )
                        )
                        break
        return findings


AI_SDK_IMPORT_RE = re.compile(
    r"\b(openai|anthropic|langchain|llama_index|google\.generativeai|chromadb|mcp|autogen|crewai)\b",
    re.I,
)


class CheckC9MissingPromptInjectionTests(RepoCheck):
    id = "C9"
    analyst = "ai_surface"
    title = "AI application repository has no tests or evals for prompt injection"
    severity = "low"
    asi_ids = ["ASI01", "ASI09"]
    incident_ref = None

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        uses_ai = False
        ai_file = None
        has_injection_test = False

        for path, content in repo_ctx.files.items():
            if AI_SDK_IMPORT_RE.search(content):
                uses_ai = True
                if ai_file is None:
                    ai_file = path
            if ("test" in path.lower() or "eval" in path.lower()) and (
                "prompt_injection" in content.lower()
                or "ignore previous" in content.lower()
                or "jailbreak" in content.lower()
            ):
                has_injection_test = True

        if uses_ai and not has_injection_test:
            return [
                self.make_finding(
                    file=ai_file or "README.md",
                    line=1,
                    evidence="AI SDK detected without corresponding prompt-injection test suite or evals",
                    why_it_matters=(
                        "AI applications without automated adversarial prompt-injection tests frequently regress "
                        "when prompts, models, or tools are updated."
                    ),
                )
            ]
        return []


AI_SURFACE_CHECKS: List[RepoCheck] = [
    CheckC1HiddenUnicodeInRules(),
    CheckC2MaliciousInstructionDirectives(),
    CheckC3UnsafeMCPConfig(),
    CheckC4LLMOutputToDangerousSink(),
    CheckC5PromptConcatenation(),
    CheckC6UnconfirmedAgentTools(),
    CheckC7UnsanitizedRAGIngestion(),
    CheckC8HardcodedCredentialsOrEnv(),
    CheckC9MissingPromptInjectionTests(),
]
