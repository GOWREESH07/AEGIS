"""
reposcan/cloner.py — Safe repository cloner and static file walker.

Hard safety rules enforced:
- Static analysis only: NEVER executes, installs, builds, or imports repository code.
- Validates URL is strictly https://github.com/<owner>/<repo> (rejects SSRF / other hosts).
- Clones with `git clone --depth 1 --no-tags --single-branch`, `GIT_TERMINAL_PROMPT=0`,
  and `-c core.hooksPath=/dev/null` into a temporary directory deleted after scan.
- Enforces: max repo size 200 MB, max file size 2 MB, skips binaries, never follows
  symlinks outside the clone root, 120s timeout.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


GITHUB_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

MAX_REPO_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_FILE_BYTES = 2 * 1024 * 1024    # 2 MB
CLONE_TIMEOUT_SECONDS = 120

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".pyc", ".pyo", ".class", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".sqlite", ".db", ".wasm", ".o", ".a", ".lib", ".tif", ".tiff",
    ".geojson", ".shp", ".dbf", ".shx", ".nc", ".hdf5", ".h5", ".parquet",
    ".feather", ".npy", ".npz", ".pt", ".pth", ".onnx", ".safetensors",
    ".gguf", ".pkl", ".joblib", ".pb", ".tflite", ".whl",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def validate_github_url(url: str) -> Tuple[str, str, str]:
    """
    Validate that *url* is strictly `https://github.com/<owner>/<repo>`.
    Rejects non-GitHub hosts, credentials in URL, query strings, fragments, and path traversal.
    Returns `(normalized_url, owner, repo)`.
    """
    cleaned = url.strip()
    if "@" in cleaned or "?" in cleaned or "#" in cleaned or ".." in cleaned:
        raise ValueError(f"Rejected unsafe URL: {url}")
    m = GITHUB_URL_RE.match(cleaned)
    if not m:
        raise ValueError("URL must be a public GitHub repository: https://github.com/<owner>/<repo>")
    owner, repo = m.group(1), m.group(2)
    if owner in (".", "..") or repo in (".", ".."):
        raise ValueError("Invalid repository owner or name")
    normalized = f"https://github.com/{owner}/{repo}"
    return normalized, owner, repo


def is_binary_bytes(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample[:4096]:
        return True
    return False


@dataclass
class RepoContext:
    root: Path
    url: str
    owner: str
    repo: str
    commit_sha: str
    files: Dict[str, str] = field(default_factory=dict)
    files_eligible: int = 0
    files_analysed: int = 0
    total_bytes: int = 0

    @property
    def coverage_pct(self) -> float:
        if self.files_eligible == 0:
            return 100.0
        return round((self.files_analysed / self.files_eligible) * 100.0, 1)


def load_repo_context(
    root: Path,
    url: str = "https://github.com/local/fixture",
    owner: str = "local",
    repo: str = "fixture",
    commit_sha: str = "0" * 40,
) -> RepoContext:
    """
    Walk *root* safely without following symlinks outside *root*, skipping binaries
    and files > 2 MB, and enforcing the 200 MB repository cap.
    """
    resolved_root = root.resolve()
    ctx = RepoContext(
        root=resolved_root,
        url=url,
        owner=owner,
        repo=repo,
        commit_sha=commit_sha,
    )

    for dirpath, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        # Prune skipped directories and symlinked directories
        kept_dirs = []
        for d in dirnames:
            if d in SKIP_DIRS:
                continue
            full_d = Path(dirpath) / d
            if full_d.is_symlink():
                try:
                    target = full_d.resolve()
                    if not str(target).startswith(str(resolved_root)):
                        continue
                except Exception:
                    continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fname in filenames:
            fpath = Path(dirpath) / fname
            # Never follow symlinks pointing outside the clone root
            if fpath.is_symlink():
                try:
                    target = fpath.resolve()
                    if not str(target).startswith(str(resolved_root)):
                        continue
                except Exception:
                    continue

            try:
                st = fpath.stat()
            except OSError:
                continue

            ctx.total_bytes += st.st_size
            if ctx.total_bytes > MAX_REPO_BYTES:
                raise RuntimeError(f"Repository exceeds maximum allowed size of {MAX_REPO_BYTES // (1024 * 1024)} MB")

            ext = fpath.suffix.lower()
            if ext in BINARY_EXTENSIONS:
                continue

            ctx.files_eligible += 1
            if st.st_size > MAX_FILE_BYTES:
                continue

            try:
                raw = fpath.read_bytes()
            except OSError:
                continue

            if is_binary_bytes(raw):
                ctx.files_eligible -= 1
                continue

            text = raw.decode("utf-8", errors="replace")
            rel_path = fpath.relative_to(resolved_root).as_posix()
            ctx.files[rel_path] = text
            ctx.files_analysed += 1

    return ctx


def clone_and_load(url: str, ref: Optional[str] = None) -> RepoContext:
    """
    Safely clone a public GitHub repository into a temporary directory, read eligible
    text files into memory, and delete the temporary directory in a `finally` block.
    """
    normalized_url, owner, repo = validate_github_url(url)
    tmp_dir = Path(tempfile.mkdtemp(prefix="aegis_reposcan_"))

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/echo",
        "HOME": str(tmp_dir),
    }

    clone_target = tmp_dir / "repo"
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "submodule.recurse=false",
        "clone",
        "--depth", "1",
        "--filter=blob:limit=2m",
        "--no-checkout",
        "--no-tags",
        "--single-branch",
    ]
    if ref and re.match(r"^[A-Za-z0-9_./-]+$", ref) and not ref.startswith("-"):
        cmd.extend(["--branch", ref])

    # Support optional GITHUB_TOKEN via http.extraheader without ever logging it
    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if gh_token:
        import base64
        b64 = base64.b64encode(f"x-access-token:{gh_token}".encode()).decode()
        cmd[1:1] = ["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {b64}"]

    cmd.extend([f"{normalized_url}.git", str(clone_target)])

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
            text=True,
        )
        if proc.returncode != 0:
            # Redact any token from stderr
            err = (proc.stderr or "git clone failed").strip()
            if gh_token:
                err = err.replace(gh_token, "***")
            raise RuntimeError(f"git clone failed: {err[:240]}")

        # Read HEAD commit SHA
        sha_proc = subprocess.run(
            ["git", "-C", str(clone_target), "rev-parse", "HEAD"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            text=True,
        )
        commit_sha = sha_proc.stdout.strip() if sha_proc.returncode == 0 else "0" * 40

        # Enumerate locally downloaded blobs (< 2 MB) without contacting the remote
        batch_proc = subprocess.run(
            [
                "git", "-C", str(clone_target),
                "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                "--batch-all-objects",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            text=True,
        )
        local_blobs: Dict[str, int] = {}
        if batch_proc.returncode == 0:
            for line in batch_proc.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[1] == "blob":
                    try:
                        local_blobs[parts[0]] = int(parts[2])
                    except ValueError:
                        pass

        # List tree entries in HEAD and select only locally present, non-binary files
        tree_proc = subprocess.run(
            ["git", "-C", str(clone_target), "ls-tree", "-r", "HEAD"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            text=True,
        )
        checkout_paths: List[str] = []
        skipped_large_text_files = 0
        if tree_proc.returncode == 0:
            for line in tree_proc.stdout.splitlines():
                if "\t" not in line:
                    continue
                meta, rel_path = line.split("\t", 1)
                meta_parts = meta.split()
                if len(meta_parts) < 3:
                    continue
                mode, obj_type, sha = meta_parts[0], meta_parts[1], meta_parts[2]
                if mode == "120000" or obj_type != "blob":
                    continue
                p_obj = Path(rel_path)
                if any(part in SKIP_DIRS for part in p_obj.parts):
                    continue
                if p_obj.suffix.lower() in BINARY_EXTENSIONS:
                    continue
                if sha in local_blobs and local_blobs[sha] <= MAX_FILE_BYTES:
                    checkout_paths.append(rel_path)
                else:
                    skipped_large_text_files += 1

        # Checkout only the locally available text blobs in batches (0 network calls)
        chunk_size = 400
        for i in range(0, len(checkout_paths), chunk_size):
            batch = checkout_paths[i : i + chunk_size]
            subprocess.run(
                ["git", "-C", str(clone_target), "checkout", "HEAD", "--"] + batch,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
                text=True,
            )

        ctx = load_repo_context(
            root=clone_target,
            url=normalized_url,
            owner=owner,
            repo=repo,
            commit_sha=commit_sha,
        )
        ctx.files_eligible += skipped_large_text_files
        return ctx
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
