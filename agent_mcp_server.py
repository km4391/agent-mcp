#!/usr/bin/env python3
"""
agent-mcp — a hardened local MCP server for macOS: terminal + files + processes.

Design (defense in depth, in order of strength):
  1. KERNEL SANDBOX  every command runs under macOS Seatbelt (sandbox-exec):
                     - writes only inside the workspace (+ temp dirs)
                     - reads: system + toolchains + workspace; your home folder,
                       secrets, other users and external volumes are unreadable
                     - no raw network; the only allowed socket is the local proxy
                     - dangerous binaries (osascript, open, security, launchctl…) can't exec
  2. NETWORK PROXY   a local CONNECT proxy with a HOSTNAME ALLOWLIST (pypi, npm,
                     github…). TLS stays end-to-end; the proxy only sees host:port.
  3. CLEAN ENV       commands get a minimal environment (no host app secrets/API keys).
  4. POLICY IN CODE  no tool can change the policy; it is fixed at launch by env vars.
  5. AUDIT + REDACT  every tool call is logged outside the workspace; common secret
                     formats are redacted from anything returned to the model.
  6. SOFT DELETE     delete_path moves to a trash folder instead of removing.

Subcommands:
  python3 agent_mcp_server.py                 # serve over stdio (what the MCP client runs)
  python3 agent_mcp_server.py doctor          # validate the sandbox on this Mac (30s)
  python3 agent_mcp_server.py print-profile   # show the generated Seatbelt profile
  python3 agent_mcp_server.py print-policy    # show effective config

Requires Python 3.10+ and `pip install "mcp[cli]"` (SDK 1.x or 2.x both work).
"""
from __future__ import annotations

import asyncio
import base64
import difflib
import fnmatch
import functools
import json
import logging
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import stat as statmod
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlsplit

from pydantic import Field

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

__version__ = "2.0.0"
IS_MAC = platform.system() == "Darwin"

# ============================================================================ config
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_list(name: str) -> list[str]:
    return [x.strip() for x in _env(name).split(",") if x.strip()]


HOME = Path.home().resolve()
WORKSPACE = Path(_env("AGENT_WORKSPACE") or (HOME / "AgentWorkspace")).expanduser().resolve()
WORKSPACE.mkdir(parents=True, exist_ok=True)
TMPDIR = Path(tempfile.gettempdir()).resolve()

DEFAULT_TIMEOUT = int(_env("AGENT_TIMEOUT", "60"))
MAX_TIMEOUT = 1800
MAX_OUTPUT_CHARS = int(_env("AGENT_MAX_OUTPUT", "30000"))
MAX_READ_BYTES = 5_000_000
MAX_SESSIONS = 16
SESSION_BUFFER_BYTES = 2 * 1024 * 1024

SANDBOX_MODE = _env("AGENT_SANDBOX") or ("seatbelt" if IS_MAC else "off")   # seatbelt | off
ALLOW_INBOUND_ALL = _env("AGENT_ALLOW_INBOUND") == "1"
ALLOW_LOCALHOST = _env("AGENT_ALLOW_LOCALHOST", "1") == "1"   # talk to Ollama / local dev servers
EXTRA_READ = [str(Path(p).expanduser().resolve()) for p in _env_list("AGENT_EXTRA_READ")]
EXTRA_WRITE = [str(Path(p).expanduser().resolve()) for p in _env_list("AGENT_EXTRA_WRITE")]
PASS_ENV = _env_list("AGENT_PASS_ENV")

NET_OFF = _env("AGENT_NET_OFF") == "1"
DEFAULT_NET_ALLOW = [
    # Python
    "pypi.org", "files.pythonhosted.org",
    # Node
    "registry.npmjs.org", "registry.yarnpkg.com",
    # GitHub (note: git push to GitHub is an exfiltration channel; remove if you don't need it)
    "github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com", "ghcr.io",
    # Rust / Go
    "crates.io", "static.crates.io", "index.crates.io", "proxy.golang.org", "sum.golang.org",
    # Homebrew metadata (installs still need writes outside the workspace -> run brew yourself)
    "formulae.brew.sh",
    # Models
    "huggingface.co", "*.huggingface.co", "*.hf.co",
]
NET_ALLOW = _env_list("AGENT_NET_ALLOW_ONLY") or (DEFAULT_NET_ALLOW + _env_list("AGENT_NET_ALLOW"))
NET_PORTS = {int(p) for p in (_env_list("AGENT_NET_PORTS") or ["80", "443"])}

LOG_DIR = Path(_env("AGENT_LOG_DIR") or (HOME / "Library" / "Logs" / "agent-mcp" if IS_MAC
                                        else HOME / ".local" / "state" / "agent-mcp"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

SHELL = next((s for s in ("/bin/zsh", "/bin/bash", "/bin/sh") if Path(s).exists()), "/bin/sh")

# stdout is the MCP protocol channel: log to stderr only.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[agent-mcp] %(message)s")
log = logging.getLogger("agent-mcp")

# ============================================================================ audit log
_audit_lock = threading.Lock()
_AUDIT_FILE = LOG_DIR / "audit.jsonl"


def audit(event: str, **data) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **data}
    line = json.dumps(rec, default=str)[:4000]
    with _audit_lock:
        try:
            with _AUDIT_FILE.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
    log.info("%s %s", event, {k: (str(v)[:160]) for k, v in data.items()})


# ============================================================================ redaction
_SECRET_PATTERNS = [
    re.compile(p) for p in (
        r"sk-[A-Za-z0-9_\-]{20,}",                       # OpenAI/Anthropic-style keys
        r"ghp_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{20,}", r"gho_[A-Za-z0-9]{30,}",
        r"AKIA[0-9A-Z]{16}",                             # AWS access key id
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",                # Slack
        r"AIza[0-9A-Za-z_\-]{35}",                       # Google API
        r"hf_[A-Za-z0-9]{30,}",                          # HuggingFace
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-/+]{16,}['\"]?",
    )
]


def redact(text: str) -> str:
    n = 0
    for rx in _SECRET_PATTERNS:
        text, k = rx.subn("[REDACTED]", text)
        n += k
    if n:
        audit("redacted", count=n)
    return text


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n\n... [{len(text) - limit:,} chars omitted — use offset/length or read_output to page] ...\n\n{text[-half:]}"


def finish(text: str) -> str:
    return truncate(redact(text))


# ============================================================================ paths
def safe_path(rel: str, must_exist: bool = False) -> Path:
    """Resolve a path and refuse anything outside WORKSPACE (blocks ../ and symlink escapes)."""
    p = Path(rel).expanduser()
    target = (p if p.is_absolute() else WORKSPACE / p).resolve()
    if target != WORKSPACE and not target.is_relative_to(WORKSPACE):
        raise PermissionError(f"'{rel}' is outside the workspace ({WORKSPACE})")
    if must_exist and not target.exists():
        raise FileNotFoundError(f"'{rel}' does not exist")
    return target


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(WORKSPACE)) or "."
    except ValueError:
        return str(p)


# ============================================================================ network policy + proxy
class NetPolicy:
    def __init__(self, hosts: list[str], ports: set[int], enabled: bool):
        self.enabled = enabled
        self.ports = ports
        self.exact = {h.lower().rstrip(".") for h in hosts if not h.startswith("*.")}
        self.suffixes = tuple(h.lower()[1:] for h in hosts if h.startswith("*."))  # ".example.com"

    def allowed(self, host: str, port: int) -> bool:
        if not self.enabled:
            return False
        host = host.lower().rstrip(".").strip("[]")
        if port not in self.ports:
            return False
        if host in self.exact:
            return True
        return any(host.endswith(s) and host != s[1:] for s in self.suffixes)

    def describe(self) -> str:
        if not self.enabled:
            return "network: OFF"
        return f"network: ports {sorted(self.ports)}; hosts {sorted(self.exact)} + wildcards {['*' + s for s in self.suffixes]}"


POLICY = NetPolicy(NET_ALLOW, NET_PORTS, enabled=not NET_OFF)


class AllowlistProxy(threading.Thread):
    """Minimal HTTP/1.1 forward proxy (CONNECT + absolute-URI) bound to 127.0.0.1 with a per-launch token."""

    def __init__(self, policy: NetPolicy):
        super().__init__(name="allowlist-proxy", daemon=True)
        self.policy = policy
        self.token = secrets.token_urlsafe(24)
        self._expected_auth = "Basic " + base64.b64encode(f"agent:{self.token}".encode()).decode()
        self.port = 0
        self._ready = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # -- lifecycle
    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        server = await asyncio.start_server(self._on_client, "127.0.0.1", 0, limit=1 << 16)
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        async with server:
            await server.serve_forever()

    def start_and_wait(self) -> "AllowlistProxy":
        self.start()
        if not self._ready.wait(5):
            raise RuntimeError("proxy failed to start")
        return self

    @property
    def url(self) -> str:
        return f"http://agent:{self.token}@127.0.0.1:{self.port}"

    # -- protocol
    @staticmethod
    async def _respond(writer: asyncio.StreamWriter, code: int, reason: str, extra: str = "") -> None:
        body = f"{code} {reason}\n".encode()
        head = f"HTTP/1.1 {code} {reason}\r\n{extra}Content-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        writer.write(head.encode() + body)
        try:
            await writer.drain()
        finally:
            writer.close()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        except Exception:
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            await self._respond(writer, 400, "Bad Request")
            return
        method, target, version = parts
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if headers.get("proxy-authorization") != self._expected_auth:
            audit("net.unauthorized", target=target)
            await self._respond(writer, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Basic realm="agent"\r\n')
            return

        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            host = host.strip("[]")
            port = int(port_s or 443)
            if not self.policy.allowed(host, port):
                audit("net.denied", host=host, port=port, method="CONNECT")
                await self._respond(writer, 403, "Blocked by agent-mcp allowlist")
                return
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 20)
            except Exception as e:
                audit("net.error", host=host, port=port, error=str(e))
                await self._respond(writer, 502, "Bad Gateway")
                return
            audit("net.allowed", host=host, port=port, method="CONNECT")
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._pipe_both(reader, writer, ur, uw)
            return

        u = urlsplit(target)
        if u.scheme != "http" or not u.hostname:
            await self._respond(writer, 400, "Only absolute http:// URLs or CONNECT")
            return
        port = u.port or 80
        if not self.policy.allowed(u.hostname, port):
            audit("net.denied", host=u.hostname, port=port, method=method)
            await self._respond(writer, 403, "Blocked by agent-mcp allowlist")
            return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(u.hostname, port), 20)
        except Exception as e:
            audit("net.error", host=u.hostname, port=port, error=str(e))
            await self._respond(writer, 502, "Bad Gateway")
            return
        audit("net.allowed", host=u.hostname, port=port, method=method)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        fwd = [ln for ln in lines[1:] if ln and not ln.lower().startswith(("proxy-", "connection:", "keep-alive:"))]
        new_head = f"{method} {path} {version}\r\n" + "\r\n".join(fwd) + "\r\nConnection: close\r\n\r\n"
        uw.write(new_head.encode("latin-1"))
        await uw.drain()
        await self._pipe_both(reader, writer, ur, uw)

    @staticmethod
    async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.write_eof()
            except Exception:
                pass

    async def _pipe_both(self, cr, cw, ur, uw) -> None:
        try:
            await asyncio.gather(self._pipe(cr, uw), self._pipe(ur, cw), return_exceptions=True)
        finally:
            for w in (cw, uw):
                try:
                    w.close()
                except Exception:
                    pass


PROXY: Optional[AllowlistProxy] = None

# ============================================================================ seatbelt profile
SECRET_DIRS = [
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud", ".config/gh", ".config/op",
    ".netrc", ".npmrc", ".pypirc", ".gitconfig.local", ".git-credentials", ".bash_history", ".zsh_history",
    "Library/Keychains", "Library/Cookies", "Library/Application Support", "Library/Mail", "Library/Messages",
    "Library/Safari", "Library/Group Containers", "Library/Containers", "Library/Accounts", "Library/HTTPStorages",
    "Library/Preferences", "Library/Mobile Documents", "Documents", "Desktop", "Downloads", "Pictures",
]
TOOLCHAIN_DIRS = [
    ".cache", ".npm", ".pyenv", ".nvm", ".volta", ".local", ".cargo", ".rustup", "go", ".bun", ".deno", ".asdf",
    ".sdkman", ".rbenv", ".gem", ".m2", ".gradle", "Library/pnpm", "Library/Caches", "Library/Python",
    ".gitconfig", ".gitignore_global", ".config/git", ".tool-versions",
    ".zshenv", ".profile",
]
DENIED_BINARIES = [
    "/usr/bin/osascript", "/usr/bin/open", "/usr/bin/security", "/bin/launchctl", "/usr/bin/defaults",
    "/usr/bin/tccutil", "/usr/sbin/diskutil", "/sbin/mount", "/sbin/umount", "/usr/sbin/systemsetup",
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/login", "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/screencapture",
    "/usr/sbin/networksetup", "/usr/bin/profiles", "/usr/sbin/spctl", "/usr/bin/csrutil", "/usr/bin/automator",
    "/usr/bin/shortcuts",
]
MACH_SERVICES = [
    "com.apple.system.opendirectoryd.libinfo", "com.apple.system.opendirectoryd.membership",
    "com.apple.system.logger", "com.apple.logd", "com.apple.system.notification_center",
    "com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent", "com.apple.bsd.dirhelper",
    "com.apple.trustd", "com.apple.trustd.agent", "com.apple.SecurityServer", "com.apple.FSEvents",
    "com.apple.networkd", "com.apple.nehelper",
]


def _q(p: str) -> str:
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_profile(proxy_port: int) -> str:
    h = str(HOME)
    ws = str(WORKSPACE)
    L: list[str] = ["(version 1)", "(deny default)", ";; --- agent-mcp generated Seatbelt profile ---",
                    "(allow process-fork)", "(allow sysctl-read)", "(allow process-info*)",
                    "(allow signal (target same-sandbox))", "(allow ipc-posix*)", "(allow pseudo-tty)",
                    "(allow file-ioctl)", "(allow user-preference-read)",
                    "(allow mach-lookup " + " ".join(f'(global-name "{s}")' for s in MACH_SERVICES) + ")"]
    # exec: everything except known-dangerous binaries
    L.append("(allow process-exec* (require-all " + " ".join(f"(require-not (literal {_q(b)}))" for b in DENIED_BINARIES) + "))")
    # reads: system, minus user homes / external volumes / system secrets
    L.append('(allow file-read* (require-all (require-not (subpath "/Users")) (require-not (subpath "/Volumes")) '
             '(require-not (subpath "/Library/Keychains")) (require-not (subpath "/private/var/root")) '
             '(require-not (subpath "/private/etc/sudoers")) (require-not (subpath "/private/var/db/dslocal"))))')
    L.append(f'(allow file-read-metadata (literal "/Users") (literal "/Volumes") (literal {_q(h)}))')
    read_ok = [ws, str(TMPDIR)] + [str(HOME / d) for d in TOOLCHAIN_DIRS] + EXTRA_READ
    L.append("(allow file-read* " + " ".join(f"(subpath {_q(p)})" for p in read_ok) + ")")
    L.append("(deny file-read* " + " ".join(f"(subpath {_q(str(HOME / d))})" for d in SECRET_DIRS) + ")")
    # writes: workspace + temp only
    write_ok = [ws, str(TMPDIR), "/private/tmp", "/tmp", "/private/var/tmp"] + EXTRA_WRITE
    L.append("(allow file-write* " + " ".join(f"(subpath {_q(p)})" for p in write_ok) + ")")
    L.append('(allow file-write* (literal "/dev/null") (literal "/dev/tty") (literal "/dev/ptmx") '
             '(literal "/dev/dtracehelper") (regex #"^/dev/ttys[0-9]+$") (regex #"^/dev/fd/[0-9]+$"))')
    # network: only the local allowlist proxy (+ unix sockets in workspace, + local dev servers)
    if proxy_port:
        L.append(f'(allow network-outbound (remote ip "localhost:{proxy_port}"))')
    L.append(f"(allow network* (subpath {_q(ws)}))")
    scope = '"*:*"' if ALLOW_INBOUND_ALL else '"localhost:*"'
    L.append(f"(allow network-bind (local ip {scope}))")
    L.append(f"(allow network-inbound (local ip {scope}))")
    if ALLOW_LOCALHOST:  # Ollama, local dev servers. NOTE: a local proxy on your Mac would bypass the allowlist.
        L.append('(allow network-outbound (remote ip "localhost:*"))')
    return "\n".join(L) + "\n"


def sandbox_argv(argv: list[str]) -> list[str]:
    if SANDBOX_MODE == "seatbelt":
        return ["/usr/bin/sandbox-exec", "-p", build_profile(PROXY.port if PROXY else 0)] + argv
    return argv


def check_sandbox_available() -> None:
    if SANDBOX_MODE == "seatbelt":
        if not Path("/usr/bin/sandbox-exec").exists():
            log.error("sandbox-exec not found. Refusing to start unsandboxed. Set AGENT_SANDBOX=off to override (NOT recommended).")
            sys.exit(2)
    elif SANDBOX_MODE == "off":
        log.warning("!!! SANDBOX OFF — commands run with your full user permissions !!!")
    else:
        log.error("AGENT_SANDBOX must be 'seatbelt' or 'off'")
        sys.exit(2)


# ============================================================================ child environment
def _toolchain_paths() -> list[str]:
    cands = [HOME / ".local/bin", HOME / ".cargo/bin", HOME / ".pyenv/shims", HOME / ".volta/bin",
             HOME / ".bun/bin", HOME / "go/bin", HOME / ".deno/bin", HOME / "Library/pnpm"]
    nvm = HOME / ".nvm/versions/node"
    if nvm.is_dir():
        vers = sorted(nvm.iterdir(), key=lambda p: p.name, reverse=True)
        if vers:
            cands.append(vers[0] / "bin")
    return [str(p) for p in cands if p.is_dir()]


def child_env() -> dict[str, str]:
    cache = WORKSPACE / ".cache"
    path = ":".join(_toolchain_paths() + ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                                          "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    env = {
        "PATH": path, "HOME": str(HOME), "USER": os.environ.get("USER", ""), "LOGNAME": os.environ.get("USER", ""),
        "SHELL": SHELL, "TMPDIR": str(TMPDIR), "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        "TERM": "dumb", "COLUMNS": "160", "LINES": "50", "NO_COLOR": "1", "CI": "1",
        "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_PROGRESS_BAR": "off", "PIP_CACHE_DIR": str(cache / "pip"), "UV_CACHE_DIR": str(cache / "uv"),
        "npm_config_cache": str(cache / "npm"), "npm_config_update_notifier": "false", "XDG_CACHE_HOME": str(cache),
        "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1", "GIT_TERMINAL_PROMPT": "0",
        "AGENT_WORKSPACE": str(WORKSPACE), "NODE_USE_ENV_PROXY": "1",
    }
    if PROXY and POLICY.enabled:
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[k] = PROXY.url
        env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1,::1"
    for k in PASS_ENV:
        if k in os.environ:
            env[k] = os.environ[k]
    return env


# ============================================================================ process sessions (pty)
import fcntl  # noqa: E402
import pty  # noqa: E402,F401
import struct  # noqa: E402
import termios  # noqa: E402


@dataclass
class Session:
    pid: int
    command: str
    cwd: str
    proc: subprocess.Popen
    master_fd: int
    started: float = field(default_factory=time.time)
    buf: bytearray = field(default_factory=bytearray)
    total: int = 0            # bytes ever written to buf (for cursors)
    dropped: int = 0          # bytes trimmed from the front
    cursor: int = 0           # read position for read_output
    lock: threading.Lock = field(default_factory=threading.Lock)
    reader: Optional[threading.Thread] = None
    eof: bool = False

    @property
    def exit_code(self) -> Optional[int]:
        return self.proc.poll()

    def _reader(self) -> None:
        while True:
            try:
                data = os.read(self.master_fd, 65536)
            except OSError:
                data = b""
            if not data:
                break
            with self.lock:
                self.buf += data
                self.total += len(data)
                if len(self.buf) > SESSION_BUFFER_BYTES:
                    cut = len(self.buf) - SESSION_BUFFER_BYTES
                    del self.buf[:cut]
                    self.dropped += cut
        self.eof = True
        try:
            os.close(self.master_fd)
        except OSError:
            pass

    def new_output(self) -> str:
        with self.lock:
            start = max(self.cursor - self.dropped, 0)
            note = ""
            if self.cursor < self.dropped:
                note = f"[... {self.dropped - self.cursor:,} bytes of output dropped ...]\n"
            chunk = bytes(self.buf[start:])
            self.cursor = self.total
        return note + chunk.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")

    def status(self) -> str:
        code = self.exit_code
        return "running" if code is None else f"exited ({code})"


class ProcessManager:
    def __init__(self) -> None:
        self.sessions: dict[int, Session] = {}
        self.lock = threading.Lock()

    def _gc(self) -> None:
        done = [p for p, s in self.sessions.items() if s.exit_code is not None]
        for p in done[:-30]:  # keep the 30 most recent finished sessions
            self.sessions.pop(p, None)

    def start(self, command: str, cwd: str = ".") -> Session:
        workdir = safe_path(cwd, must_exist=True)
        if not workdir.is_dir():
            raise NotADirectoryError(f"{cwd} is not a directory")
        with self.lock:
            self._gc()
            if sum(1 for s in self.sessions.values() if s.exit_code is None) >= MAX_SESSIONS:
                raise RuntimeError(f"too many running processes (max {MAX_SESSIONS}); kill some first")
        env = child_env()
        (WORKSPACE / ".cache").mkdir(exist_ok=True)
        master, slave = os.openpty()
        try:
            attrs = termios.tcgetattr(slave)
            attrs[1] &= ~termios.ONLCR           # no \r\n translation
            attrs[3] &= ~termios.ECHO            # don't echo our own input back
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
        except (termios.error, OSError):
            pass
        argv = sandbox_argv([SHELL, "-f", "-c", command] if SHELL.endswith("zsh") else [SHELL, "-c", command])
        try:
            proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, cwd=str(workdir), env=env,
                                    start_new_session=True, close_fds=True)
        finally:
            os.close(slave)
        s = Session(pid=proc.pid, command=command, cwd=rel(workdir), proc=proc, master_fd=master)
        s.reader = threading.Thread(target=s._reader, name=f"pty-{proc.pid}", daemon=True)
        s.reader.start()
        with self.lock:
            self.sessions[proc.pid] = s
        audit("proc.start", pid=proc.pid, cwd=s.cwd, command=command[:500])
        return s

    def get(self, pid: int) -> Session:
        s = self.sessions.get(pid)
        if not s:
            raise KeyError(f"no managed process with pid {pid}")
        return s

    @staticmethod
    def wait(s: Session, timeout: float, wait_for: Optional[re.Pattern] = None) -> None:
        """Block until exit, timeout, or (if wait_for) the pattern appears in unread output."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if s.exit_code is not None:
                time.sleep(0.15)  # let the reader drain
                return
            if wait_for is not None:
                with s.lock:
                    pending = bytes(s.buf[max(s.cursor - s.dropped, 0):]).decode("utf-8", "replace")
                if wait_for.search(pending):
                    return
            time.sleep(0.05)

    def send(self, pid: int, text: str, press_enter: bool) -> None:
        s = self.get(pid)
        if s.exit_code is not None:
            raise RuntimeError(f"process {pid} already {s.status()}")
        os.write(s.master_fd, (text + ("\n" if press_enter else "")).encode())
        audit("proc.input", pid=pid, text=text[:200])

    def kill(self, pid: int) -> str:
        s = self.get(pid)
        if s.exit_code is not None:
            return f"process {pid} already {s.status()}"
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(20):
            if s.exit_code is not None:
                break
            time.sleep(0.1)
        if s.exit_code is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            s.proc.wait(timeout=5)
        audit("proc.kill", pid=pid)
        return f"process {pid} terminated ({s.status()})"

    def kill_all(self) -> None:
        for pid, s in list(self.sessions.items()):
            if s.exit_code is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


PM = ProcessManager()


def format_result(s: Session, body: str, still_running_hint: bool = True) -> str:
    head = f"[pid {s.pid}] {s.status()} — {s.cwd}$ {s.command[:200]}"
    if s.exit_code is None and still_running_hint:
        head += "\n(still running: use read_output(pid) to get more, send_input(pid, text) to interact, kill_process(pid) to stop)"
    return head + "\n" + body


# ============================================================================ MCP server + tools
mcp = _Server(
    "agent-mcp",
    instructions=(
        f"You control a sandboxed terminal and file tools on the user's Mac. Workspace: {WORKSPACE}. "
        "Writes outside the workspace, reads of the user's home folder/secrets, and network to hosts outside the "
        "allowlist are blocked by the OS and will fail — don't retry them; tell the user. "
        "Use run_command for short commands; for servers/REPLs use start_process + read_output + send_input."
    ),
)


def tool(fn):
    """Register with MCP and wrap with audit + error-to-string."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        t0 = time.time()
        try:
            out = fn(*a, **kw)
            audit("tool", name=fn.__name__, ms=int((time.time() - t0) * 1000), args=kw or a, ok=True)
            return out
        except Exception as e:  # noqa: BLE001
            audit("tool", name=fn.__name__, ms=int((time.time() - t0) * 1000), args=kw or a, ok=False, error=repr(e))
            return f"Error ({type(e).__name__}): {e}"
    return mcp.tool()(wrapper)


P = Annotated  # shorthand


@tool
def agent_info() -> str:
    """Show the sandbox policy: workspace, sandbox mode, network allowlist, limits, running processes."""
    running = [f"  pid {p}: {s.command[:80]}" for p, s in PM.sessions.items() if s.exit_code is None]
    return "\n".join([
        f"agent-mcp v{__version__} on {platform.platform()}",
        f"workspace (read/write): {WORKSPACE}",
        f"sandbox: {SANDBOX_MODE}" + ("" if SANDBOX_MODE == "seatbelt" else "  <-- WARNING: not sandboxed"),
        POLICY.describe(),
        f"extra read: {EXTRA_READ or '-'} | extra write: {EXTRA_WRITE or '-'} | localhost access: {ALLOW_LOCALHOST} | inbound from LAN: {ALLOW_INBOUND_ALL}",
        f"limits: default timeout {DEFAULT_TIMEOUT}s (max {MAX_TIMEOUT}s), output {MAX_OUTPUT_CHARS:,} chars, {MAX_SESSIONS} concurrent processes",
        f"audit log: {_AUDIT_FILE}",
        "running processes:" + ("\n" + "\n".join(running) if running else " none"),
    ])


# ---- terminal
@tool
def run_command(
    command: P[str, Field(description="Shell command (zsh). Runs inside the sandboxed workspace.")],
    cwd: P[str, Field(description="Working directory relative to the workspace")] = ".",
    timeout_seconds: P[int, Field(description="Return after this many seconds even if still running (max 1800)")] = DEFAULT_TIMEOUT,
) -> str:
    """Run a terminal command and return its output. If it is still running when the timeout hits, it keeps
    running in the background and you get its pid to use with read_output / send_input / kill_process."""
    timeout = max(1, min(int(timeout_seconds), MAX_TIMEOUT))
    s = PM.start(command, cwd)
    PM.wait(s, timeout)
    return finish(format_result(s, s.new_output()))


@tool
def start_process(
    command: P[str, Field(description="Command to start (server, REPL, watcher, long build…)")],
    cwd: P[str, Field(description="Working directory relative to the workspace")] = ".",
    wait_seconds: P[float, Field(description="Seconds to collect initial output before returning")] = 2.0,
) -> str:
    """Start a long-running or interactive process in the background and return its pid plus initial output."""
    s = PM.start(command, cwd)
    PM.wait(s, max(0.0, min(float(wait_seconds), 60.0)))
    return finish(format_result(s, s.new_output()))


@tool
def read_output(
    pid: P[int, Field(description="pid from run_command/start_process")],
    timeout_seconds: P[float, Field(description="Max seconds to wait for new output or exit")] = 5.0,
    wait_for: P[Optional[str], Field(description="Optional regex; return as soon as it appears in new output (e.g. 'Listening on|>>> ')")] = None,
) -> str:
    """Read new output from a managed process since the last read. Waits up to timeout_seconds for output."""
    s = PM.get(pid)
    rx = re.compile(wait_for) if wait_for else None
    timeout = max(0.0, min(float(timeout_seconds), 600.0))
    with s.lock:
        pending = len(s.buf) > max(s.cursor - s.dropped, 0)
    if rx or not pending:  # wait for pattern, or for *any* new output if nothing is pending
        PM.wait(s, timeout, rx)
    out = s.new_output()
    return finish(format_result(s, out if out else "(no new output)"))


@tool
def send_input(
    pid: P[int, Field(description="pid of a running managed process")],
    text: P[str, Field(description="Text to type into the process's terminal")],
    press_enter: P[bool, Field(description="Append a newline (Enter) after the text")] = True,
    wait_seconds: P[float, Field(description="Seconds to wait for a response before returning")] = 2.0,
) -> str:
    """Type into an interactive process (REPL, prompt, password-less CLI) and return what it printed next."""
    PM.send(pid, text, press_enter)
    s = PM.get(pid)
    PM.wait(s, max(0.0, min(float(wait_seconds), 120.0)))
    return finish(format_result(s, s.new_output()))


@tool
def kill_process(pid: P[int, Field(description="pid of a managed process")]) -> str:
    """Terminate a managed process (SIGTERM, then SIGKILL) and its whole process group."""
    return PM.kill(pid)


@tool
def list_processes(
    all_system: P[bool, Field(description="Also list all system processes via ps (read-only)")] = False,
) -> str:
    """List processes started by this server (and optionally every process on the Mac)."""
    rows = [f"{'pid':>7}  {'status':<12} {'age':>6}  cwd / command"]
    for p, s in sorted(PM.sessions.items()):
        rows.append(f"{p:>7}  {s.status():<12} {int(time.time() - s.started):>5}s  {s.cwd}$ {s.command[:100]}")
    if len(rows) == 1:
        rows.append("  (none)")
    if all_system:
        try:
            ps = subprocess.run(["ps", "-axo", "pid,ppid,%cpu,%mem,etime,command"], capture_output=True, text=True, timeout=10).stdout
            rows += ["", "system processes:", ps]
        except Exception as e:  # noqa: BLE001
            rows.append(f"ps failed: {e}")
    return finish("\n".join(rows))


@tool
def run_code(
    language: P[str, Field(description="python | node | shell")],
    code: P[str, Field(description="Source code to execute")],
    timeout_seconds: P[int, Field(description="Timeout in seconds")] = DEFAULT_TIMEOUT,
) -> str:
    """Execute a snippet without creating a file in the project: python, node or shell. Runs sandboxed."""
    lang = language.lower().strip()
    runners = {"python": ("python3", ".py"), "py": ("python3", ".py"), "node": ("node", ".js"), "javascript": ("node", ".js"),
               "js": ("node", ".js"), "shell": (SHELL, ".sh"), "bash": (SHELL, ".sh"), "zsh": (SHELL, ".sh"), "sh": (SHELL, ".sh")}
    if lang not in runners:
        return f"Error: unsupported language '{language}'. Use python, node or shell."
    exe, ext = runners[lang]
    scratch = WORKSPACE / ".tmp"
    scratch.mkdir(exist_ok=True)
    f = scratch / f"snippet_{int(time.time() * 1000)}_{secrets.token_hex(3)}{ext}"
    f.write_text(code, encoding="utf-8")
    try:
        return run_command(f"{shlex.quote(exe)} {shlex.quote(str(f))}", ".", timeout_seconds)  # type: ignore[misc]
    finally:
        try:
            f.unlink()
        except OSError:
            pass


# ---- files
def _read_text(target: Path, offset: int, length: int) -> str:
    size = target.stat().st_size
    if size > MAX_READ_BYTES:
        return f"Error: file is {size:,} bytes (> {MAX_READ_BYTES:,}). Use run_command with head/sed/grep to read parts."
    raw = target.read_bytes()
    if b"\x00" in raw[:8192]:
        return f"(binary file, {size:,} bytes, {target.suffix or 'no extension'}) — use run_command with xxd/file/strings to inspect."
    lines = raw.decode("utf-8", errors="replace").splitlines()
    total = len(lines)
    sel = lines[offset: offset + length] if length > 0 else lines[offset:]
    body = "\n".join(f"{i + offset + 1:>6}│ {ln}" for i, ln in enumerate(sel))
    more = f"\n... ({total - offset - len(sel)} more lines; next offset={offset + len(sel)})" if offset + len(sel) < total else ""
    return f"{rel(target)} — lines {offset + 1}-{offset + len(sel)} of {total}\n{body}{more}"


@tool
def read_file(
    path: P[str, Field(description="File path relative to the workspace")],
    offset: P[int, Field(description="Start line (0-based)")] = 0,
    length: P[int, Field(description="Max lines to return (0 = all, subject to output cap)")] = 500,
) -> str:
    """Read a text file with line numbers. Page large files with offset/length."""
    return finish(_read_text(safe_path(path, must_exist=True), max(0, offset), length))


@tool
def read_multiple_files(paths: P[list[str], Field(description="Workspace-relative file paths")]) -> str:
    """Read several files at once (first 200 lines each)."""
    out = []
    for p in paths[:20]:
        try:
            out.append(_read_text(safe_path(p, must_exist=True), 0, 200))
        except Exception as e:  # noqa: BLE001
            out.append(f"{p}: Error {e}")
    return finish("\n\n".join(out))


@tool
def write_file(
    path: P[str, Field(description="File path relative to the workspace; parent folders are created")],
    content: P[str, Field(description="Text content")],
    mode: P[str, Field(description="'rewrite' (default) or 'append'")] = "rewrite",
) -> str:
    """Create/overwrite (or append to) a text file inside the workspace."""
    target = safe_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a" if mode == "append" else "w", encoding="utf-8") as f:
        f.write(content)
    return f"{'Appended' if mode == 'append' else 'Wrote'} {len(content):,} chars ({content.count(chr(10)) + 1} lines) to {rel(target)}"


@tool
def edit_block(
    path: P[str, Field(description="File path relative to the workspace")],
    old_string: P[str, Field(description="Exact text to find (include enough context to be unique)")],
    new_string: P[str, Field(description="Replacement text")],
    expected_replacements: P[int, Field(description="How many occurrences you expect (safety check)")] = 1,
) -> str:
    """Surgical search-and-replace edit. Fails safely if the text isn't found or the count doesn't match,
    and shows the closest match so you can fix your old_string."""
    target = safe_path(path, must_exist=True)
    text = target.read_text(encoding="utf-8", errors="replace")
    count = text.count(old_string)
    if count == 0:
        # find closest region for a helpful error
        lines = text.splitlines()
        probe = old_string.strip().splitlines()[0] if old_string.strip() else ""
        best = difflib.get_close_matches(probe, lines, n=1, cutoff=0.5) if probe else []
        hint = ""
        if best:
            i = lines.index(best[0])
            ctx = "\n".join(lines[max(0, i - 3): i + 4])
            hint = f"\nClosest match near line {i + 1}:\n{ctx}"
        return f"Error: old_string not found in {rel(target)} (0 matches).{hint}"
    if count != expected_replacements:
        return f"Error: found {count} occurrences but expected {expected_replacements}. Add more context to old_string or set expected_replacements={count}."
    target.write_text(text.replace(old_string, new_string), encoding="utf-8")
    diff = "\n".join(difflib.unified_diff(old_string.splitlines(), new_string.splitlines(), "before", "after", lineterm="", n=1))
    return finish(f"Replaced {count} occurrence(s) in {rel(target)}\n{diff}")


@tool
def create_directory(path: P[str, Field(description="Folder path relative to the workspace")]) -> str:
    """Create a folder (and parents)."""
    t = safe_path(path)
    t.mkdir(parents=True, exist_ok=True)
    return f"Created {rel(t)}/"


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"


@tool
def list_directory(
    path: P[str, Field(description="Folder relative to the workspace")] = ".",
    depth: P[int, Field(description="Recursion depth (1 = just this folder, max 5)")] = 1,
    include_hidden: P[bool, Field(description="Include dotfiles")] = False,
) -> str:
    """List files and folders as a tree with sizes."""
    root = safe_path(path, must_exist=True)
    if not root.is_dir():
        return f"Error: {path} is not a directory"
    depth = max(1, min(depth, 5))
    rows: list[str] = [f"{rel(root)}/"]
    count = 0

    def walk(d: Path, lvl: int) -> None:
        nonlocal count
        try:
            kids = sorted(d.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower()))
        except PermissionError:
            return
        for c in kids:
            if not include_hidden and c.name.startswith("."):
                continue
            if c.name in ("node_modules", "__pycache__", ".git") and lvl > 0:
                rows.append("  " * (lvl + 1) + f"{c.name}/ (skipped)")
                continue
            count += 1
            if count > 2000:
                return
            if c.is_dir() and not c.is_symlink():
                rows.append("  " * (lvl + 1) + f"{c.name}/")
                if lvl + 1 < depth:
                    walk(c, lvl + 1)
            else:
                try:
                    size = _fmt_size(c.stat().st_size)
                except OSError:
                    size = "?"
                rows.append("  " * (lvl + 1) + f"{c.name}  ({size})")

    walk(root, 0)
    return finish("\n".join(rows))


@tool
def move_path(source: P[str, Field(description="Existing path")], destination: P[str, Field(description="New path")]) -> str:
    """Move or rename a file/folder inside the workspace."""
    src = safe_path(source, must_exist=True)
    dst = safe_path(destination)
    if dst.exists():
        return f"Error: destination {rel(dst)} already exists"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return f"Moved {rel(src)} -> {rel(dst)}"


@tool
def delete_path(path: P[str, Field(description="File or folder to delete (moved to workspace trash, not destroyed)")]) -> str:
    """Soft-delete: moves the path into .trash/<timestamp>/ inside the workspace so the user can recover it."""
    src = safe_path(path, must_exist=True)
    if src == WORKSPACE:
        return "Error: refusing to delete the workspace root"
    trash = WORKSPACE / ".trash" / datetime.now().strftime("%Y%m%d-%H%M%S")
    trash.mkdir(parents=True, exist_ok=True)
    dst = trash / src.name
    shutil.move(str(src), str(dst))
    return f"Moved {rel(src)} to trash: {rel(dst)}  (restore with move_path; empty .trash yourself when sure)"


@tool
def get_file_info(path: P[str, Field(description="Path relative to the workspace")]) -> str:
    """Size, type, permissions, timestamps and line count for a path."""
    t = safe_path(path, must_exist=True)
    st = t.lstat()
    kind = "symlink" if t.is_symlink() else "directory" if t.is_dir() else "file"
    info = [f"path: {rel(t)}", f"type: {kind}", f"size: {st.st_size:,} bytes", f"mode: {statmod.filemode(st.st_mode)}",
            f"modified: {datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')}",
            f"created: {datetime.fromtimestamp(getattr(st, 'st_birthtime', st.st_ctime)).isoformat(timespec='seconds')}"]
    if kind == "file" and st.st_size < MAX_READ_BYTES:
        raw = t.read_bytes()
        info.append("binary: yes" if b"\x00" in raw[:8192] else f"lines: {raw.count(b'\n') + (1 if raw and not raw.endswith(b'\n') else 0)}")
    return "\n".join(info)


# ---- search
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache", ".trash", ".tmp", "dist", "build", ".next"}


@tool
def search_files(
    pattern: P[str, Field(description="Glob or substring to match file NAMES, e.g. '*.py', 'config', 'test_*.ts'")],
    path: P[str, Field(description="Folder to search, relative to the workspace")] = ".",
    max_results: P[int, Field(description="Cap on results")] = 200,
) -> str:
    """Find files by name (case-insensitive glob/substring), skipping node_modules/.git/etc."""
    root = safe_path(path, must_exist=True)
    pat = pattern.lower()
    glob = any(ch in pat for ch in "*?[")
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames + dirnames:
            ln = name.lower()
            if (fnmatch.fnmatch(ln, pat) if glob else pat in ln):
                hits.append(rel(Path(dirpath) / name))
                if len(hits) >= max_results:
                    return finish("\n".join(hits) + f"\n... capped at {max_results}")
    return finish("\n".join(hits) if hits else "no matches")


@tool
def search_code(
    pattern: P[str, Field(description="Regex to search for inside files")],
    path: P[str, Field(description="Folder or file to search, relative to the workspace")] = ".",
    file_glob: P[Optional[str], Field(description="Only files matching this glob, e.g. '*.py'")] = None,
    case_sensitive: P[bool, Field(description="Case-sensitive match")] = False,
    max_results: P[int, Field(description="Cap on matching lines")] = 200,
    context_lines: P[int, Field(description="Lines of context around each match (0-5)")] = 0,
) -> str:
    """Search file CONTENTS with a regex (uses ripgrep when installed, else a built-in scanner)."""
    root = safe_path(path, must_exist=True)
    ctx = max(0, min(context_lines, 5))
    rg = shutil.which("rg")
    if rg:
        argv = [rg, "--line-number", "--no-heading", "--color", "never", "--max-count", "50", "-e", pattern]
        if not case_sensitive:
            argv.append("-i")
        if file_glob:
            argv += ["-g", file_glob]
        if ctx:
            argv += ["-C", str(ctx)]
        argv += [str(root)]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return "Error: search timed out"
        if r.returncode == 2 and r.stderr:
            return f"Error: {r.stderr.strip()}"
        lines = [ln.replace(str(root) + os.sep, "", 1) for ln in r.stdout.splitlines()]
        if len(lines) > max_results:
            lines = lines[:max_results] + [f"... capped at {max_results}"]
        return finish("\n".join(lines) if lines else "no matches")
    # fallback scanner
    try:
        rx = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
    except re.error as e:
        return f"Error: bad regex: {e}"
    out: list[str] = []
    files = [root] if root.is_file() else []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for n in filenames:
                if file_glob and not fnmatch.fnmatch(n, file_glob):
                    continue
                files.append(Path(dirpath) / n)
    for f in files:
        try:
            if f.stat().st_size > 2_000_000:
                continue
            raw = f.read_bytes()
            if b"\x00" in raw[:8192]:
                continue
            lines = raw.decode("utf-8", "replace").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            if rx.search(ln):
                lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
                for j in range(lo, hi):
                    out.append(f"{rel(f)}:{j + 1}:{'>' if j == i else ' '} {lines[j][:300]}")
                if ctx:
                    out.append("--")
                if len(out) >= max_results:
                    return finish("\n".join(out) + f"\n... capped at {max_results}")
    return finish("\n".join(out) if out else "no matches")


# ---- network (same allowlist as the sandbox)
@tool
def fetch_url(
    url: P[str, Field(description="http(s) URL on an allowlisted host")],
    max_bytes: P[int, Field(description="Max bytes to return")] = 200_000,
) -> str:
    """Fetch a URL (GET) through the same hostname allowlist the sandbox uses. Text only."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "Error: need an http(s) URL"
    port = u.port or (443 if u.scheme == "https" else 80)
    if not POLICY.allowed(u.hostname, port):
        audit("net.denied", host=u.hostname, port=port, method="fetch_url")
        return f"Error: {u.hostname} is not on the network allowlist (see agent_info)"
    audit("net.allowed", host=u.hostname, port=port, method="fetch_url")
    req = urllib.request.Request(url, headers={"User-Agent": f"agent-mcp/{__version__}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # direct; we did the allow check
    with opener.open(req, timeout=30) as resp:
        ctype = resp.headers.get("Content-Type", "")
        data = resp.read(min(max_bytes, 5_000_000) + 1)
        more = len(data) > max_bytes
        data = data[:max_bytes]
        if "text" not in ctype and "json" not in ctype and "xml" not in ctype and b"\x00" in data[:4096]:
            return f"{resp.status} {ctype}: binary content ({len(data):,}+ bytes) — download it with run_command + curl instead."
        return finish(f"{resp.status} {ctype} ({len(data):,} bytes{'+' if more else ''})\n" + data.decode("utf-8", "replace"))


# ============================================================================ doctor
def doctor() -> int:
    global PROXY
    print(f"agent-mcp v{__version__} doctor — {platform.platform()}")
    print(f"workspace: {WORKSPACE}\nsandbox:   {SANDBOX_MODE}\n{POLICY.describe()}\n")
    if SANDBOX_MODE != "seatbelt":
        print("!! sandbox is OFF — the isolation tests below will FAIL by design. Only use this on Linux for development.\n")
    PROXY = AllowlistProxy(POLICY).start_and_wait()
    results: list[tuple[str, bool, bool, str]] = []  # name, required, passed, detail

    def t(name: str, cmd: str, expect_ok: bool = True, required: bool = True, timeout: int = 60, contains: str = "") -> None:
        s = PM.start(cmd, ".")
        PM.wait(s, timeout)
        out = s.new_output().strip()
        if s.exit_code is None:
            PM.kill(s.pid)
        ok = (s.exit_code == 0) == expect_ok and (contains in out if contains else True)
        results.append((name, required, ok, (out.splitlines() or ["(no output)"])[-1][:120]))
        print(f"  {'PASS' if ok else 'FAIL'}{'' if required else ' (optional)'}  {name}")

    if SANDBOX_MODE == "seatbelt":
        r = subprocess.run(["/usr/bin/sandbox-exec", "-p", build_profile(PROXY.port), "/usr/bin/true"], capture_output=True, text=True)
        ok = r.returncode == 0
        results.append(("seatbelt profile compiles", True, ok, r.stderr.strip()[:300]))
        print(f"  {'PASS' if ok else 'FAIL'}  seatbelt profile compiles")
        if not ok:
            print("     " + r.stderr.strip())
    t("shell runs", "echo ok", contains="ok")
    t("python3 available", "python3 -c 'print(6*7)'", contains="42")
    t("node available", "node -e 'console.log(6*7)'", required=False, contains="42")
    t("git available", "git --version", required=False)
    t("write inside workspace", "echo hi > .doctor_probe && cat .doctor_probe && rm .doctor_probe", contains="hi")
    t("read system files", "ls /usr/bin > /dev/null && echo ok", contains="ok")
    t("BLOCK write outside workspace", "touch ~/agent_mcp_doctor_should_not_exist", expect_ok=False)
    t("BLOCK read home folder", "ls ~/Library", expect_ok=False)
    t("BLOCK read ~/.ssh", "ls -a ~/.ssh", expect_ok=False)
    t("BLOCK osascript", "osascript -e 'return 1'", expect_ok=False)
    t("BLOCK open", "open -a Calculator", expect_ok=False)
    t("BLOCK direct network (bypass proxy)", "curl -sS --noproxy '*' -m 8 https://pypi.org/ -o /dev/null", expect_ok=False)
    t("ALLOW network to allowlisted host via proxy", "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/simple/pip/", contains="200")
    t("BLOCK network to non-allowlisted host", "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/", expect_ok=False, contains="403")
    t("pip can install into a workspace venv", "python3 -m venv .doctor_venv && .doctor_venv/bin/pip -q install six && echo ok && rm -rf .doctor_venv",
      required=False, timeout=180, contains="ok")
    Path(HOME / "agent_mcp_doctor_should_not_exist").unlink(missing_ok=True)
    print()
    failed = [r for r in results if r[1] and not r[2]]
    for name, req, ok, detail in results:
        if not ok:
            print(f"  {name}: {detail}")
    if failed:
        print(f"\n{len(failed)} required check(s) FAILED. Do not use this server until they pass.")
        if SANDBOX_MODE == "seatbelt":
            print("Debug sandbox denials with:  log show --last 5m --style compact --predicate 'process == \"sandboxd\" OR sender == \"Sandbox\"' | grep -i deny")
        return 1
    print("All required checks passed. Sandbox is enforcing the policy on this Mac.")
    return 0


def print_policy() -> None:
    print(json.dumps({
        "version": __version__, "workspace": str(WORKSPACE), "sandbox": SANDBOX_MODE, "shell": SHELL,
        "network": {"enabled": POLICY.enabled, "ports": sorted(POLICY.ports), "hosts": NET_ALLOW},
        "extra_read": EXTRA_READ, "extra_write": EXTRA_WRITE, "pass_env": PASS_ENV,
        "limits": {"default_timeout": DEFAULT_TIMEOUT, "max_timeout": MAX_TIMEOUT, "max_output_chars": MAX_OUTPUT_CHARS,
                   "max_sessions": MAX_SESSIONS},
        "audit_log": str(_AUDIT_FILE),
    }, indent=2))


# ============================================================================ main
def main() -> None:
    global PROXY
    if sys.version_info < (3, 10):
        sys.exit("agent-mcp needs Python 3.10+ (brew install python)")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "print-profile":
        print(build_profile(0))
        return
    if cmd == "print-policy":
        print_policy()
        return
    check_sandbox_available()
    if cmd == "doctor":
        sys.exit(doctor())
    if cmd != "serve":
        sys.exit(f"unknown subcommand {cmd!r} (serve | doctor | print-profile | print-policy)")
    if POLICY.enabled:
        PROXY = AllowlistProxy(POLICY).start_and_wait()
        log.info("allowlist proxy on 127.0.0.1:%d", PROXY.port)
    audit("server.start", version=__version__, workspace=str(WORKSPACE), sandbox=SANDBOX_MODE, net=POLICY.describe())
    try:
        mcp.run()  # stdio
    finally:
        PM.kill_all()
        audit("server.stop")


if __name__ == "__main__":
    main()
