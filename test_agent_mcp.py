"""Integration tests for agent-mcp (run on any OS with AGENT_SANDBOX=off; seatbelt is validated by `doctor` on a Mac)."""
import asyncio
import http.server
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).parent
WS = Path(tempfile.mkdtemp(prefix="agentws_"))
for _k in ("no_proxy","NO_PROXY"): os.environ.pop(_k, None)
os.environ.update({
    "AGENT_WORKSPACE": str(WS), "AGENT_SANDBOX": "off", "AGENT_LOG_DIR": str(WS.parent / "agent_logs"),
    "AGENT_NET_ALLOW_ONLY": "localhost,allowed.example", "AGENT_NET_PORTS": "80,443,18080",
})
sys.path.insert(0, str(ROOT))
import agent_mcp_server as S  # noqa: E402

PASSED = 0


def check(name, cond, detail=""):
    global PASSED
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail[:200]}" if (detail and not cond) else ""))
    if cond:
        PASSED += 1
    else:
        raise SystemExit(f"FAILED: {name}\n{detail}")


# ---------------------------------------------------------------- local upstream for proxy tests
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"upstream-ok:" + self.path.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), H)
threading.Thread(target=upstream.serve_forever, daemon=True).start()

print("\n== network policy")
pol = S.POLICY
check("allow exact host", pol.allowed("localhost", 18080))
check("deny other host", not pol.allowed("evil.example", 443))
check("deny other port", not pol.allowed("localhost", 2222))
w = S.NetPolicy(["*.github.com", "pypi.org"], {443}, True)
check("wildcard subdomain", w.allowed("api.github.com", 443) and not w.allowed("github.com", 443) and not w.allowed("notgithub.com", 443))
check("trailing dot / case", w.allowed("PYPI.ORG.", 443))

print("\n== proxy")
S.PROXY = S.AllowlistProxy(pol).start_and_wait()
px = S.PROXY
curl = shutil.which("curl")
r = subprocess.run([curl, "-sS", "-x", px.url, "http://localhost:18080/hello"], capture_output=True, text=True)
check("HTTP GET via proxy to allowed host", r.stdout == "upstream-ok:/hello", r.stdout + r.stderr)
r = subprocess.run([curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-x", px.url, "http://evil.example/"], capture_output=True, text=True)
check("HTTP GET to denied host -> 403", r.stdout == "403", r.stdout + r.stderr)
r = subprocess.run([curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"http://127.0.0.1:{px.port}", "http://localhost:18080/"], capture_output=True, text=True)
check("missing proxy token -> 407", r.stdout == "407", r.stdout + r.stderr)
r = subprocess.run([curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-x", px.url, "https://evil.example/"], capture_output=True, text=True)
check("CONNECT to denied host refused", r.returncode != 0 or r.stdout in ("403", "000"), r.stdout + r.stderr)
# CONNECT to allowed host (tunnel plain HTTP through CONNECT to prove the tunnel works)
def raw_connect():
    s = socket.create_connection(("127.0.0.1", px.port), 5)
    s.sendall(f"CONNECT localhost:18080 HTTP/1.1\r\nHost: localhost:18080\r\nProxy-Authorization: {px._expected_auth}\r\n\r\n".encode())
    head = s.recv(4096)
    assert b"200 Connection Established" in head, head
    s.sendall(b"GET /tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
    return data
check("CONNECT tunnel to allowed host", b"upstream-ok:/tunnel" in raw_connect())

print("\n== seatbelt profile generation")
prof = S.build_profile(px.port)
check("profile has deny default", prof.startswith("(version 1)\n(deny default)"))
check("profile confines writes to workspace", f'(allow file-write* (subpath "{WS}")' in prof)
check("profile denies home reads", '(require-not (subpath "/Users"))' in prof)
check("profile denies osascript", '(require-not (literal "/usr/bin/osascript"))' in prof)
check("profile allows only proxy port outbound", f'localhost:{px.port}' in prof and "remote ip \"*" not in prof)
check("profile denies secret dirs", '.ssh' in prof and 'Library/Keychains' in prof)
check("profile parens balanced", prof.count("(") == prof.count(")"))

print("\n== child env hygiene")
os.environ["OPENAI_API_KEY"] = "sk-shouldnotleak-000000000000000000000000"
env = S.child_env()
check("host secrets not passed to child", "OPENAI_API_KEY" not in env)
check("proxy vars set", env["HTTPS_PROXY"] == px.url and env["NO_PROXY"].startswith("localhost"))
check("caches redirected into workspace", env["PIP_CACHE_DIR"].startswith(str(WS)))

print("\n== redaction")
check("redacts keys", "[REDACTED]" in S.redact("token ghp_" + "a" * 36 + " and AKIAABCDEFGHIJKLMNOP") and "AKIA" not in S.redact("AKIAABCDEFGHIJKLMNOP"))
check("leaves normal text", S.redact("hello world 12345") == "hello world 12345")

print("\n== path safety")
(WS / "sub").mkdir()
os.symlink("/etc", WS / "sub" / "evil_link")
for bad in ["../x", "/etc/passwd", "sub/evil_link/passwd", "~/x", str(WS.parent / "y")]:
    try:
        S.safe_path(bad); ok = False
    except PermissionError:
        ok = True
    check(f"reject {bad}", ok)
check("accept workspace root", S.safe_path(".") == WS)

# unwrap tools: the decorator returned the MCP-registered wrapper; call underlying via __wrapped__ when needed
T = {n: getattr(S, n) for n in ["run_command", "start_process", "read_output", "send_input", "kill_process", "list_processes",
                                "run_code", "read_file", "read_multiple_files", "write_file", "edit_block", "create_directory",
                                "list_directory", "move_path", "delete_path", "get_file_info", "search_files", "search_code",
                                "fetch_url", "agent_info"]}
def call(name, *a, **kw):
    fn = T[name]
    if not callable(fn):  # some SDK versions return a Tool object
        fn = getattr(fn, "fn", None) or getattr(fn, "__wrapped__")
    return fn(*a, **kw)

print("\n== commands")
out = call("run_command", "echo hello && pwd")
check("run_command output + cwd", "hello" in out and str(WS) in out and "exited (0)" in out, out)
out = call("run_command", "exit 3")
check("exit code reported", "exited (3)" in out, out)
out = call("run_command", "sleep 30", timeout_seconds=1)
m = re.search(r"\[pid (\d+)\] running", out)
check("timeout returns running pid", bool(m), out)
pid = int(m.group(1))
out = call("kill_process", pid)
check("kill_process works", "terminated" in out, out)
out = call("run_command", "ls", cwd="../..")
check("cwd escape rejected", "outside the workspace" in out, out)
out = call("run_command", "python3 -c \"print('x'*100000)\"")
check("output truncated with notice", "chars omitted" in out and len(out) < 40000, str(len(out)))

print("\n== interactive session (python REPL)")
out = call("start_process", "python3 -i -q", wait_seconds=1.5)
pid = int(re.search(r"\[pid (\d+)\]", out).group(1))
out = call("send_input", pid, "print(21*2)", wait_seconds=1.5)
check("REPL responds", "42" in out, out)
out = call("send_input", pid, "import time; time.sleep(1); print('late')", wait_seconds=0.1)
out2 = call("read_output", pid, timeout_seconds=5, wait_for="late")
check("read_output wait_for regex", "late" in out2, out + out2)
out = call("send_input", pid, "exit()", wait_seconds=1.5)
check("REPL exits", "exited (0)" in out, out)
out = call("list_processes")
check("list_processes shows session", str(pid) in out, out)

print("\n== run_code")
out = call("run_code", "python", "import sys; print(sys.version_info[0])")
check("run_code python", "3" in out and "exited (0)" in out, out)
out = call("run_code", "shell", "echo $AGENT_WORKSPACE")
check("run_code shell sees workspace env", str(WS) in out, out)
check("snippet cleaned up", not list((WS / ".tmp").glob("snippet_*")))

print("\n== files")
out = call("write_file", "a/b/notes.md", "line1\nline2\nline3\n")
check("write_file creates parents", "Wrote" in out and (WS / "a/b/notes.md").exists(), out)
out = call("write_file", "a/b/notes.md", "line4\n", mode="append")
check("append", (WS / "a/b/notes.md").read_text().endswith("line4\n"))
out = call("read_file", "a/b/notes.md", offset=1, length=2)
check("read_file paging", "2│ line2" in out and "3│ line3" in out and "next offset=3" in out, out)
out = call("edit_block", "a/b/notes.md", "line2", "LINE2")
check("edit_block replaces", "Replaced 1" in out and "LINE2" in (WS / "a/b/notes.md").read_text(), out)
out = call("edit_block", "a/b/notes.md", "line", "x")
check("edit_block count mismatch is safe", "found 3 occurrences but expected 1" in out and "LINE2" in (WS / "a/b/notes.md").read_text(), out)
out = call("edit_block", "a/b/notes.md", "lin3", "x")
check("edit_block not-found shows closest", "not found" in out and "Closest match" in out, out)
out = call("create_directory", "d1/d2")
check("create_directory", (WS / "d1/d2").is_dir())
out = call("list_directory", ".", depth=3)
check("list_directory tree", "a/" in out and "notes.md" in out and "d2/" in out, out)
out = call("move_path", "a/b/notes.md", "d1/notes.md")
check("move_path", (WS / "d1/notes.md").exists() and not (WS / "a/b/notes.md").exists(), out)
out = call("get_file_info", "d1/notes.md")
check("get_file_info", "lines: 4" in out and "type: file" in out, out)
out = call("delete_path", "d1/notes.md")
check("delete_path is soft", "trash" in out and list((WS / ".trash").rglob("notes.md")), out)
out = call("delete_path", ".")
check("refuse to delete root", "refusing" in out, out)
out = call("read_multiple_files", ["d1", "nope.txt"])
check("read_multiple_files tolerant", "Error" in out, out)
(WS / "bin.dat").write_bytes(b"\x00\x01\x02")
out = call("read_file", "bin.dat")
check("binary detection", "binary file" in out, out)

print("\n== search")
(WS / "src").mkdir(); (WS / "src/app.py").write_text("def main():\n    return 'Hello'\n"); (WS / "src/util.ts").write_text("export const hello = 1;\n")
(WS / "node_modules").mkdir(); (WS / "node_modules/x.py").write_text("hello")
out = call("search_files", "*.py")
check("search_files glob skips node_modules", "src/app.py" in out and "node_modules" not in out, out)
out = call("search_code", "hello", ".")
check("search_code case-insensitive", "src/app.py:2" in out and "src/util.ts:1" in out, out)
out = call("search_code", "hello", ".", file_glob="*.ts", case_sensitive=True)
check("search_code glob + case", "util.ts" in out and "app.py" not in out, out)

print("\n== fetch_url")
out = call("fetch_url", "http://localhost:18080/fetched")
check("fetch_url allowed host", "upstream-ok:/fetched" in out, out)
out = call("fetch_url", "https://evil.example/x")
check("fetch_url denied host", "not on the network allowlist" in out, out)

print("\n== agent_info + audit")
out = call("agent_info")
check("agent_info", str(WS) in out and "network:" in out, out)
audit = Path(os.environ["AGENT_LOG_DIR"]) / "audit.jsonl"
check("audit log written outside workspace", audit.exists() and "net.denied" in audit.read_text() and not str(audit).startswith(str(WS)))

print("\n== MCP protocol round-trip (real stdio client)")
async def rt():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    p = StdioServerParameters(command=sys.executable, args=[str(ROOT / "agent_mcp_server.py")],
                              env={**{k: v for k, v in os.environ.items() if k.startswith("AGENT_")}, "PATH": os.environ["PATH"], "HOME": os.environ["HOME"]})
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            res = await s.call_tool("run_command", {"command": "echo via-mcp"})
            res2 = await s.call_tool("write_file", {"path": "mcp.txt", "content": "hi"})
            return names, res.content[0].text, res2.content[0].text
names, txt, txt2 = asyncio.run(rt())
check("all 20 tools registered", len(names) == 20, str(names))
check("run_command over MCP", "via-mcp" in txt and "exited (0)" in txt, txt)
check("write_file over MCP", (WS / "mcp.txt").read_text() == "hi", txt2)

upstream.shutdown()
print(f"\nALL {PASSED} CHECKS PASSED")
