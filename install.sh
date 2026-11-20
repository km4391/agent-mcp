#!/bin/zsh
# One-shot installer for agent-mcp on macOS. Safe to re-run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="$HOME/.agent-mcp"
WS="${AGENT_WORKSPACE:-$HOME/AgentWorkspace}"

PY="$(command -v python3.13 || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  echo "Need Python 3.10+. Install with:  brew install python"; exit 1
fi
[ -x /usr/bin/sandbox-exec ] || { echo "sandbox-exec not found — this installer is for macOS."; exit 1; }

echo "→ creating venv at $VENV with $PY"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip "mcp[cli]"
mkdir -p "$WS"

cat > "$HERE/mcp-config.json" <<JSON
{
  "mcpServers": {
    "agent-mcp": {
      "command": "$VENV/bin/python",
      "args": ["$HERE/agent_mcp_server.py"],
      "env": { "AGENT_WORKSPACE": "$WS" }
    }
  }
}
JSON

echo
echo "→ running doctor (validates the sandbox on this Mac)"
AGENT_WORKSPACE="$WS" "$VENV/bin/python" "$HERE/agent_mcp_server.py" doctor || {
  echo; echo "Doctor reported failures. Fix them before connecting an agent."; exit 1; }

echo
echo "✓ Installed. Paste the contents of $HERE/mcp-config.json into your MCP client:"
echo "   Claude Desktop: Settings → Developer → Edit Config  (~/Library/Application Support/Claude/claude_desktop_config.json)"
echo "   LM Studio:      Program → Install → Edit mcp.json"
echo "   Cursor/Cline/Goose: their MCP settings use the same JSON shape"
echo "Then restart the app and ask it to run: agent_info"
