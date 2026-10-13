#!/bin/bash
# Build release binaries, install to ~/.local/bin, and load the agentkeyd LaunchAgent.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release
BIN="$HOME/.local/bin"; mkdir -p "$BIN" "$HOME/Library/Logs/AgentKey" "$HOME/Library/LaunchAgents"
for b in agentkeyd agentkey agentkey-mcp; do install -m 0755 ".build/release/$b" "$BIN/$b"; done
ln -sf "$BIN/agentkey" "$BIN/ak"
PLIST="$HOME/Library/LaunchAgents/com.neardws.agentkey.agentkeyd.plist"
sed -e "s#__AGENTKEYD__#$BIN/agentkeyd#" -e "s#__HOME__#$HOME#g" Support/com.neardws.agentkey.agentkeyd.plist > "$PLIST"
launchctl bootout "gui/$(id -u)/com.neardws.agentkey.agentkeyd" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Installed. Binaries in $BIN (add it to PATH). Logs: ~/Library/Logs/AgentKey/agentkeyd.log"
echo "Next: agentkey init && agentkey unlock && agentkey status"
