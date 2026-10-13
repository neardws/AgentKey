#!/bin/bash
# Build release binaries, install to ~/.local/bin, and load the agentkeyd LaunchAgent.
#
#   ./Support/install-launchagent.sh                       # normal device
#   ./Support/install-launchagent.sh --sync-node           # home node (e.g. Mac mini): TCP 7373 + Bonjour _agentkey._tcp
#   ./Support/install-launchagent.sh --sync-node --no-bonjour [--sync-port 7373] [--host mini.tailnet.ts.net]
set -euo pipefail
cd "$(dirname "$0")/.."

EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --sync-node|--no-bonjour) EXTRA+=("$1"); shift ;;
    --sync-port|--sync-host|--host|--sync-interval) EXTRA+=("$1" "$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

swift build -c release
BIN="$HOME/.local/bin"; mkdir -p "$BIN" "$HOME/Library/Logs/AgentKey" "$HOME/Library/LaunchAgents"
for b in agentkeyd agentkey agentkey-mcp; do install -m 0755 ".build/release/$b" "$BIN/$b"; done
ln -sf "$BIN/agentkey" "$BIN/ak"

ARGS_XML=""
for a in "${EXTRA[@]+"${EXTRA[@]}"}"; do ARGS_XML+="<string>${a}</string>"; done
PLIST="$HOME/Library/LaunchAgents/com.neardws.agentkey.agentkeyd.plist"
sed -e "s#__AGENTKEYD__#$BIN/agentkeyd#" -e "s#__HOME__#$HOME#g" -e "s#<!--__SYNC_NODE_ARGS__-->#${ARGS_XML}#" \
    Support/com.neardws.agentkey.agentkeyd.plist > "$PLIST"
plutil -lint "$PLIST" >/dev/null 2>&1 || { echo "generated plist is invalid: $PLIST" >&2; exit 1; }
launchctl bootout "gui/$(id -u)/com.neardws.agentkey.agentkeyd" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Installed. Binaries in $BIN (add it to PATH). Logs: ~/Library/Logs/AgentKey/agentkeyd.log"
[ ${#EXTRA[@]} -gt 0 ] && echo "agentkeyd arguments: ${EXTRA[*]}"
echo "Next: agentkey init && agentkey unlock && agentkey status"
if [[ " ${EXTRA[*]-} " == *" --sync-node "* ]]; then
  echo "Home node: the first Bonjour advertise may trigger macOS's Local Network prompt (System Settings → Privacy & Security → Local Network)."
  echo "--sync-node needs an existing vault (agentkey init); then: agentkey device pair"
fi
