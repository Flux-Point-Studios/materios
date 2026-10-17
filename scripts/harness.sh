#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

zk_plugin_root="${FPL_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-$HOME/.claude/plugins/cache/fluxpoint/fluxpoint/1.42.0}}}"
if [ ! -f "$zk_plugin_root/scripts/py.sh" ] || [ ! -f "$zk_plugin_root/scripts/specification.py" ]; then
  echo 'harness: required specification runner missing; no checks passed' >&2
  exit 1
fi

case "${1:---full}" in
  --spec-check)
    bash "$zk_plugin_root/scripts/py.sh" specification.py --check
    ;;
  --full)
    # This is the specification gate in the FluxPoint 1.42.0 template.
    bash "$zk_plugin_root/scripts/py.sh" specification.py --run --if-present
    zk_adapter_relative="$(realpath --relative-to="$zk_plugin_root/scripts" tools/zk-spec/test_adapter.py)"
    nice -n 10 bash "$zk_plugin_root/scripts/py.sh" "$zk_adapter_relative"
    ;;
  *)
    echo 'usage: scripts/harness.sh --spec-check|--full' >&2
    exit 2
    ;;
esac
