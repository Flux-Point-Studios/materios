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
  --full|--all)
    bash "$zk_plugin_root/scripts/py.sh" specification.py --check
    nice -n 10 python3 -m unittest discover -s tools/zk-spec -p 'test_*.py'
    zk_phase_args=()
    if [ "${1:---full}" = --all ]; then
      zk_phase_args+=(--all)
    else
      if [ -n "${FPL_DIFF_BASE:-}" ]; then
        zk_diff_base="$(git rev-parse --verify --end-of-options "${FPL_DIFF_BASE}^{commit}")"
      else
        zk_diff_base="$(git merge-base HEAD origin/main)"
      fi
      zk_paths=(':(top,glob)tools/zk-spec/**' ':(top,literal).fluxpoint-spec.json' ':(top,literal).fluxpoint-spec-lock.json')
      zk_diff_status=0
      git diff --quiet --no-ext-diff --no-renames "$zk_diff_base" -- "${zk_paths[@]}" || zk_diff_status=$?
      if [ "$zk_diff_status" -gt 1 ]; then exit "$zk_diff_status"; fi
      zk_untracked="$(git ls-files --others --exclude-standard -- "${zk_paths[@]}")"
      if [ "$zk_diff_status" -eq 0 ] && [ -z "$zk_untracked" ]; then
        echo "harness: base=$zk_diff_base; P0 phase checks were not selected"
        exit 0
      fi
    fi
    nice -n 10 python3 tools/zk-spec/phases.py "${zk_phase_args[@]}"
    ;;
  *)
    echo 'usage: scripts/harness.sh --spec-check|--full|--all' >&2
    exit 2
    ;;
esac
