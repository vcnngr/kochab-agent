#!/usr/bin/env bash
# check-coverage.sh — coverage threshold gate per package.
# See kochab-platform/scripts/check-coverage.sh header for rationale.

set -eu

floor_for() {
  case "$1" in
    pkg/protocol) echo 95 ;;
    internal/executor) echo 88 ;;
    internal/agent) echo 75 ;;
    internal/enrollment) echo 72 ;;
    internal/profiler) echo 70 ;;
    internal/transport) echo 68 ;;
    *) echo "" ;;
  esac
}

echo "Running coverage..."
go test -cover ./... > /tmp/kochab-agent-cov.txt 2>&1 || true

fail_count=0
while read -r line; do
  pkg=$(echo "$line" | awk '{print $2}' | sed 's|github.com/kochab-ai/kochab-agent/||')
  cov=$(echo "$line" | awk '{print $5}' | tr -d '%')
  [ -z "$pkg" ] && continue
  [ -z "$cov" ] && continue
  floor=$(floor_for "$pkg")
  cov_int=${cov%.*}
  if [ -z "$floor" ]; then
    printf "  %-30s %s%% (no floor)\n" "$pkg" "$cov"
    continue
  fi
  if [ "$cov_int" -lt "$floor" ]; then
    printf "❌ %-30s %s%% < floor %s%%\n" "$pkg" "$cov" "$floor"
    fail_count=$((fail_count + 1))
  else
    printf "✅ %-30s %s%% (floor %s%%)\n" "$pkg" "$cov" "$floor"
  fi
done < <(grep -E "^ok\s" /tmp/kochab-agent-cov.txt | grep "coverage:")

if [ "$fail_count" -gt 0 ]; then
  echo ""
  echo "FAIL: $fail_count package(s) below coverage floor."
  exit 1
fi

echo ""
echo "OK: all packages meet coverage floors."
