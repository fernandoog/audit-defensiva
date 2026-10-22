# shellcheck shell=bash
# Biblioteca común para auditorías defensivas (source desde otros scripts).
# No ejecutar directamente.

: "${AUDIT_VERSION:=1.1.0}"

PASS=0
WARN=0
FAIL=0
INFO=0
RESULTS=()

record() {
  local status="$1" code="$2" msg="$3"
  RESULTS+=("${status}|${code}|${msg}")
  case "$status" in
    PASS) PASS=$((PASS + 1)) ;;
    WARN) WARN=$((WARN + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
    INFO) INFO=$((INFO + 1)) ;;
  esac
  printf '[%s] %s — %s\n' "$status" "$code" "$msg"
}

section() {
  printf '\n== %s ==\n' "$1"
}

have() { command -v "$1" >/dev/null 2>&1; }

audit_write_json() {
  local out="$1" host="$2" stamp="$3"
  {
    echo '{'
    echo "  \"version\": \"${AUDIT_VERSION}\","
    echo "  \"host\": \"${host}\","
    echo "  \"generated_at\": \"${stamp}\","
    echo "  \"summary\": {\"pass\": ${PASS}, \"warn\": ${WARN}, \"fail\": ${FAIL}, \"info\": ${INFO}},"
    echo '  "results": ['
    local i=0 total=${#RESULTS[@]}
    for item in "${RESULTS[@]}"; do
      local st code msg rest
      st="${item%%|*}"
      rest="${item#*|}"
      code="${rest%%|*}"
      msg="${rest#*|}"
      msg="${msg//\\/\\\\}"
      msg="${msg//\"/\\\"}"
      printf '    {"status":"%s","code":"%s","message":"%s"}' "$st" "$code" "$msg"
      i=$((i + 1))
      if [[ $i -lt $total ]]; then echo ','; else echo; fi
    done
    echo '  ]'
    echo '}'
  } > "$out"
}

audit_exit_code() {
  if [[ "$FAIL" -gt 0 ]]; then return 2; fi
  if [[ "$WARN" -gt 0 ]]; then return 1; fi
  return 0
}

audit_summary() {
  section "Resumen"
  printf 'PASS=%s WARN=%s FAIL=%s INFO=%s\n' "$PASS" "$WARN" "$FAIL" "$INFO"
  if [[ "$FAIL" -gt 0 ]]; then
    echo "Veredicto: hay hallazgos críticos (FAIL). Prioriza corregirlos."
  elif [[ "$WARN" -gt 0 ]]; then
    echo "Veredicto: sin FAIL, pero hay advertencias a revisar."
  else
    echo "Veredicto: sin FAIL/WARN en las comprobaciones automatizadas."
  fi
}
