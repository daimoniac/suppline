#!/bin/sh
# Keep in sync with charts/suppline/files/trivy-json-logs.sh
# Convert Trivy text logs on stderr into slog-style JSON so compose/Helm
# output matches suppline. Image digest is attached by the suppline client
# when it relays CLI stderr; the server process does not know the image ref.
set -eu

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

strip_ansi() {
  printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r'
}

emit_json() {
  line=$(strip_ansi "$1")
  [ -n "$line" ] || return 0

  old_ifs=$IFS
  set -f
  IFS='	'
  # shellcheck disable=SC2086
  set -- $line
  set +f
  IFS=$old_ifs

  if [ "$#" -lt 3 ]; then
    printf '{"time":"","level":"INFO","msg":"%s"}\n' "$(json_escape "$line")"
    return 0
  fi

  ts=$1
  level=$2
  shift 2
  msg=$1
  shift
  attrs=""
  if [ "$#" -gt 0 ]; then
    attrs=$*
  fi

  prefix=""
  case "$msg" in
    \[*\]*)
      prefix=${msg#\[}
      prefix=${prefix%%]*}
      msg=${msg#*]}
      msg=${msg# }
      ;;
  esac

  printf '{"time":"%s","level":"%s","msg":"%s"' \
    "$(json_escape "$ts")" "$(json_escape "$level")" "$(json_escape "$msg")"
  if [ -n "$prefix" ]; then
    printf ',"trivy_prefix":"%s"' "$(json_escape "$prefix")"
  fi
  if [ -n "$attrs" ]; then
    printf ',"trivy_attrs":"%s"' "$(json_escape "$attrs")"
  fi
  printf '}\n'
}

fifo="${TMPDIR:-/tmp}/trivy-json-logs.fifo"
rm -f "$fifo"
mkfifo "$fifo"

# Format Trivy's stderr from a background reader over a FIFO rather than a
# pipeline: a pipeline hides Trivy's PID, and a PID 1 shell without a trap
# ignores SIGTERM, so Trivy would only ever die from the post-grace SIGKILL.
while IFS= read -r line || [ -n "$line" ]; do
  emit_json "$line"
done <"$fifo" &
formatter_pid=$!

trivy "$@" 2>"$fifo" &
trivy_pid=$!

trap 'kill -TERM "$trivy_pid" 2>/dev/null || true' TERM INT HUP

# wait returns early whenever a trapped signal arrives, so keep waiting until
# Trivy is really gone, then drain the formatter and report Trivy's own status.
rc=0
while :; do
  wait "$trivy_pid" && rc=0 || rc=$?
  kill -0 "$trivy_pid" 2>/dev/null || break
done

wait "$formatter_pid" 2>/dev/null || true
exit "$rc"
