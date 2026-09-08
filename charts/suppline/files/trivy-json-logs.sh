#!/bin/sh
# Keep in sync with scripts/trivy-json-logs.sh
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

exec 3>&1
set -o pipefail
trivy "$@" 2>&1 1>&3 | while IFS= read -r line || [ -n "$line" ]; do
  emit_json "$line"
done
