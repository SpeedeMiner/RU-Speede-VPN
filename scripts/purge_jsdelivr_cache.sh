#!/usr/bin/env bash
set -euo pipefail

base='/gh/SpeedeMiner/RU-Speede-VPN@main'
body=$(mktemp)
trap 'rm -f "$body"' EXIT
result=0

for file in "$@"; do
  path="$base/$file"
  if http=$(curl --silent --show-error --fail-with-body \
      --retry 3 --retry-delay 2 --retry-connrefused --retry-max-time 30 \
      --connect-timeout 5 --max-time 12 \
      --output "$body" --write-out '%{http_code}' "https://purge.jsdelivr.net$path") \
      && [[ $http == 2[0-9][0-9] ]]; then
    if python3 - "$body" "$path" <<'PY'
import json
import sys
from pathlib import Path

try:
    response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    path_result = response["paths"][sys.argv[2]]
    providers = path_result["providers"]
    confirmed = (
        response["status"] == "finished"
        and path_result["throttled"] is False
        and isinstance(providers, dict)
        and bool(providers)
        and all(status is True for status in providers.values())
    )
except (OSError, ValueError, KeyError, TypeError):
    confirmed = False
sys.exit(0 if confirmed else 1)
PY
    then
      printf 'jsDelivr confirmed purge for %s (HTTP %s)\n' "$file" "$http"
      continue
    fi
    printf '::warning::jsDelivr did not confirm purge for %s (HTTP %s)\n' "$file" "$http"
  else
    printf '::warning::jsDelivr purge request failed for %s (HTTP %s)\n' "$file" "${http:-000}"
  fi
  result=1
done
exit "$result"
