#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-https://mllabapi.snu.ac.kr/api/last_submission}"
PAGE_SIZE="${PAGE_SIZE:-10}"
TARGET_TEAM="${TARGET_TEAM:-team28}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 2
fi

page=1

while :; do
  response="$(
    curl -fsS \
      --get "$API_URL" \
      --data-urlencode "page=${page}" \
      --data-urlencode "page_size=${PAGE_SIZE}"
  )"

  parsed="$(
    TARGET_TEAM="$TARGET_TEAM" python3 -c '''
import json
import os
import re
import sys

target = re.sub(r"\s+", "", os.environ["TARGET_TEAM"]).lower()
data = json.load(sys.stdin)

for item in data.get("results", []):
    team = str(item.get("team", ""))
    if re.sub(r"\s+", "", team).lower() == target:
        print(
            "MATCH\t{}\t{}\t{}\t{}\t{}".format(
                team,
                item.get("score", ""),
                item.get("timestamp", ""),
                item.get("job_id", ""),
                item.get("status", ""),
            )
        )
        break
else:
    print("NO_MATCH\t{}".format(data.get("page_num") or 0))
''' <<<"$response"
  )"

  IFS=$'\t' read -r result team score timestamp job_id status <<<"$parsed"

  if [[ "$result" == "MATCH" ]]; then
    echo "found=true"
    echo "team=${team}"
    echo "score=${score}"
    echo "timestamp=${timestamp}"
    echo "job_id=${job_id}"
    echo "status=${status}"
    exit 0
  fi

  page_num="${team:-0}"
  if (( page >= page_num )); then
    echo "found=false"
    echo "message=no response found for ${TARGET_TEAM}" >&2
    exit 1
  fi

  page=$((page + 1))
done
