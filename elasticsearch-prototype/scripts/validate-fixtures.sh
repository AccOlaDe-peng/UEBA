#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

while IFS= read -r file; do
  if [[ "${file}" == *.jsonl || "${file}" == *.ndjson ]]; then
    jq -c . "${file}" >/dev/null
  else
    jq . "${file}" >/dev/null
  fi
done < <(find "${repo_dir}/testdata" "${repo_dir}/elasticsearch-prototype" -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.ndjson' \) | sort)

jq -s -e 'length == 2' "${repo_dir}/testdata/expected/windows-security.jsonl" >/dev/null
jq -s -e 'length == 2' "${repo_dir}/testdata/expected/zeek.jsonl" >/dev/null
jq -s -e 'length == 3 and all(.[]; .ueba.quality.status=="invalid")' "${repo_dir}/testdata/expected/errors.jsonl" >/dev/null
jq -s -e 'map(.test_id) == ["WIN-4624-001","WIN-4625-001"]' "${repo_dir}/testdata/raw/windows-security.jsonl" >/dev/null
jq -s -e 'map(.test_id) == ["ZEEK-CONN-001","ZEEK-DNS-001"]' "${repo_dir}/testdata/raw/zeek.jsonl" >/dev/null
jq -s -e '.[0].event.outcome=="success" and .[1].event.outcome=="failure"' "${repo_dir}/testdata/expected/windows-security.jsonl" >/dev/null
jq -s -e '.[0].network.bytes==1668 and .[0].source.ip=="10.10.1.25" and .[0].destination.ip=="8.8.8.8"' "${repo_dir}/testdata/expected/zeek.jsonl" >/dev/null

echo 'JSON syntax and fixture assertions passed'
