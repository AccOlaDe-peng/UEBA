#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
es_url="${ES_URL:-http://localhost:9200}"
curl_args=(-sS --fail-with-body -H 'Content-Type: application/json')
if [[ -n "${ES_API_KEY:-}" ]]; then curl_args+=(-H "Authorization: ApiKey ${ES_API_KEY}"); fi

"${root_dir}/scripts/validate.sh"

while IFS= read -r row; do
  test_id="$(jq -r '.test_id' <<<"${row}")"
  expected="$(jq -r '.expected_index' <<<"${row}")"
  source_doc="$(jq -c '._source' <<<"${row}")"
  response="$(jq -n --argjson doc "${source_doc}" '{docs:[{_index:"logs-ueba.ingress-prod",_source:$doc}]}' | curl "${curl_args[@]}" -X POST "${es_url}/_ingest/pipeline/ueba-normalized-event-ingress-1.1.0/_simulate" --data-binary @-)"
  actual="$(jq -r '.docs[0].doc._index' <<<"${response}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${test_id}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
  echo "${test_id}: ${actual}"
done < "${root_dir}/examples/route-simulate.ndjson"

echo 'normalized-event routing smoke tests passed'
