#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
es_url="${ES_URL:-http://localhost:9200}"
curl_args=(-sS --fail-with-body -H 'Content-Type: application/json')
if [[ -n "${ES_API_KEY:-}" ]]; then
  curl_args+=(-H "Authorization: ApiKey ${ES_API_KEY}")
fi

"${repo_dir}/elasticsearch-prototype/scripts/validate-fixtures.sh"

win_doc="$(sed -n '1p' "${repo_dir}/testdata/raw/windows-security.jsonl")"
zeek_doc="$(sed -n '1p' "${repo_dir}/testdata/raw/zeek.jsonl")"

jq -n --argjson doc "${win_doc}" '{docs:[{_source:$doc}]}' |
  curl "${curl_args[@]}" -X POST "${es_url}/_ingest/pipeline/ueba-windows-security-1.0.0/_simulate" --data-binary @- |
  jq -e '.docs[0].doc._source.event.outcome=="success" and .docs[0].doc._source.ueba.event.type=="authentication.login"' >/dev/null

jq -n --argjson doc "${zeek_doc}" '{docs:[{_source:$doc}]}' |
  curl "${curl_args[@]}" -X POST "${es_url}/_ingest/pipeline/ueba-zeek-1.0.0/_simulate" --data-binary @- |
  jq -e '.docs[0].doc._source.network.bytes==1668 and .docs[0].doc._source.ueba.event.type=="network.connection"' >/dev/null

echo 'Elasticsearch pipeline smoke tests passed'
