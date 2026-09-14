#!/usr/bin/env bash
set -euo pipefail

prototype_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
es_url="${ES_URL:-http://localhost:9200}"
curl_args=(-sS --fail-with-body -H 'Content-Type: application/json')
if [[ -n "${ES_API_KEY:-}" ]]; then
  curl_args+=(-H "Authorization: ApiKey ${ES_API_KEY}")
fi

put_json() {
  local path="$1"
  local file="$2"
  curl "${curl_args[@]}" -X PUT "${es_url}${path}" --data-binary "@${file}" >/dev/null
  echo "installed ${path}"
}

put_json '/_ilm/policy/ueba-events-90d' "${prototype_dir}/ilm/ueba-events-90d.json"
put_json '/_component_template/ueba-base@1.0.0' "${prototype_dir}/component-templates/ueba-base.json"
put_json '/_ingest/pipeline/ueba-windows-security-1.0.0' "${prototype_dir}/pipelines/windows-security.json"
put_json '/_ingest/pipeline/ueba-zeek-1.0.0' "${prototype_dir}/pipelines/zeek.json"
put_json '/_ingest/pipeline/ueba-router-1.0.0' "${prototype_dir}/pipelines/router.json"
put_json '/_index_template/logs-ueba@1.0.0' "${prototype_dir}/index-templates/logs-ueba.json"

echo 'prototype installation complete'
