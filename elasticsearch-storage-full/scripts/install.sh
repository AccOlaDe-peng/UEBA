#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
es_url="${ES_URL:-http://localhost:9200}"
curl_args=(-sS --fail-with-body -H 'Content-Type: application/json')
if [[ -n "${ES_API_KEY:-}" ]]; then curl_args+=(-H "Authorization: ApiKey ${ES_API_KEY}"); fi

put_json() {
  local path="$1" file="$2"
  curl "${curl_args[@]}" -X PUT "${es_url}${path}" --data-binary "@${file}" >/dev/null
  echo "installed ${path}"
}

python3 "${root_dir}/scripts/compile-route-pipeline.py"
"${root_dir}/scripts/validate.sh"

for file in "${root_dir}"/ilm/*.json; do
  name="$(basename "${file}" .json)"
  put_json "/_ilm/policy/ueba-${name}" "${file}"
done

for file in "${root_dir}"/component-templates/*.json; do
  artifact="$(jq -r '._meta.artifact' "${file}")"
  version="$(jq -r '._meta.semantic_version' "${file}")"
  put_json "/_component_template/${artifact}@${version}" "${file}"
done

put_json '/_ingest/pipeline/ueba-normalized-event-classifier-1.1.0' "${root_dir}/pipelines/normalized-event-classifier.json"
put_json '/_ingest/pipeline/ueba-normalized-event-router-1.1.0' "${root_dir}/pipelines/normalized-event-router.json"
put_json '/_ingest/pipeline/ueba-normalized-event-validate-1.1.0' "${root_dir}/pipelines/normalized-event-validate.json"
put_json '/_ingest/pipeline/ueba-normalized-event-ingress-1.1.0' "${root_dir}/pipelines/normalized-event-ingress.json"
put_json '/_ingest/pipeline/ueba-raw-evidence-envelope-1.0.0' "${root_dir}/pipelines/raw-evidence-envelope.json"

for file in "${root_dir}"/index-templates/*.json; do
  artifact="$(jq -r '._meta.artifact' "${file}")"
  version="$(jq -r '._meta.semantic_version' "${file}")"
  put_json "/_index_template/${artifact}@${version}" "${file}"
done

create_versioned_index() {
  local index="$1" alias="$2"
  if ! curl "${curl_args[@]}" -I "${es_url}/${index}" >/dev/null 2>&1; then
    curl "${curl_args[@]}" -X PUT "${es_url}/${index}" --data-binary "{\"aliases\":{\"${alias}\":{\"is_write_index\":true}}}" >/dev/null
    echo "created ${index} with alias ${alias}"
  fi
}

namespace="${UEBA_NAMESPACE:-default}"
create_versioned_index "ueba-entities-v1-${namespace}" "ueba-entities-${namespace}"
create_versioned_index "ueba-baselines-v1-${namespace}" "ueba-baselines-current-${namespace}"
create_versioned_index "ueba-entity-risk-current-v1-${namespace}" "ueba-entity-risk-current-${namespace}"
create_versioned_index "ueba-cases-v1-${namespace}" "ueba-cases-${namespace}"

echo 'UEBA data-object storage artifacts installed'
