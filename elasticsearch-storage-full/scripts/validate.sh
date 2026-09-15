#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "${root_dir}/.." && pwd)"

while IFS= read -r -d '' file; do
  if [[ "${file}" == *.ndjson ]]; then
    jq -c . "${file}" >/dev/null
  else
    jq . "${file}" >/dev/null
  fi
done < <(find "${root_dir}" -type f \( -name '*.json' -o -name '*.ndjson' \) -print0 | sort -z)

jq -s -e 'length == 4 and map(.test_id) == ["ROUTE-WIN-AUTH","ROUTE-ZEEK-DNS","ROUTE-LINUX-PROCESS","ROUTE-INVALID"]' "${root_dir}/examples/route-simulate.ndjson" >/dev/null

python3 - "${root_dir}" "${repo_dir}/UEBA日志分类与最小ECS字段全量表.md" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
contract = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
ids = re.findall(r"^### 4\.\d+ (\d{4})", contract, re.M)
if len(set(ids)) != 32:
    raise SystemExit(f"expected 32 Windows event ids, found {len(set(ids))}")
registry = json.loads((root / "routing/route-registry.json").read_text())
allowed = set(registry["allowed_domains"])
windows_routes = registry["windows_security_event_code"]
if set(windows_routes) != set(ids):
    raise SystemExit("route registry does not cover exactly the 32 Windows event contracts")
for group in (windows_routes, registry["fixed_vendor_dataset"]):
    invalid = set(group.values()) - allowed
    if invalid:
        raise SystemExit(f"route registry contains invalid domains: {sorted(invalid)}")
for dataset, domains in registry["conditional_vendor_dataset"].items():
    invalid = set(domains) - allowed
    if invalid:
        raise SystemExit(f"{dataset} contains invalid route domains: {sorted(invalid)}")
for dataset, routes in registry["native_type_routes"].items():
    invalid = set(routes.values()) - allowed
    if invalid:
        raise SystemExit(f"{dataset} native routes contain invalid domains: {sorted(invalid)}")
classifier = json.loads((root / "pipelines/normalized-event-classifier.json").read_text())
params = classifier["processors"][0]["script"]["params"]
for param_key, registry_key in (
    ("windows_event_code", "windows_security_event_code"),
    ("fixed_vendor_dataset", "fixed_vendor_dataset"),
    ("native_type_routes", "native_type_routes"),
):
    if params[param_key] != registry[registry_key]:
        raise SystemExit("compiled route pipeline is stale; run scripts/compile-route-pipeline.py")
for line in (root / "examples/route-simulate.ndjson").read_text().splitlines():
    if not line.strip():
        continue
    sample = json.loads(line)
    domain = sample["_source"].get("ueba", {}).get("route", {}).get("domain")
    if domain is not None and domain not in allowed:
        raise SystemExit(f"{sample['test_id']} uses invalid route domain {domain}")
components = {}
for path in sorted((root / "component-templates").glob("*.json")):
    data = json.loads(path.read_text())
    key = data["_meta"]["artifact"] + "@" + data["_meta"]["semantic_version"]
    components[key] = path.name
for path in sorted((root / "index-templates").glob("*.json")):
    data = json.loads(path.read_text())
    missing = set(data.get("composed_of", [])) - set(components)
    if missing:
        raise SystemExit(f"{path}: missing component refs {sorted(missing)}")
for path in root.rglob("*"):
    if path.is_file() and re.search(r"(^|[-_/])l[0-4][-_]", str(path.relative_to(root)), re.I):
        raise SystemExit(f"layer-coded artifact name remains: {path.relative_to(root)}")
print(f"validated {len(components)} component templates and 32 Windows event contracts")
PY

echo 'data-object JSON syntax, fixtures and template references passed'
