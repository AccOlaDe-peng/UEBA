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
print(f"validated {len(components)} component templates and 32 Windows event contracts")
PY

echo 'L0-L4 JSON syntax, fixtures and template references passed'
