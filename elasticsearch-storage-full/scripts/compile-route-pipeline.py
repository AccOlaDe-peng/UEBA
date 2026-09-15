#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
registry = json.loads((root / "routing/route-registry.json").read_text(encoding="utf-8"))
pipeline = {
    "description": "Derive the trusted route contract from the controlled source mapping registry",
    "version": 10100,
    "processors": [{
        "script": {
            "lang": "painless",
            "params": {
                "windows_event_code": registry["windows_security_event_code"],
                "fixed_vendor_dataset": registry["fixed_vendor_dataset"],
                "native_type_routes": registry["native_type_routes"],
                "route_version": registry["version"]
            },
            "source": "if(ctx.ueba==null)ctx.ueba=new HashMap();ctx.ueba.remove('route');ctx.ueba.route=new HashMap();def dataset=ctx.vendor?.dataset;def domain=null;def rule=null;if(dataset=='windows.security'&&ctx.event?.code!=null){def code=ctx.event.code.toString();domain=params.windows_event_code[code];if(domain!=null)rule=dataset+'/'+code;}if(domain==null&&dataset!=null){domain=params.fixed_vendor_dataset[dataset];if(domain!=null)rule=dataset;}if(domain==null&&dataset!=null&&params.native_type_routes.containsKey(dataset)){def nativeType=ctx.vendor?.payload?.record_type;if(nativeType==null)nativeType=ctx.vendor?.payload?.event_type;if(nativeType!=null){domain=params.native_type_routes[dataset][nativeType.toString()];if(domain!=null)rule=dataset+'/'+nativeType.toString();}}if(domain!=null){ctx.ueba.route.domain=domain;ctx.ueba.route.rule_id=rule;ctx.ueba.route.version=params.route_version;}"
        }
    }]
}
(root / "pipelines" / "normalized-event-classifier.json").write_text(
    json.dumps(pipeline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
print("compiled routing/route-registry.json -> pipelines/normalized-event-classifier.json")

