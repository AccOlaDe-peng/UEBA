import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { marked } = require("C:/Users/changchang/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/marked");
const dir = path.dirname(fileURLToPath(import.meta.url));
const parts = [
  "00-阅读入口.md",
  "01-领导主报告.md",
  "02-数据平台与工程机制.md",
  "03-行为检测与风险机制.md",
  "04-自研映射与验证边界.md",
  "05-证据索引与勘误.md",
  "06-Windows-AD与Zeek日志采集机制对比.md",
  "07-Splunk-Indexer开源替代方案.md",
  "08-数据进入与UEBA特征计算机制.md",
  "09-Splunk数据进入流程总结.md",
  "10-CIM与Zeek映射及Dataset参考.md",
];

marked.use({ gfm: true });
const sections = [];
const nav = [];
for (const [index, file] of parts.entries()) {
  const source = fs.readFileSync(path.join(dir, file), "utf8");
  const title = source.match(/^#\s+(.+)$/m)?.[1] ?? file;
  const part = `part-${String(index).padStart(2, "0")}`;
  let html = marked.parse(source);
  html = html.replace(/href="(?:\.\/)?(\d{2})-[^"]+\.md(?:#[^"]*)?"/g, (_m, n) => `href="#part-${n}"`);
  html = html.replace(/<table>/g, '<div class="table-wrap"><table>').replace(/<\/table>/g, "</table></div>");
  sections.push(`<section id="${part}">${html}</section>`);
  nav.push(`<li><a href="#${part}">${title}</a></li>`);
}

const css = `:root{color-scheme:light;--ink:#20242a;--muted:#626b76;--rule:#d9dee5;--accent:#204c75}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:24px}body{margin:0;background:#fff;color:var(--ink);font:16px/1.85 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}nav{position:fixed;left:0;top:0;bottom:0;width:280px;padding:34px 22px;border-right:1px solid var(--rule);overflow:auto;background:#f7f8fa;font-size:14px}nav strong{font-size:18px}nav ol{padding-left:21px}nav li{margin:14px 0}nav p{color:var(--muted);font-size:13px}main{max-width:1190px;margin-left:280px;padding:42px 64px 110px}section{margin-bottom:90px;scroll-margin-top:24px}section+section{border-top:2px solid var(--rule);padding-top:48px}h1{font-size:30px;line-height:1.4;margin:0 0 26px;letter-spacing:.02em}h2{font-size:23px;line-height:1.5;margin:42px 0 16px}h3{font-size:18px;line-height:1.6;margin:30px 0 14px}p{margin:14px 0}li{margin:6px 0}.table-wrap{overflow-x:auto;margin:22px 0}table{border-collapse:collapse;width:100%;font-size:14px;line-height:1.7}th,td{border:1px solid var(--rule);padding:11px 13px;text-align:left;vertical-align:top;min-width:110px}th{background:#eef1f4;font-weight:600}tr:nth-child(even) td{background:#fafbfc}pre{background:#f5f6f8;border:1px solid var(--rule);padding:18px;overflow-x:auto;font-size:13px;line-height:1.65}code{font-family:ui-monospace,SFMono-Regular,Menlo,"PingFang SC",monospace;overflow-wrap:anywhere}p code,td code{background:#f1f3f5;padding:1px 4px}button{font:inherit;border:1px solid #b9c4ce;background:white;padding:6px 14px;cursor:pointer;color:var(--ink)}footer{border-top:1px solid var(--rule);padding-top:24px;font-size:13px;color:var(--muted)}@media(max-width:1050px){nav{position:static;width:auto;border-right:0;border-bottom:1px solid var(--rule);padding:20px 26px}nav ol{columns:2}nav li{margin:8px 0;break-inside:avoid}main{margin:0;padding:32px 26px;max-width:none}h1{font-size:26px}}@media print{@page{size:A4;margin:18mm 15mm}body{font-size:10pt;line-height:1.65}nav{display:none}main{margin:0;padding:0;max-width:none}h1{font-size:23pt}h2{font-size:16pt}h3{font-size:12pt}section{margin:0;break-before:page}section:first-child{break-before:auto}section+section{border:0;padding:0}h1,h2,h3{break-after:avoid}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:8pt;break-inside:avoid}.table-wrap{overflow:visible}table{font-size:8.5pt}th,td{padding:5px 7px;min-width:0}tr{break-inside:avoid}thead{display:table-header-group}a{color:inherit}button{display:none}}`;
const output = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Splunk 实现机制与 UEBA 预研报告</title><style>${css}</style></head><body><nav><strong>Splunk 机制预研报告</strong><ol>${nav.join("")}</ol><p>核验截止：2026-09-10<br>事实、解释与示例分开呈现<br>可离线阅读，无外部脚本依赖</p><button onclick="window.print()">打印 / 保存 PDF</button></nav><main>${sections.join("")}<footer>本报告提供机制解释与证据边界，最终自研路线由决策者确定。来源详情见证据索引。</footer></main></body></html>`;
fs.writeFileSync(path.join(dir, "Splunk机制预研报告-合订本.html"), output, "utf8");
