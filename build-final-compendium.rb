#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"

root = File.expand_path(__dir__)
output = File.join(root, "UEBA异构日志归一设计-最终合订本.md")

chapters = [
  ["第一篇　总体架构", "UEBA整体架构预研-Elasticsearch方案.md"],
  ["第二篇　统一事件模型规范", "统一事件模型规范.md"],
  ["第三篇　日志源接入与映射清单", "日志源接入与映射清单.md"],
  ["第四篇　CIM—ECS—UEBA 语义对照表", "CIM—ECS—UEBA语义对照表.md"],
  ["第五篇　事件类型目录", "事件类型目录.md"],
  ["第六篇　数据质量规则", "数据质量规则.md"],
  ["第七篇　解析与映射测试集", "解析与映射测试集.md"],
  ["第八篇　Pipeline 版本和发布规范", "Pipeline版本和发布规范.md"],
  ["第九篇　数据源健康监控指标", "数据源健康监控指标.md"],
  ["第十篇　Elasticsearch 原型", "Elasticsearch原型.md"],
  ["第十一篇　完整验证链", "完整验证链.md"]
]

missing = chapters.map { |_, file| file }.reject { |file| File.file?(File.join(root, file)) }
abort("Missing source documents: #{missing.join(', ')}") unless missing.empty?

header = <<~MARKDOWN
  # UEBA 异构日志归一设计——最终合订本

  > 文档状态：预研设计合订本  
  > 编制日期：2026-09-14  
  > 总体架构：Elasticsearch 作为事件、特征和分析结果的存储检索底座  
  > 首期范围：HR/AD、CMDB/AD Computer、Windows Security、DHCP、VPN、Zeek conn/dns/http  
  > 参考体系：Splunk CIM、Splunk UEBA/Asset and Identity、Elastic ECS  
  > 配套制品：[Elasticsearch 原型](./elasticsearch-prototype/README.md)、[机器可读测试集](./testdata/manifest.json)

  ## 文档说明

  本合订本将总体架构、统一事件模型、日志源映射、CIM—ECS—UEBA 语义对照、事件目录、质量规则、测试集、Pipeline 发布、健康监控、Elasticsearch 原型和端到端验证链组织为一份完整设计。各分册仍作为独立维护单元；本文件由分册机械合并生成，用于统一评审和交付。

  Splunk 官方资料用于确认 CIM、身份解析、资产与身份、行为分析和数据源要求；文中的 Elasticsearch 结构、`ueba.*` 扩展、质量阈值、版本机制和实现流程属于本项目自研设计，不代表 Splunk 内部实现。

  核心判断是：任何单一日志源都不能形成完整、高可信的 UEBA。Zeek 单独只能形成 IP、设备候选和网络会话行为；用户级输出必须同时具备身份源、资产源、含用户活动源及事件时刻有效的用户—设备—IP 关系。

  ## 总目录

MARKDOWN

toc = chapters.each_with_index.map do |(title, file), index|
  "#{index + 1}. [#{title}](#part-#{format('%02d', index + 1)})"
end.join("\n")

body = chapters.each_with_index.map do |(title, file), index|
  content = File.read(File.join(root, file), encoding: "UTF-8")
  source_title_removed = false
  content = content.lines.each_with_object([]) do |line, lines|
    if !source_title_removed && line.match?(/^# /)
      source_title_removed = true
    elsif line.match?(/\A\#{2,5} /)
      lines << "##{line}"
    else
      lines << line
    end
  end.join
  "\n\n---\n\n<a id=\"part-#{format('%02d', index + 1)}\"></a>\n\n## #{title}\n\n> 本篇来源：[#{file}](./#{file})\n\n#{content.strip}\n"
end.join

File.write(output, header + toc + body, mode: "w", encoding: "UTF-8")
puts output
