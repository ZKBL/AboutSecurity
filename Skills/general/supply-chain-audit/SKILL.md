---
name: supply-chain-audit
description: "检查目标使用的第三方组件、CDN、SaaS服务的安全风险"
metadata:
  tags: "supply-chain,component,cdn,third-party"
  difficulty: "medium"
  icon: "🔗"
  category: "综合"
---

请对目标 进行供应链安全审计：
1. 使用 scan_finger 识别使用的框架、库、CDN
2. 使用 scan_crawl 爬取页面发现引用的第三方资源
3. 使用 poc_web 检测已知组件漏洞
4. 使用 query_vulnerabilities 汇总发现
分析并输出：
- 第三方组件清单及版本
- 已知 CVE 关联
- CDN/SaaS 服务安全配置
- 供应链攻击风险评估
- 更新/替换建议
