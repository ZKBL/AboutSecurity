---
name: red-team-assessment
description: "全自动化红队评估：侦察+突破+驻留+报告生成"
metadata:
  tags: "red-team,assessment,automation,report"
  difficulty: "hard"
  icon: "🔴"
  category: "综合"
---

请执行全面的红队评估（目标: 目标）：
测试范围: {{scope}}

**Phase 1: 被动侦察**
1. 使用 osint_fofa 收集目标资产情报
2. 使用 osint_quake 补充搜索

**Phase 2: 主动侦察**
3. 使用 scan_dns 枚举子域名
4. 使用 scan_port 发现开放端口
5. 使用 scan_finger 识别技术栈

**Phase 3: 漏洞评估**
6. 使用 poc_web 扫描 Web 漏洞
7. 使用 poc_default_login 检测默认口令
8. 使用 brute_dir 发现隐藏路径

**Phase 4: 分析与报告**
9. 使用 query_vulnerabilities 和 query_assets 汇总所有发现
10. 生成红队评估报告

报告要求：
- 执行摘要（管理层可读）
- 发现清单（按严重度排序）
- 攻击路径分析
- 风险评级矩阵
- 修复建议优先级
