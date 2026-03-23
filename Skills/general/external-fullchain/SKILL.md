---
name: external-fullchain
description: "从侦察到突破到驻留的端到端自动化渗透流程"
metadata:
  tags: "fullchain,recon,exploit,persist,automation"
  difficulty: "hard"
  icon: "🎯"
  category: "综合"
---

请对目标 执行外网打点全流程自动化渗透：

**阶段1 - 侦察**
1. 使用 scan_dns 进行子域名枚举
2. 使用 scan_port 扫描发现的资产端口
3. 使用 scan_urlive 检测 URL 存活
4. 使用 scan_finger 识别技术栈

**阶段2 - 漏洞发现**
5. 使用 poc_web 进行漏洞扫描
6. 使用 poc_default_login 检测默认口令

**阶段3 - 利用与驻留**
7. 分析发现的漏洞，评估利用可能性
8. 给出完整的攻击路径和持久化建议

每个阶段完成后更新执行计划，总结发现。
最终输出完整的渗透测试报告，包括：发现清单、风险评级、攻击路径、修复建议。
