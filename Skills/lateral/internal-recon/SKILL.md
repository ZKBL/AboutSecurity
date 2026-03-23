---
name: internal-recon
description: "内网网段探测+端口扫描+服务识别，绘制内网拓扑"
metadata:
  tags: "internal,recon,network,discovery"
  difficulty: "medium"
  icon: "🏢"
  category: "内网渗透"
---

请对内网网段 目标 执行信息收集：
1. 使用 scan_port 扫描网段内存活主机和开放端口
2. 使用 scan_finger 对发现的服务进行指纹识别
3. 使用 query_assets 查看已收集的资产清单
4. 使用 get_store_stats 获取整体统计
分析内网拓扑，输出：
- 存活主机清单和服务分布
- 关键基础设施识别（域控/DNS/邮件/文件服务器）
- 高价值目标标记
- 薄弱点评估（弱口令服务/未打补丁/暴露管理端口）
