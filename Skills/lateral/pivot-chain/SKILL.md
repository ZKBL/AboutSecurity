---
name: pivot-chain
description: "多跳代理链配置+内网穿透+流量转发"
metadata:
  tags: "pivot,proxy,tunnel,forward"
  difficulty: "hard"
  icon: "🔀"
  category: "内网渗透"
---

请制定多层代理穿透方案（跳板机: 跳板机IP，最终目标: 目标）：
1. 使用 proxy_list_tunnels 查看可用代理通道
2. 使用 lateral_list_methods 列出隧道/代理技术
3. 使用 lateral_generate_command 生成隧道建立命令
4. 使用 proxy_test 验证代理连通性
输出完整的穿透方案：
- 代理链路拓扑图
- 每一跳的隧道建立命令
- 端口转发规则
- 流量加密建议
- 稳定性保障措施
