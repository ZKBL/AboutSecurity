---
name: mobile-backend
description: "针对移动App后端API的安全测试"
metadata:
  tags: "mobile,api,backend,auth"
  difficulty: "medium"
  icon: "📱"
  category: "综合"
---

请对移动端后端 API 目标 执行安全测试：
1. 使用 brute_dir 发现 API 端点（重点: /api/v1/, /api/v2/, /graphql）
2. 使用 scan_finger 识别后端技术栈
3. 使用 poc_web 检测已知漏洞
4. 使用 fuzz_bypass 尝试认证绕过
重点关注：
- API 认证机制弱点（JWT/OAuth/API Key）
- 越权访问（IDOR/水平越权/垂直越权）
- 数据泄露（调试接口/错误信息/版本信息）
- 业务逻辑漏洞（支付/优惠券/验证码）
- 速率限制缺失
