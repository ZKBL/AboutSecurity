---
name: cloud-metadata
description: "SSRF探测云元数据+IAM凭据提取+云服务枚举"
metadata:
  tags: "cloud,metadata,ssrf,iam,aws,azure,gcp"
  difficulty: "hard"
  icon: "☁️"
  category: "云环境"
---

请对目标 进行云元数据利用分析：
1. 使用 scan_finger 识别目标云环境（AWS/Azure/GCP）
2. 使用 poc_web 检测 SSRF 相关漏洞
3. 使用 query_vulnerabilities 查看已发现的 SSRF 漏洞
4. 分析云环境特征，给出元数据利用方案
针对不同云平台输出：
- AWS: 169.254.169.254 元数据访问 + IAM Role 凭据提取 + S3 枚举
- Azure: 169.254.169.254/metadata + Managed Identity 令牌获取
- GCP: metadata.google.internal + Service Account 密钥
- 通用: 内网探测 + 凭据横向利用
