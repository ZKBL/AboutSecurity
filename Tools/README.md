# Tools/ — 外部工具声明式配置

本目录存放的 YAML 文件是面向**程序化工具编排框架**的结构化接口定义，用于自动化引擎按声明式配置调用外部安全工具。

## 与 skills/tool/ 的区别

| | Tools/ YAML | skills/tool/ SKILL.md |
|---|---|---|
| **面向对象** | 程序化编排引擎（代码调用） | LLM Agent（自然语言对话） |
| **内容** | 参数类型、命令模板、输出解析器、结果映射 | 何时用、怎么选参数、结果怎么判断 |
| **格式** | 结构化 YAML（机器可解析） | Markdown（人/LLM 可读） |
| **调用方** | 工具编排框架自动拼接命令行 | LLM 理解方法论后自行决策执行 |

**如果你只使用 Claude Code 等 LLM Agent，关注 `skills/tool/` 即可。** 本目录的 YAML 适用于需要程序化编排多工具流水线的场景（如自动化扫描平台）。

## 目录结构

```
Tools/
├── scan/          # 扫描探测（端口、子域名、指纹、爬虫）
├── fuzz/          # 模糊测试（目录爆破、参数Fuzz）
├── osint/         # 开源情报（资产发现、历史URL）
├── poc/           # 漏洞验证（nuclei、sqlmap、dalfox）
├── brute/         # 暴力破解（hydra）
└── postexploit/   # 后渗透（impacket、crackmapexec）
```

共 31 个工具配置，覆盖侦察到后渗透的常用外部工具。

## YAML 格式说明

每个 YAML 文件包含以下字段：

```yaml
# === 基本信息 ===
id: ext_nmap_scan              # 唯一标识符
name: Nmap 端口扫描             # 显示名称
description: "..."             # 工具用途描述
homepage: "https://..."        # 官方链接
category: scan                 # 所属分类
binary: nmap                   # 可执行文件名
version_cmd: "nmap --version"  # 版本检查命令

# === 安装方式 ===
install:
  brew: "brew install nmap"
  apt: "sudo apt install -y nmap"

# === 参数定义 ===
parameters:
  - name: target
    type: string
    description: "扫描目标"
    required: true
  - name: ports
    type: string
    default: "1-10000"
    enum: ["syn", "tcp", "udp"]   # 可选：枚举限制

# === 命令模板（Go template 语法）===
command_template: |
  -sS -p {{.ports}} -oG {{.OutputFile}} {{.target}}

# === 输出解析 ===
output:
  mode: file                       # file 或 stdout
  file_pattern: "{{.OutputFile}}"
  parser: json | grepable          # 解析器类型
  json:
    fields:
      - { name: host, path: "host" }

# === 结果映射（统一格式）===
findings_mapping:
  type: vulnerability | info
  severity: info | low | medium | high | critical
  target_field: host
  detail_template: "{{.host}}:{{.port}} open"

# === 约束 ===
constraints:
  timeout: 300s
  requires_root: false
  max_concurrent: 2
```

## 各分类工具一览

### scan/ — 扫描探测
| 工具 | 用途 |
|------|------|
| nmap | 端口扫描（SYN/TCP/UDP） |
| masscan | 大规模端口快速扫描 |
| naabu | 轻量端口扫描 |
| fscan | 内网综合扫描 |
| httpx | HTTP 探活与指纹 |
| subfinder | 被动子域名枚举 |
| ksubdomain | 主动子域名爆破 |
| dnsx | DNS 解析验证 |
| katana | 爬虫/URL发现 |
| tlsx | TLS 证书探测 |
| mapcidr | CIDR 处理 |
| fingerprintx | 服务指纹识别 |
| nikto | Web 漏洞扫描 |
| nerva | 资产发现 |
| gogo | 端口扫描 |

### fuzz/ — 模糊测试
| 工具 | 用途 |
|------|------|
| ffuf | 通用 Web Fuzzer |
| dirsearch | 目录/文件爆破 |
| spray | 密码喷洒 |

### osint/ — 开源情报
| 工具 | 用途 |
|------|------|
| uncover | 搜索引擎资产发现 |
| gau | 历史 URL 收集 |

### poc/ — 漏洞验证
| 工具 | 用途 |
|------|------|
| nuclei | 模板化漏洞扫描 |
| sqlmap | SQL 注入检测与利用 |
| dalfox | XSS 扫描 |
| padbuster | Padding Oracle 攻击 |

### brute/ — 暴力破解
| 工具 | 用途 |
|------|------|
| hydra | 多协议密码爆破 |

### postexploit/ — 后渗透
| 工具 | 用途 |
|------|------|
| crackmapexec | 内网横向（SMB/LDAP/WinRM） |
| netexec | crackmapexec 后继 |
| impacket-psexec | 远程命令执行 |
| impacket-secretsdump | 凭据导出 |
| impacket-getuserspns | Kerberoasting |
| impacket-getnpusers | AS-REP Roasting |
