# AboutSecurity

渗透测试知识库，以 AI Agent 可执行的格式沉淀安全方法论。

## 核心模块

**Skills/** — 113 个技能方法论，覆盖侦察到后渗透全流程

- `cloud/` — 云环境（Docker逃逸、K8s攻击、AWS IAM、阿里云、腾讯云）
- `ctf/` — CTF竞赛（Web解题、逆向、PWN、密码学、取证）
- `evasion/` — 免杀对抗（C2框架、Shellcode生成、安全研究）
- `exploit/` — 漏洞利用（SQL注入、XSS、SSTI、文件上传、反序列化、JWT、GraphQL、SSRF/XXE、CORS、CSRF、OAuth、WebSocket、竞态条件、缓存投毒/请求走私）
- `general/` — 综合（报告生成、供应链审计、移动后端API）
- `lateral/` — 横向移动（AD域攻击、NTLM中继、数据库横向）
- `postexploit/` — 后渗透（Linux/Windows提权、持久化、凭据窃取）
- `recon/` — 侦察（子域名枚举、被动信息收集、JS API提取）
- `tool/` — 工具使用（fscan、nuclei、sqlmap、msfconsole、ffuf、hashcat）

**Dict/** — 字典库

- `Auth/` — 用户名/密码
- `Network/` — IP段排除、DNS服务器
- `Port/` — 按端口分类的爆破字典
- `Web/` — Web目录、API参数、fuzz字典

**Payload/** — 攻击载荷

- `SQL-Inj/`、`XSS/`、`SSRF/`、`XXE/`、`LFI/`、`RCE/`、`upload/`、`CORS/`、`HPP/`、`Format/`、`SSI/`、`email/`

**Tools/** — 外部工具声明式配置

- `scan/`、`fuzz/`、`osint/`、`poc/`、`brute/`、`postexploit/`

## Skill 格式

```
sql-injection-methodology/
├── SKILL.md           # 决策树（触发条件 → 执行流程）
├── references/        # 详细内容（payload + 脚本）
└── evals/             # A/B 测试评估
```

SKILL.md 定义 AI Agent 的行为约束（NEVER/ALWAYS），references/ 目录按需加载详细内容。

## Skill Benchmark

`python scripts/bench-skill.py --all` 量化 Skill 对 Agent 效果的提升，结果记录在 `benchmarks/` 目录。

## 快速开始

```bash
# 列出所有 Skill
ls Skills/

# 查看特定 Skill
cat Skills/exploit/sql-injection-methodology/SKILL.md

# 运行 Benchmark (需要本地配置好 claude code 使用)
python scripts/bench-skill.py --skill sql-injection-methodology
```

## 贡献

提交前阅读 [CONTRIBUTING.md](./CONTRIBUTING.md)，包括 Skill 格式规范、references 编写要求、benchmark 测试流程。

## 参考

- https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md
- https://github.com/ljagiello/ctf-skills
- https://github.com/JDArmy/Evasion-SubAgents
- https://github.com/teamssix/twiki
