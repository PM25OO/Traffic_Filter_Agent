# Traffic_Filter_Agent — AI 代理工作指引

## ✅ 必读规范
- 指令文件固定在 `.github/AGENTS.md`；除非用户明确要求，不再创建/迁移到其他位置。
- 设计与安全约束的**唯一权威**在 `instruction.md`：请先阅读并严格遵循（漏斗式分治、LangGraph 拓扑、强类型状态、输入白名单、ReAct 步数熔断、包数量硬截断等）。
- 如需“优化/修订”该文档：**先提出修改建议与理由并征得用户确认**，再动手修改。

## 🧭 任务与沟通
- 开始编码前，基于 `instruction.md` **先产出任务拆解清单（TODO）**，与用户对齐后再进入实现。
- 遇到不清楚的项目细节：**必须先向用户提问**，不要凭空假设。
- 任何实现都应遵循“宏观确定性 + 微观可探索”的设计哲学（宏观用 LangGraph、微观用 ReAct）。

## 🧩 架构对齐提示（当前仓库现状）
- 当前代码仍为骨架：`src/__main__.py` 仅有 CLI 框架，尚未实现流程。
- `src/state.py` 的 `AgentState` 与 `instruction.md` 中的 `TrafficAnalysisState` **字段不一致**。实现前请与用户确认以哪一份为准，并在代码中对齐。

## ✅ 提交规范（原子化）
- 每完成一个清晰的逻辑闭环或测试通过后，**自动执行一次 git commit（原子化）**。
- 提交信息采用 **Conventional Commits** 且带 scope（例如：`feat(graph): add macro triage node`）。
- 若需要将多个逻辑合并为单次提交，先与用户确认。

## 🔐 环境与依赖
- 如使用 Wireshark-MCP / TShark / Nmap 等外部工具，请先确认系统已安装并在 PATH 中。
- 如需要 API Key（如 `ABUSEIPDB_API_KEY`），**先检查项目根目录是否存在 `.env`**；若不存在则创建并写入占位符，再告知用户。

## 🧪 测试/运行
- 当前无统一测试命令或脚本。若新增测试或运行脚本，请在此文档补充说明。

## 📎 参考文档
- 项目主规范：`instruction.md`
