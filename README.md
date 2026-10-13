# AgentKey

**A personal password manager for humans and AI agents on Apple devices.**
AutoFill everywhere on Mac, iPhone and iPad · end-to-end encrypted sync through your own iCloud · AI agents that use
*and tidy* your vault — only with your Touch ID or Apple Watch approval.

面向人和 AI Agent 的个人密码管理器：Apple 全端自动填充，自己的 iCloud 端到端加密同步，Agent 在你的 Touch ID / Apple Watch 批准下取用并帮你打理保险库。

- **For you**: AutoFill credential provider (passwords, passkeys, TOTP) on iOS/iPadOS/macOS, Safari extension,
  menu-bar quick search, import from 1Password / Apple Passwords / Chrome / Firefox / Bitwarden / CSV. *(apps: roadmap)*
- **For agents**: `agentkeyd` + `agentkey` CLI + MCP server. Agents get secrets injected into processes (never shown by
  default), read vault health findings (metadata only), and propose cleanup plans that **you** approve.
- **Personal & serverless**: every device holds the full encrypted vault; sync is ciphertext-only via CloudKit private DB.

> Status: **v0.2 (Phase 1.5)** — core crypto & vault, Mac daemon/CLI/MCP, importers, vault health + cleanup plans,
> sync model with 3-way merge (CloudKit adapter is a skeleton pending Mac validation). Not audited.

[中文说明](#中文说明) · [Design doc (zh)](docs/DESIGN.zh.md) · [Security](SECURITY.md)

---

## Architecture

```
 ┌───────────── agent (Claude Code / Cursor / script) ─────────────┐
 │  agentkey exec --env TOKEN=ak://OpenAI -- curl ...               │
 │  agentkey-mcp  (MCP stdio: list_items / run_with_secret / ...)   │
 └───────────────┬─────────────────────────────────────────────────┘
                 │ Unix socket ~/Library/Application Support/AgentKey/agent.sock (0600, same uid only)
                 │ 4-byte length + JSON (JSON-RPC 2.0 semantics), "progress" notifications
 ┌───────────────▼─────────────────────────────────────────────────┐
 │ agentkeyd  (LaunchAgent, Aqua session)                           │
 │  policy → ApprovalCoordinator (serialized, 60 s timeout)         │
 │        → LAContext (fresh, reuse 0, no password fallback)        │
 │          policy .deviceOwnerAuthenticationWithBiometricsOrCompanion
 │          = Touch ID keyboard  OR  Apple Watch                    │
 │  hash-chained audit log (audit.jsonl)                            │
 └───────────────┬─────────────────────────────────────────────────┘
                 │ AgentKeyCore
 ┌───────────────▼─────────────────────────────────────────────────┐
 │ vault.akv  JSON envelope, AES-256-GCM per item (AAD = vault/item/rev)
 │ VK wrapped by AUK = KDF(master password) ⊕ HKDF(Secret Key)      │
 │ Secret Key in Keychain (ThisDeviceOnly, not synced)              │
 └─────────────────────────────────────────────────────────────────┘
```

| Target | What |
|---|---|
| `AgentKeyCore` (macOS 14+/iOS 17+, also Linux) | **Importers** (1PUX, 1Password/Apple/Chrome/Firefox/Bitwarden/generic CSV, Bitwarden JSON, otpauth), **Hygiene** (`VaultHealth`, `CleanupPlan`), **Sync** (Lamport `Stamp`, `RecordMeta`, tombstones, `MergeEngine` 3-way merge, `CloudKitSyncAdapter` skeleton), CryptoKit AES-GCM + HKDF, 2SKD key hierarchy, `PasswordKDF` (PBKDF2-SHA256 600k today, Argon2id TODO), Secret Key, vault model (login / secure note / API token / TOTP), encrypted store, RFC 6238 TOTP, password generator, policy, prompt sanitizer, redactor, audit log |
| `AgentKeyIPC` | Unix-socket framing, peer credentials, daemon client |
| `agentkeyd` | per-user daemon; Touch ID / Apple Watch approval (`ApprovalGate.swift`) |
| `agentkey` | CLI (`ak` alias via installer) |
| `agentkey-mcp` | MCP stdio server |
| `App/` | placeholder SwiftUI multiplatform app |

### Release modes

| mode | plaintext goes to | default |
|---|---|---|
| `run` | child process env (`agentkey exec`, MCP `run_with_secret`); output redacted | ✅ |
| `totp` | only the current code | ✅ |
| `reveal` | caller (`agentkey get`, MCP `get_secret`) | ❌ must be enabled for the agent **and** the item |
| `http`, `inject`, `fill` | roadmap | — |

## Build & run on the Mac mini

Requirements: macOS 14+ (tested target: macOS 27, Xcode 26.2, Swift 6.2). For approvals you need **either** a
Magic Keyboard with Touch ID **or** an Apple Watch with *System Settings → Touch ID & Password → Apple Watch* enabled.

```bash
git clone https://github.com/neardws/AgentKey && cd AgentKey
swift build
swift test

# install binaries to ~/.local/bin and load the LaunchAgent (runs in your GUI session)
./Support/install-launchagent.sh
export PATH="$HOME/.local/bin:$PATH"

agentkey init                      # prints your Secret Key once — write it down
agentkey unlock                    # master password → daemon
agentkey status                    # touchIDReady / watchReady
agentkey add token --title OpenAI  # prompts for the token
agentkey add login --title GitHub --username neardws --generate
agentkey add totp  --title AWS --secret 'otpauth://totp/...'
agentkey list
agentkey exec --agent claude-code --env OPENAI_API_KEY=ak://OpenAI -- python my_script.py
agentkey totp ak://AWS
agentkey generate --length 32
agentkey audit verify

# migrate (export file is read into memory only; delete it afterwards)
agentkey import auto ~/Downloads/1PasswordExport.1pux --dry-run
agentkey import apple-csv ~/Downloads/Passwords.csv
agentkey import csv export.csv --map title=Account,password=Secret

# let an agent tidy up — it can only propose; you approve
agentkey health --json
agentkey plan create                 # or MCP propose_cleanup
agentkey plan show plan-1a2b3c4d
agentkey plan apply plan-1a2b3c4d --actions a1,a3   # Touch ID / Apple Watch
```

MCP tools: `list_items`, `run_with_secret`, `get_totp`, `get_secret` (off by default), `vault_health`,
`propose_cleanup`, `get_plan_status`. There is deliberately no tool to apply a plan.

**Agent-native output:** every command accepts `--json` (or `AGENTKEY_OUTPUT=json`); metadata commands
(`status`, `list`, `add`, `init`, `unlock`, `lock`, `audit`) emit JSON automatically when stdout is not a TTY.
Errors look like `{"ok":false,"error":{"code":"POLICY_DENIED","exit":65,"message":"..."}}`. For `exec`, the child's
output stays on stdout/stderr (redacted) and JSON metadata goes to stderr. `get`/`totp`/`generate` print the raw value
when piped unless `--json` is given.

**Redaction:** `exec` / `run_with_secret` redact every released secret on stdout and stderr, streaming-safe across chunk
boundaries. Secrets shorter than 8 characters are still redacted, but trigger a `SHORT_SECRET` warning because
redaction of short values is unreliable.

Optional policy: copy `Support/policy.example.json` to `~/Library/Application Support/AgentKey/policy.json`.

### MCP client config

```bash
claude mcp add agentkey -- ~/.local/bin/agentkey-mcp --agent claude-code
```
```json
{ "mcpServers": { "agentkey": { "command": "/Users/<you>/.local/bin/agentkey-mcp", "args": ["--agent", "cursor"] } } }
```
Set the client's tool timeout ≥ 90 s — approvals wait up to 60 s.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Mac core + agent channel: crypto, vault, `agentkeyd` Touch ID/Watch approvals, CLI, MCP, audit, `--json`, redaction | ✅ v0.1 |
| 1.5 | Importers, vault health + cleanup plans, sync model (Lamport, tombstones, 3-way merge), CKSyncEngine skeleton | ✅ v0.2 (sync adapter: Mac validation pending) |
| 2 | Encrypted SQLite record store, CKSyncEngine live sync, Argon2id, Secure Enclave unlock, signed app + App Group | ⏳ |
| 3 | iPhone / iPad / Mac apps, AutoFill extension (passwords + TOTP), menu-bar quick search, import wizard | ⏳ |
| 4 | Passkeys provider, Safari web extension, Chrome extension | ⏳ |
| 5 | Rotation assistant, `http`/`inject`/`fill` modes, grants & revoke, remote approval on iPhone, encrypted audit | ⏳ |

---

## 中文说明

AgentKey 是一个个人使用、开源、类似 1Password 的密码管理器，覆盖 Mac / iPhone / iPad。**人和 AI Agent 都是一等用户**：
你在所有 App 和网站里享受自动填充（密码、通行密钥、验证码），从 1Password / Apple 密码 / Chrome / Firefox / Bitwarden 一键迁移，
通过自己的 iCloud 端到端加密同步；Agent 则可以取用秘密、体检保险库并提出清理计划——
Agent 可以"使用"你的密码和 API Key，但每一次释放都必须由你本人在 Mac 上用 **Touch ID（妙控键盘）或双击 Apple Watch 侧边按钮** 确认；
推荐的 `run` 模式下，秘密只注入子进程环境变量，Agent 自己看不到明文；Agent 提出的清理计划（合并重复、归档、标记轮换等）也必须由你批准才会执行，且可撤销、全程审计。

### 安全模型（摘要）

- **双因素密钥派生（2SKD）**：AUK = PBKDF2(主密码) ⊕ HKDF(Secret Key)。只拿到加密的 vault 文件，没有本机 Secret Key 无法离线爆破。
- **逐条加密**：每个条目 AES-256-GCM，AAD 绑定保险库 ID / 条目 ID / 版本号，防止密文互换。
- **每次释放都要人确认**：每个请求新建 `LAContext`，复用时长 0，不允许退回登录密码；两种认证都不可用、超时（60 s）或非 GUI 会话时 **一律拒绝**。
- **防伪造提示**：系统弹框里的 Agent 名、条目名经过净化（去掉控制字符 / 双向文字覆盖 / 零宽字符，并截断），并显示 4 位关联码，与终端里的码对照。
- **明文默认不出门**：`reveal` 需要在策略里为该 Agent 开启，并且条目本身也允许。
- **审计**：追加写的 JSONL，SHA-256 哈希链 + HMAC（密钥由保险库密钥派生），`agentkey audit verify` 可检测篡改。

### 在 Mac mini 上构建运行

```bash
swift build && swift test
./Support/install-launchagent.sh      # 安装到 ~/.local/bin 并加载 LaunchAgent
agentkey init && agentkey unlock && agentkey status
```

注意：Mac mini 没有内置 Touch ID，需要配对带 Touch ID 的妙控键盘，或在"系统设置 → 触控 ID 与密码"中打开 Apple Watch 解锁。
`agentkeyd` 必须运行在你登录后的图形会话中（LaunchAgent 已设置 `LimitLoadToSessionType=Aqua`），从 SSH 启动将无法弹出确认框，请求会被拒绝。

### 路线图

Phase 1 ✅ Mac 核心 + Agent 通道 · Phase 1.5 ✅ 迁移导入、保险库体检与清理计划、同步模型（三方合并）·
Phase 2：加密 SQLite 记录库、CKSyncEngine 实际同步、Argon2id、Secure Enclave 快速解锁 ·
Phase 3：iPhone / iPad / Mac App、自动填充扩展、菜单栏快速搜索 · Phase 4：通行密钥、Safari / Chrome 扩展 ·
Phase 5：轮换助手、`http` 模式、iPhone 远程审批。

详细设计见 [docs/DESIGN.zh.md](docs/DESIGN.zh.md)。

## License

MIT © Neil Xu
