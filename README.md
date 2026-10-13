# AgentKey

**Agent-Native password & secrets manager for Apple devices.**
面向 Apple 设备的 Agent 原生密码与密钥管理器。

AgentKey is a personal, open-source, 1Password-style vault for Mac, iPhone and iPad, designed from day one so that
AI agents (Claude Code, Cursor, Codex, MCP clients, scripts…) can *use* your secrets — while **you approve every
single release with Touch ID or a double-click on your Apple Watch**, and agents ideally never see the plaintext.

> Status: **v0.1 / Phase 1 (Mac-first)** — core crypto, vault, CLI, daemon and MCP server. Not audited. Don't put
> your only copy of important secrets in it yet.

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
| `AgentKeyCore` (macOS 14+/iOS 17+, also Linux) | CryptoKit AES-GCM + HKDF, 2SKD key hierarchy, `PasswordKDF` (PBKDF2-SHA256 600k today, Argon2id TODO), Secret Key, vault model (login / secure note / API token / TOTP), encrypted store, RFC 6238 TOTP, password generator, policy, prompt sanitizer, redactor, audit log |
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
```

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

- **Phase 1 (this release)**: Mac daemon, CLI, MCP, Touch ID / Watch approvals, audit log.
- **Phase 2**: Argon2id; Secure Enclave–wrapped VK (unlock without typing the master password), signed app +
  keychain ACL `[.biometryCurrentSet, .or, .companion]`; `http` / `inject` modes; grants & revoke; menu-bar app.
- **Phase 3**: iCloud (CloudKit private DB) sync with conflict resolution; iPhone / iPad apps.
- **Phase 4**: AutoFill Credential Provider extension, Safari web extension, passkeys (as provider), `fill` mode.

---

## 中文说明

AgentKey 是一个个人使用、开源、类似 1Password 的密码管理器，覆盖 Mac / iPhone / iPad，并且**从设计上就把 AI Agent 当作一等调用方**：
Agent 可以"使用"你的密码和 API Key，但每一次释放都必须由你本人在 Mac 上用 **Touch ID（妙控键盘）或双击 Apple Watch 侧边按钮** 确认；
推荐的 `run` 模式下，秘密只注入子进程环境变量，Agent 自己看不到明文。

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

Phase 2：Argon2id、Secure Enclave 快速解锁、签名 App + 钥匙串访问控制、`http`/`inject` 模式、菜单栏 App ·
Phase 3：iCloud（CloudKit）同步、iPhone / iPad App · Phase 4：自动填充扩展、Safari 扩展、通行密钥（Passkeys）。

详细设计见 [docs/DESIGN.zh.md](docs/DESIGN.zh.md)。

## License

MIT © Neil Xu
