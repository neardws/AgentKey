# AgentKey App (placeholder)

Phase 1 is Mac + CLI + MCP. This folder only holds a minimal SwiftUI multiplatform entry point.

## Create the Xcode project (Xcode 26.2)

1. Xcode → File → New → Project → **Multiplatform → App**. Product name `AgentKey`,
   bundle id `com.neardws.agentkey`, interface SwiftUI, save it into `App/`.
2. Delete the generated `AgentKeyApp.swift`/`ContentView.swift`, then drag in `Shared/AgentKeyApp.swift`.
3. File → Add Package Dependencies → **Add Local…** → choose the repo root; add the
   `AgentKeyCore` library to the app target.
4. Signing: choose your team. Add capabilities later: Keychain Sharing (`com.neardws.agentkey.shared`),
   App Groups, iCloud (CloudKit), AutoFill Credential Provider.
5. Run on "My Mac", an iPhone, or an iPad simulator.

中文：用 Xcode 新建 Multiplatform App 工程（bundle id `com.neardws.agentkey`），替换入口文件为
`Shared/AgentKeyApp.swift`，再以 "Add Local…" 方式引用仓库根目录的 Swift Package，并把 `AgentKeyCore` 加到 App target。
