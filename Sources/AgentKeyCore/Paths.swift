import Foundation

public enum AKPaths {
    /// ~/Library/Application Support/AgentKey on macOS; $XDG_DATA_HOME/agentkey elsewhere.
    /// Override with AGENTKEY_HOME (used by tests).
    public static var home: URL {
        if let o = ProcessInfo.processInfo.environment["AGENTKEY_HOME"], !o.isEmpty { return URL(fileURLWithPath: o) }
        #if os(macOS) || os(iOS)
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentKey", isDirectory: true)
        #else
        let base = ProcessInfo.processInfo.environment["XDG_DATA_HOME"].map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share")
        return base.appendingPathComponent("agentkey", isDirectory: true)
        #endif
    }
    public static var vault: URL { home.appendingPathComponent("vault.akv") }
    public static var socket: URL { home.appendingPathComponent("agent.sock") }
    public static var audit: URL { home.appendingPathComponent("audit.jsonl") }
    public static var policy: URL { home.appendingPathComponent("policy.json") }
    public static var secretKeyFile: URL { home.appendingPathComponent("secret-key.txt") }
}
