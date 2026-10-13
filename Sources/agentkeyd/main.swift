import Foundation
import AgentKeyCore
import AgentKeyIPC
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// agentkeyd — per-user agent service. Must run inside the logged-in GUI (Aqua) session,
// e.g. as a LaunchAgent (see Support/com.neardws.agentkey.agentkeyd.plist), otherwise
// LocalAuthentication cannot show the Touch ID / Apple Watch sheet and requests fail closed.

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)
umask(0o077)

let args = CommandLine.arguments
if args.contains("--version") { print(AgentKeyVersion.string); exit(0) }
let socketPath = args.firstIndex(of: "--socket").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } ?? AKPaths.socket.path

let daemon = Daemon()
let listener: UnixListener
do { listener = try UnixListener(path: socketPath) }
catch { FileHandle.standardError.write(Data("agentkeyd: \(error)\n".utf8)); exit(1) }

for sig in [SIGINT, SIGTERM] {
    signal(sig) { _ in unlink(AKPaths.socket.path); exit(0) }
}

print("agentkeyd \(AgentKeyVersion.string) listening on \(socketPath)")

func argValue(_ n: String) -> String? { args.firstIndex(of: n).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
daemon.syncPort = argValue("--sync-port").flatMap(UInt16.init) ?? SyncNode.defaultPort
daemon.extraHosts = argValue("--host").map { $0.split(separator: ",").map(String.init) } ?? []

// --sync-node: this machine (e.g. an always-on Mac mini) is the home node: it listens for paired
// devices on TCP (LAN / Tailscale / WireGuard). No cloud, no third-party server.
if args.contains("--sync-node") {
    guard let node = daemon.sync else { FileHandle.standardError.write(Data("agentkeyd: cannot load sync state\n".utf8)); exit(1) }
    if node.replica == nil {
        guard let vid = try? Vault.vaultID(at: AKPaths.vault) else {
            FileHandle.standardError.write(Data("agentkeyd: --sync-node needs a vault; run `agentkey init` first\n".utf8)); exit(1)
        }
        do { _ = try node.initHome(vaultID: vid) } catch { FileHandle.standardError.write(Data("agentkeyd: \(error)\n".utf8)); exit(1) }
    }
    let host = argValue("--sync-host") ?? "0.0.0.0"
    let tcp: TCPListener
    do { tcp = try TCPListener(host: host, port: daemon.syncPort) }
    catch { FileHandle.standardError.write(Data("agentkeyd: sync listener: \(error)\n".utf8)); exit(1) }
    print("agentkeyd sync node \(node.identity.name) fingerprint \(node.identity.fingerprint) on \(host):\(tcp.port)")
    // TODO(mac): also advertise via Bonjour (_agentkey._tcp) with BonjourSyncListener from AppleTransports.swift.
    Thread {
        node.runListener(tcp, log: { print("sync: \($0)") }, before: { daemon.reconcileVault() }, after: { daemon.reconcileVault() })
    }.start()
}

// Background client sync for paired devices (every --sync-interval seconds, default 300; 0 disables).
let syncInterval = argValue("--sync-interval").flatMap(Double.init) ?? 300
if syncInterval > 0 {
    Thread {
        while true {
            Thread.sleep(forTimeInterval: syncInterval)
            guard let node = daemon.sync, node.replica != nil, !node.peers.endpoints.isEmpty else { continue }
            daemon.reconcileVault(); _ = try? node.syncNow(); daemon.reconcileVault()
        }
    }.start()
}
let acceptThread = Thread {
    while true {
        guard let conn = try? listener.accept() else { continue }
        Thread { daemon.serve(conn) }.start()
    }
}
acceptThread.start()
dispatchMain()
