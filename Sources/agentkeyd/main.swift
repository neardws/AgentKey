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
let acceptThread = Thread {
    while true {
        guard let conn = try? listener.accept() else { continue }
        Thread { daemon.serve(conn) }.start()
    }
}
acceptThread.start()
dispatchMain()
