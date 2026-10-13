import Foundation
import AgentKeyCore
import AgentKeyIPC
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

let usage = """
agentkey — Agent-Native password & secrets manager (CLI)

USAGE
  agentkey init                                  create vault + Secret Key (stored in Keychain)
  agentkey unlock [--secret-key A1-...]          unlock agentkeyd (asks master password)
  agentkey lock | status
  agentkey add login  --title T --username U [--password P | --generate] [--url URL]
  agentkey add token  --title T [--token V]
  agentkey add note   --title T [--text V]
  agentkey add totp   --title T [--secret BASE32|otpauth://...]
               common: [--modes run,totp,reveal]  (agent release modes allowed on this item)
  agentkey list [--json]
  agentkey get ak://<item>[/<field>]             plaintext via daemon (mode=reveal, OFF by default)
  agentkey totp ak://<item>                      current code via daemon (approval-gated)
  agentkey exec --env NAME=ak://item[/field] [--env ...] -- <cmd> [args...]
  agentkey generate [--length 24] [--no-symbols] [--words N]
  agentkey audit verify

Agent label: --agent L, else $AGENTKEY_AGENT, else "cli:<parent>".
Exit codes: 0 ok, 64 usage, 65 policy denied, 66 user denied, 67 timeout, 68 no approver, 69 daemon/locked.
"""

func die(_ msg: String, _ code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data("agentkey: \(msg)\n".utf8)); exit(code)
}
func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

var argv = Array(CommandLine.arguments.dropFirst())
guard let cmd = argv.first else { print(usage); exit(64) }
argv.removeFirst()

func opt(_ name: String) -> String? {
    guard let i = argv.firstIndex(of: name), i + 1 < argv.count else { return nil }
    let v = argv[i + 1]; argv.removeSubrange(i...(i + 1)); return v
}
func flag(_ name: String) -> Bool {
    guard let i = argv.firstIndex(of: name) else { return false }
    argv.remove(at: i); return true
}

func readSecret(_ prompt: String, env: String? = nil) -> String {
    if let env, let v = ProcessInfo.processInfo.environment[env] { return v }
    guard isatty(STDIN_FILENO) == 1 else {
        return readLine(strippingNewline: true) ?? ""   // piped input
    }
    guard let p = getpass(prompt) else { die("could not read input") }
    return String(cString: p)
}

func agentLabel() -> String {
    if let a = opt("--agent") { return a }
    if let a = ProcessInfo.processInfo.environment["AGENTKEY_AGENT"], !a.isEmpty { return a }
    #if os(macOS)
    var buf = [CChar](repeating: 0, count: 1024)
    if proc_name(getppid(), &buf, UInt32(buf.count)) > 0 { return "cli:" + String(cString: buf) }
    #else
    if let c = try? String(contentsOfFile: "/proc/\(getppid())/comm", encoding: .utf8) {
        return "cli:" + c.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    #endif
    return "cli"
}

func client() -> DaemonClient {
    do {
        let c = try DaemonClient()
        c.onProgress = { p in
            err("⏳ \(p["hint"] ?? "awaiting approval") — code [\(p["code"] ?? "?")] for \(p["ref"] ?? "")")
        }
        return c
    } catch let e as RPCError { die(e.message, e.kind.exitCode) }
    catch { die("\(error)", 69) }
}

func rpc(_ c: DaemonClient, _ m: String, _ p: [String: String]) -> [String: String] {
    do { return try c.call(m, p) }
    catch let e as RPCError { die(e.message, e.kind.exitCode) }
    catch { die("\(error)", 69) }
}

func openVaultLocally() -> Vault {
    let url = AKPaths.vault
    guard let acct = try? Vault.accountID(at: url) else { die("no vault at \(url.path); run `agentkey init`") }
    let sk = opt("--secret-key").flatMap(SecretKey.init(formatted:)) ?? SecretKeyStore.load(account: acct)
    guard let sk else { die("Secret Key not found in Keychain; pass --secret-key") }
    let pw = readSecret("Master password: ", env: "AGENTKEY_PASSWORD")
    do { return try Vault.unlock(at: url, password: pw, secretKey: sk) } catch { die("\(error)", 66) }
}

func parseModes(_ s: String?, default d: [ReleaseMode]) -> [ReleaseMode] {
    guard let s else { return d }
    return s.split(separator: ",").map { m in
        guard let r = ReleaseMode(rawValue: String(m)) else { die("unknown mode \(m)") }; return r
    }
}

switch cmd {
case "help", "-h", "--help":
    print(usage)

case "init":
    let url = AKPaths.vault
    if FileManager.default.fileExists(atPath: url.path) { die("vault already exists at \(url.path)") }
    let pw = readSecret("New master password: ", env: "AGENTKEY_PASSWORD")
    if ProcessInfo.processInfo.environment["AGENTKEY_PASSWORD"] == nil {
        guard readSecret("Repeat master password: ") == pw else { die("passwords differ") }
    }
    guard pw.count >= 12 else { die("master password must be at least 12 characters") }
    do {
        let (v, sk) = try Vault.create(at: url, password: pw)
        try SecretKeyStore.save(sk, account: v.file.accountID)
        print("""
        ✅ Vault created: \(url.path)
        Secret Key (write it down / print your Emergency Kit — needed on new devices):

            \(sk.formatted)

        It is stored in this Mac's Keychain (this device only, not iCloud).
        """)
    } catch { die("\(error)", 1) }

case "unlock":
    let c = client()
    var p = ["password": readSecret("Master password: ", env: "AGENTKEY_PASSWORD"), "agent": agentLabel()]
    if let sk = opt("--secret-key") { p["secretKey"] = sk }
    _ = rpc(c, "unlock", p); print("🔓 agentkeyd unlocked")

case "lock":
    _ = rpc(client(), "lock", ["agent": agentLabel()]); print("🔒 locked")

case "status":
    let r = rpc(client(), "status", ["agent": agentLabel()])
    for k in r.keys.sorted() { print("\(k): \(r[k]!)") }

case "add":
    guard let kind = argv.first else { die("add needs a kind: login|token|note|totp") }
    argv.removeFirst()
    guard let title = opt("--title") else { die("--title required") }
    let modesArg = opt("--modes")
    var item: VaultItem
    switch kind {
    case "login":
        guard let user = opt("--username") else { die("--username required") }
        let url = opt("--url")
        var pw = opt("--password")
        if flag("--generate") { pw = PasswordGenerator.generate() }
        let password = pw ?? readSecret("Password for \(title): ")
        item = .login(title: title, username: user, password: password, url: url)
    case "token": item = .apiToken(title: title, token: opt("--token") ?? readSecret("Token: "))
    case "note": item = .secureNote(title: title, text: opt("--text") ?? readSecret("Note: "))
    case "totp":
        let s = opt("--secret") ?? readSecret("TOTP secret or otpauth:// URI: ")
        guard TOTP(string: s) != nil else { die("invalid TOTP secret") }
        item = .totp(title: title, secretOrURI: s)
    default: die("unknown kind \(kind)")
    }
    item.agentModes = parseModes(modesArg, default: item.agentModes)
    let v = openVaultLocally()
    do {
        if (try v.items()).contains(where: { $0.title.caseInsensitiveCompare(title) == .orderedSame }) { die("an item titled '\(title)' exists") }
        try v.upsert(item)
    } catch { die("\(error)", 1) }
    print("added \(ItemRef.make(title: title))  modes=\(item.agentModes.map(\.rawValue).joined(separator: ","))")

case "list":
    let json = flag("--json")
    let r = rpc(client(), "list", ["agent": agentLabel()])
    let s = r["items"] ?? "[]"
    if json { print(s); break }
    let items = (try? JSONDecoder().decode([ItemOverview].self, from: Data(s.utf8))) ?? []
    for i in items.sorted(by: { $0.title.lowercased() < $1.title.lowercased() }) {
        let k = i.kind.rawValue.padding(toLength: 11, withPad: " ", startingAt: 0)
        print("\(k) \(i.ref)  [\(i.agentModes.map(\.rawValue).joined(separator: ","))]\(i.username.map { "  " + $0 } ?? "")")
    }

case "get":
    guard let ref = argv.first else { die("get needs a ref") }
    let r = rpc(client(), "release", ["ref": ref, "mode": "reveal", "agent": agentLabel()])
    guard let b = r["value"].flatMap({ Data(base64Encoded: $0) }) else { die("bad response", 69) }
    FileHandle.standardOutput.write(b)
    if isatty(STDOUT_FILENO) == 1 { print("") }

case "totp":
    guard let ref = argv.first else { die("totp needs a ref") }
    if let local = opt("--secret") {   // offline helper: compute from a given secret
        guard let t = TOTP(string: local) else { die("invalid secret") }
        print(t.code()); break
    }
    let r = rpc(client(), "totp", ["ref": ref, "agent": agentLabel()])
    print(r["code"] ?? "")
    err("(valid for \(r["expiresIn"] ?? "?")s)")

case "generate":
    if let w = opt("--words").flatMap(Int.init) { print(PasswordGenerator.passphrase(words: w)); break }
    var o = PasswordGenerator.Options(length: opt("--length").flatMap(Int.init) ?? 24)
    if flag("--no-symbols") { o.symbols = false }
    print(PasswordGenerator.generate(o))

case "exec", "run":
    guard let dd = argv.firstIndex(of: "--") else { die("usage: agentkey exec --env NAME=ak://... -- cmd args") }
    let command = Array(argv[(dd + 1)...]); argv = Array(argv[..<dd])
    guard !command.isEmpty else { die("missing command") }
    let agent = agentLabel()
    var envs: [(String, String)] = []
    while let e = opt("--env") {
        guard let eq = e.firstIndex(of: "=") else { die("--env expects NAME=ak://ref") }
        envs.append((String(e[..<eq]), String(e[e.index(after: eq)...])))
    }
    guard !envs.isEmpty else { die("at least one --env NAME=ak://ref required") }
    let c = client()
    var env = ProcessInfo.processInfo.environment
    var secrets: [(label: String, value: String)] = []
    for (name, ref) in envs {
        let r = rpc(c, "release", ["ref": ref, "mode": "run", "agent": agent, "command": command.joined(separator: " ")])
        guard let b = r["value"].flatMap({ Data(base64Encoded: $0) }) else { die("bad response", 69) }
        let v = String(decoding: b, as: UTF8.self)
        env[name] = v; secrets.append((r["ref"] ?? ref, v))
    }
    env.removeValue(forKey: "AGENTKEY_PASSWORD")
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = command
    p.environment = env
    // Child stdout/stderr are piped through the redactor (agents usually read this output).
    // --no-redact passes the TTY through untouched (interactive human use only).
    let redact = !flag("--no-redact")
    let red = Redactor(secrets: secrets)
    var pumps: [Thread] = []
    if redact {
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe; p.standardError = errPipe
        for (fh, out) in [(outPipe, FileHandle.standardOutput), (errPipe, FileHandle.standardError)] {
            let t = Thread {
                var buf = Data()
                while true {
                    let d = fh.fileHandleForReading.availableData
                    if d.isEmpty { break }
                    buf.append(d)
                    // flush complete lines so secrets split across reads are still caught per line
                    while let nl = buf.firstIndex(of: 0x0a) {
                        let line = buf[..<buf.index(after: nl)]
                        out.write(Data(red.redact(String(decoding: line, as: UTF8.self)).utf8))
                        buf.removeSubrange(..<buf.index(after: nl))
                    }
                }
                if !buf.isEmpty { out.write(Data(red.redact(String(decoding: buf, as: UTF8.self)).utf8)) }
            }
            pumps.append(t); t.start()
        }
    }
    do { try p.run() } catch { die("failed to start \(command[0]): \(error)", 1) }
    for i in secrets.indices { secrets[i].value = "" }
    p.waitUntilExit()
    while pumps.contains(where: { !$0.isFinished }) { usleep(10_000) }
    exit(p.terminationStatus)

case "audit":
    let r = rpc(client(), "audit.verify", ["agent": agentLabel()])
    if r["ok"] == "true" { print("✅ audit chain intact: \(r["count"] ?? "?") entries (mac checked: \(r["macChecked"] ?? "false"))") }
    else { die("❌ audit chain broken at seq \(r["seq"] ?? "?"): \(r["reason"] ?? "")", 1) }

default:
    print(usage); exit(64)
}
