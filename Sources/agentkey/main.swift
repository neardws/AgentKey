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
  agentkey add login  <title> --username U [--password P | --generate] [--url URL]
  agentkey add token  <title> [--token V]
  agentkey add note   <title> [--text V]
  agentkey add totp   <title> [--secret BASE32|otpauth://...]
               title may also be given as --title T; common: [--modes run,totp,reveal]  (agent release modes allowed on this item)
  agentkey list [--json]
  agentkey get ak://<item>[/<field>]             plaintext via daemon (mode=reveal, OFF by default)
  agentkey totp ak://<item>                      current code via daemon (approval-gated)
  agentkey exec --env NAME=ak://item[/field] [--env ...] -- <cmd> [args...]
  agentkey generate [--length 24] [--no-symbols] [--words N]
  agentkey import <auto|1pux|1password-csv|apple-csv|chrome-csv|firefox-csv|bitwarden-json|bitwarden-csv|csv> <file>
               [--dry-run] [--map title=Col,url=Col,username=Col,password=Col,notes=Col,totp=Col,tags=Col] [--modes ...]
  agentkey health [--stale-days N] [--rotation-days N]      findings only, never secret values
  agentkey plan create [--from actions.json] [--title T]     propose a cleanup plan (default: derived from health)
  agentkey plan show [<id>]
  agentkey plan apply <id> [--actions a1,a3]                 human-only: Touch ID / Apple Watch approval
  agentkey audit verify

SYNC (no cloud, no server: your devices + an always-on home node, e.g. a Mac mini running `agentkeyd --sync-node`)
  agentkey device pair [--show] [--host H,..] [--ttl SEC]   on the home node: print a one-time pairing code (QR text)
  agentkey device pair <agentkey-pair:...>                  on the new device: join (pins the node fingerprint)
  agentkey device list                                      paired devices, fingerprints, last sync
  agentkey device revoke <device-id|name|fingerprint>       human-only; rotates the vault key
  agentkey sync now | status                                sync with the home node now / show state
  agentkey backup export <file>                             encrypted offline backup (passphrase; $AGENTKEY_BACKUP_PASSPHRASE)
  agentkey backup restore <file>                            human-only; merges items into the vault

Agent label: --agent L, else $AGENTKEY_AGENT, else "cli:<parent>".
Output: --json (or AGENTKEY_OUTPUT=json) for JSON on every command; metadata commands
  (status/list/add/init/unlock/lock/audit) default to JSON when stdout is not a TTY. --text forces text.
  Errors in JSON: {"ok":false,"error":{"code":"POLICY_DENIED","exit":65,"message":...}}.
  exec: child output stays on stdout/stderr; JSON metadata/errors go to stderr.
Exit codes: 0 ok, 64 USAGE, 65 POLICY_DENIED, 66 USER_DENIED/BAD_PASSWORD, 67 TIMEOUT,
  68 NO_APPROVER, 69 DAEMON_UNAVAILABLE/LOCKED, 70 NOT_FOUND, 1 other; exec returns the child's code.
"""

func die(_ msg: String, _ code: CLIError = .usage) -> Never { Out.fail(msg, code) }
func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

var argv = Array(CommandLine.arguments.dropFirst())
guard let cmd = argv.first else { print(usage); exit(64) }
argv.removeFirst()

// Commands whose stdout is the secret/value itself stay raw when piped unless --json is given,
// so `X=$(agentkey get ...)` keeps working. Everything else defaults to JSON when piped.
let rawValueCommands: Set<String> = ["get", "totp", "generate", "exec", "run", "help", "-h", "--help"]  // import/health/plan auto-JSON when piped
do {
    // only look at flags before a `--` (exec passes the rest to the child)
    let head = argv.firstIndex(of: "--").map { Array(argv[..<$0]) } ?? argv
    let j = head.contains("--json"), t = head.contains("--text")
    if let i = argv.firstIndex(of: "--json"), i < (argv.firstIndex(of: "--") ?? argv.count) { argv.remove(at: i) }
    if let i = argv.firstIndex(of: "--text"), i < (argv.firstIndex(of: "--") ?? argv.count) { argv.remove(at: i) }
    Out.decide(explicitJSON: j, explicitText: t, autoJSONWhenPiped: !rawValueCommands.contains(cmd))
    if cmd == "exec" || cmd == "run" { Out.jsonToStderr = true }
}

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
            if Out.json {
                FileHandle.standardError.write(Out.encode(["progress": p]) + Data([0x0a]))
            } else {
                err("⏳ \(p["hint"] ?? "awaiting approval") — code [\(p["code"] ?? "?")] for \(p["ref"] ?? "")")
            }
        }
        return c
    } catch let e as RPCError { die(e.message, CLIError(e)) }
    catch { die("\(error)", .daemonUnavailable) }
}

func rpc(_ c: DaemonClient, _ m: String, _ p: [String: String]) -> [String: String] {
    do { return try c.call(m, p) }
    catch let e as RPCError { die(e.message, CLIError(e)) }
    catch { die("\(error)", .daemonUnavailable) }
}

func openVaultLocally() -> Vault {
    let url = AKPaths.vault
    guard let acct = try? Vault.accountID(at: url) else { die("no vault at \(url.path); run `agentkey init`") }
    let sk = opt("--secret-key").flatMap(SecretKey.init(formatted:)) ?? SecretKeyStore.load(account: acct)
    guard let sk else { die("Secret Key not found in Keychain; pass --secret-key") }
    let pw = readSecret("Master password: ", env: "AGENTKEY_PASSWORD")
    do { return try Vault.unlock(at: url, password: pw, secretKey: sk) } catch { die("\(error)", .badPassword) }
}

func parseModes(_ s: String?, default d: [ReleaseMode]) -> [ReleaseMode] {
    guard let s else { return d }
    return s.split(separator: ",").map { m in
        guard let r = ReleaseMode(rawValue: String(m)) else { die("unknown mode \(m)") }; return r
    }
}

func boolish(_ r: [String: String]) -> [String: Any] {
    var o: [String: Any] = [:]
    for (k, v) in r { o[k] = v == "true" ? true : v == "false" ? false : (Int(v).map { $0 as Any } ?? v) }
    return o
}

switch cmd {
case "help", "-h", "--help":
    print(usage)

case "init":
    let url = AKPaths.vault
    if FileManager.default.fileExists(atPath: url.path) { die("vault already exists at \(url.path)", .exists) }
    let pw = readSecret("New master password: ", env: "AGENTKEY_PASSWORD")
    if ProcessInfo.processInfo.environment["AGENTKEY_PASSWORD"] == nil {
        guard readSecret("Repeat master password: ") == pw else { die("passwords differ") }
    }
    guard pw.count >= 12 else { die("master password must be at least 12 characters") }
    do {
        let (v, sk) = try Vault.create(at: url, password: pw)
        try SecretKeyStore.save(sk, account: v.file.accountID)
        if Out.json {
            Out.emit(["vault": url.path, "accountID": v.file.accountID.uuidString, "secretKey": sk.formatted,
                      "secretKeyStoredIn": "keychain (this device only)"])
        } else {
            print("""
            ✅ Vault created: \(url.path)
            Secret Key (write it down / print your Emergency Kit — needed on new devices):

                \(sk.formatted)

            It is stored in this Mac's Keychain (this device only, not iCloud).
            """)
        }
    } catch { die("\(error)", .internalError) }

case "unlock":
    let c = client()
    var p = ["password": readSecret("Master password: ", env: "AGENTKEY_PASSWORD"), "agent": agentLabel()]
    if let sk = opt("--secret-key") { p["secretKey"] = sk }
    _ = rpc(c, "unlock", p)
    if Out.json { Out.emit(["locked": false]) } else { print("🔓 agentkeyd unlocked") }

case "lock":
    _ = rpc(client(), "lock", ["agent": agentLabel()])
    if Out.json { Out.emit(["locked": true]) } else { print("🔒 locked") }

case "status":
    let r = rpc(client(), "status", ["agent": agentLabel()])
    if Out.json { Out.emit(boolish(r)) } else { for k in r.keys.sorted() { print("\(k): \(r[k]!)") } }

case "add":
    guard let kind = argv.first else { die("add needs a kind: login|token|note|totp") }
    argv.removeFirst()
    let modesArg = opt("--modes")
    let titleOpt = opt("--title")
    var item: VaultItem
    var title = ""
    // Title may be given as --title T or as the first positional argument: `agentkey add token OpenAI`
    func takeTitle() -> String {
        if let t = titleOpt { return t }
        if let i = argv.firstIndex(where: { !$0.hasPrefix("--") }) { return argv.remove(at: i) }
        die("title required: agentkey add \(kind) <title> (or --title <title>)")
    }
    switch kind {
    case "login":
        guard let user = opt("--username") else { die("--username required") }
        let url = opt("--url")
        var pw = opt("--password")
        if flag("--generate") { pw = PasswordGenerator.generate() }
        title = takeTitle()
        let password = pw ?? readSecret("Password for \(title): ")
        item = .login(title: title, username: user, password: password, url: url)
    case "token":
        let tok = opt("--token"); title = takeTitle()
        item = .apiToken(title: title, token: tok ?? readSecret("Token: "))
    case "note":
        let text = opt("--text"); title = takeTitle()
        item = .secureNote(title: title, text: text ?? readSecret("Note: "))
    case "totp":
        let sec = opt("--secret"); title = takeTitle()
        let s = sec ?? readSecret("TOTP secret or otpauth:// URI: ")
        guard TOTP(string: s) != nil else { die("invalid TOTP secret") }
        item = .totp(title: title, secretOrURI: s)
    default: die("unknown kind \(kind) (login|token|note|totp)")
    }
    if let extra = argv.first { die("unexpected argument: \(extra)") }
    item.agentModes = parseModes(modesArg, default: item.agentModes)
    if let v = item.field(nil)?.value, v.utf8.count < Redactor.minimumSafeLength, item.kind != .totp {
        Out.warn("value is shorter than \(Redactor.minimumSafeLength) characters; output redaction for `exec` is unreliable",
                 code: "SHORT_SECRET", extra: ["ref": ItemRef.make(title: title)])
    }
    let v = openVaultLocally()
    do {
        if (try v.items()).contains(where: { $0.title.caseInsensitiveCompare(title) == .orderedSame }) { die("an item titled '\(title)' exists", .exists) }
        try v.upsert(item)
    } catch { die("\(error)", .internalError) }
    if Out.json {
        Out.emit(["ref": ItemRef.make(title: title), "id": item.id.uuidString, "kind": item.kind.rawValue,
                  "agentModes": item.agentModes.map(\.rawValue)])
    } else {
        print("added \(ItemRef.make(title: title))  modes=\(item.agentModes.map(\.rawValue).joined(separator: ","))")
    }

case "list":
    let r = rpc(client(), "list", ["agent": agentLabel()])
    let s = r["items"] ?? "[]"
    let items: [ItemOverview] = (try? JSONDecoder().decode([ItemOverview].self, from: Data(s.utf8))) ?? []
    if Out.json {
        let arr = (try? JSONSerialization.jsonObject(with: Data(s.utf8))) ?? []
        Out.emit(["items": arr, "count": items.count])
        break
    }
    for i in items.sorted(by: { $0.title.lowercased() < $1.title.lowercased() }) {
        let k = i.kind.rawValue.padding(toLength: 11, withPad: " ", startingAt: 0)
        print("\(k) \(i.ref)  [\(i.agentModes.map(\.rawValue).joined(separator: ","))]\(i.username.map { "  " + $0 } ?? "")")
    }

case "get":
    guard let ref = argv.first else { die("get needs a ref") }
    let r = rpc(client(), "release", ["ref": ref, "mode": "reveal", "agent": agentLabel()])
    guard let b = r["value"].flatMap({ Data(base64Encoded: $0) }) else { die("bad response from agentkeyd", .internalError) }
    if Out.json {
        Out.emit(["ref": r["ref"] ?? ref, "value": String(decoding: b, as: UTF8.self), "correlation": r["correlation"] ?? ""])
    } else {
        FileHandle.standardOutput.write(b)
        if isatty(STDOUT_FILENO) == 1 { print("") }
    }

case "totp":
    if let local = opt("--secret") {   // offline helper: compute from a given secret
        guard let t = TOTP(string: local) else { die("invalid secret") }
        if Out.json { Out.emit(["code": t.code(), "expiresIn": t.secondsRemaining()]) } else { print(t.code()) }
        break
    }
    guard let ref = argv.first else { die("totp needs a ref") }
    let r = rpc(client(), "totp", ["ref": ref, "agent": agentLabel()])
    if Out.json {
        Out.emit(["ref": ref, "code": r["code"] ?? "", "expiresIn": Int(r["expiresIn"] ?? "") ?? 0, "correlation": r["correlation"] ?? ""])
    } else {
        print(r["code"] ?? "")
        err("(valid for \(r["expiresIn"] ?? "?")s)")
    }

case "generate":
    let words = opt("--words").flatMap(Int.init)
    var o = PasswordGenerator.Options(length: opt("--length").flatMap(Int.init) ?? 24)
    if flag("--no-symbols") { o.symbols = false }
    guard o.length >= 4 && o.length <= 1024 else { die("--length must be 4...1024") }
    let pw = words.map { PasswordGenerator.passphrase(words: $0) } ?? PasswordGenerator.generate(o)
    if Out.json { Out.emit(["password": pw]) } else { print(pw) }

case "exec", "run":
    guard let dd = argv.firstIndex(of: "--") else { die("usage: agentkey exec --env NAME=ak://... -- cmd args") }
    let command = Array(argv[(dd + 1)...]); argv = Array(argv[..<dd])
    guard !command.isEmpty else { die("missing command") }
    let agent = agentLabel()
    let redact = !flag("--no-redact")
    var envs: [(String, String)] = []
    while let e = opt("--env") {
        guard let eq = e.firstIndex(of: "=") else { die("--env expects NAME=ak://ref") }
        envs.append((String(e[..<eq]), String(e[e.index(after: eq)...])))
    }
    guard !envs.isEmpty else { die("at least one --env NAME=ak://ref required") }
    if let extra = argv.first { die("unexpected argument before --: \(extra)") }
    let c = client()
    var env = ProcessInfo.processInfo.environment
    var secrets: [(label: String, value: String)] = []
    var released: [[String: Any]] = []
    for (name, ref) in envs {
        let r = rpc(c, "release", ["ref": ref, "mode": "run", "agent": agent, "command": command.joined(separator: " ")])
        guard let b = r["value"].flatMap({ Data(base64Encoded: $0) }) else { die("bad response from agentkeyd", .internalError) }
        let v = String(decoding: b, as: UTF8.self)
        env[name] = v; secrets.append((r["ref"] ?? ref, v))
        released.append(["env": name, "ref": r["ref"] ?? ref, "correlation": r["correlation"] ?? "",
                         "length": v.utf8.count, "weak": v.utf8.count < Redactor.minimumSafeLength])
    }
    env.removeValue(forKey: "AGENTKEY_PASSWORD")
    let red = Redactor(secrets: secrets)
    if let w = red.warning, redact { Out.warn(w, code: "SHORT_SECRET", extra: ["refs": red.weakSecrets]) }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = command
    p.environment = env
    // Child stdout AND stderr are piped through a streaming redactor that is safe across chunk
    // boundaries. --no-redact passes output through untouched (interactive human use only).
    var pumps: [Thread] = []
    if redact {
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe; p.standardError = errPipe
        for (fh, out) in [(outPipe, FileHandle.standardOutput), (errPipe, FileHandle.standardError)] {
            let stream = red.stream()
            let t = Thread {
                while true {
                    let d = fh.fileHandleForReading.availableData
                    if d.isEmpty { break }
                    let o = stream.feed(d)
                    if !o.isEmpty { out.write(o) }
                }
                let tail = stream.finish()
                if !tail.isEmpty { out.write(Data(tail)) }
            }
            pumps.append(t); t.start()
        }
    }
    do { try p.run() } catch { die("failed to start \(command[0]): \(error)", .spawnFailed) }
    for i in secrets.indices { secrets[i].value = "" }
    for k in envs.map(\.0) { env[k] = nil }
    p.waitUntilExit()
    while pumps.contains(where: { !$0.isFinished }) { usleep(10_000) }
    if Out.json {
        Out.emit(["exec": ["command": command, "exitCode": Int(p.terminationStatus), "redacted": redact,
                           "released": released, "warnings": red.warning.map { [$0] } ?? []]])
    }
    exit(p.terminationStatus)

case "import":
    // agentkey import <format|auto> <file> [--dry-run] [--map title=Col,password=Col,...] [--modes run,totp]
    let dry = flag("--dry-run")
    let mapSpec = opt("--map")
    let modesArg = opt("--modes")
    guard argv.count == 2 else { die("usage: agentkey import <auto|\(ImportFormat.allCases.map(\.rawValue).joined(separator: "|"))> <file> [--dry-run] [--map k=Column,...]") }
    let fmtArg = argv[0], path = argv[1]
    guard let data = FileManager.default.contents(atPath: path) else { die("cannot read \(path)", .notFound) }
    let fmt: ImportFormat
    do {
        fmt = fmtArg == "auto" ? try Importer.detect(data: data, filename: path) : try ImportFormat(rawValue: fmtArg) ?? { throw ImportError.unrecognized("unknown format \(fmtArg)") }()
    } catch { die("\(error)") }
    var result: ImportResult
    do { result = try Importer.parse(data: data, format: fmt, columnMap: try mapSpec.map(CSVColumnMap.init(spec:)) ?? CSVColumnMap()) }
    catch { die("\(error)") }
    if let m = modesArg { let modes = parseModes(m, default: []); for i in result.items.indices { result.items[i].agentModes = modes } }
    result.report.dryRun = dry
    if !dry {
        let v = openVaultLocally()
        do {
            Importer.dropExisting(&result, existing: try v.items())
            for item in result.items { try v.upsert(item) }
        } catch { die("\(error)", .internalError) }
        result.report.warnings.append("the export file \(path) still contains plaintext — securely delete it")
    }
    let r = result.report
    if Out.json {
        let rep = (try? JSONSerialization.jsonObject(with: JSONEncoder().encode(r))) ?? [:]
        Out.emit(["import": rep, "items": result.items.map { ["ref": ItemRef.make(title: $0.title), "kind": $0.kind.rawValue,
                                                              "hasTOTP": $0.fields.contains { $0.id == "totp" }] as [String: Any] }])
    } else {
        print("\(dry ? "[dry run] would import" : "imported") \(r.imported) of \(r.totalInSource) (\(r.format.rawValue)); " +
              "\(r.withTOTP) with TOTP; duplicates: \(r.duplicatesInSource) in file, \(r.duplicatesOfExisting) already in vault")
        for k in r.byKind.keys.sorted() where r.byKind[k]! > 0 { print("  \(k): \(r.byKind[k]!)") }
        for sk in r.skipped { print("  skipped #\(sk.index) \(sk.title ?? "(untitled)"): \(sk.reason)") }
        for w in r.warnings { err("warning: \(w)") }
        if !dry { print("Imported items have no agent access by default; enable per item with `--modes` or in the app.") }
    }

case "health":
    var p = ["agent": agentLabel()]
    if let d = opt("--stale-days") { p["staleDays"] = d }
    if let d = opt("--rotation-days") { p["rotationDays"] = d }
    let r = rpc(client(), "health", p)
    let s = r["report"] ?? "{}"
    if Out.json { Out.emit(["health": (try? JSONSerialization.jsonObject(with: Data(s.utf8))) ?? [:]]); break }
    guard let rep = try? Vault.decoder.decode(HealthReport.self, from: Data(s.utf8)) else { die("bad report", .internalError) }
    print("Vault health: \(rep.score)/100 — \(rep.itemCount) items, \(rep.findings.count) findings")
    for f in rep.findings { print("  [\(f.severity.rawValue)] \(f.kind.rawValue): \(f.refs.joined(separator: ", ")) — \(f.detail)") }

case "plan":
    guard let sub = argv.first else { die("usage: agentkey plan create [--from actions.json] | show [id] | apply <id> [--actions a1,a3]") }
    argv.removeFirst()
    func showPlan(_ s: String) {
        if Out.json { Out.emit(["plan": (try? JSONSerialization.jsonObject(with: Data(s.utf8))) ?? [:]]); return }
        guard let p = try? Vault.decoder.decode(CleanupPlan.self, from: Data(s.utf8)) else { print(s); return }
        print("\(p.id)  [\(p.status.rawValue)]  \(p.title)  by \(p.createdBy)")
        for a in p.actions {
            print("  \(a.id) \(a.state.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(a.kind.rawValue) \(a.itemIDs.count) item(s)\(a.tags.map { " tags=" + $0.joined(separator: ",") } ?? "") — \(a.reason)")
        }
    }
    switch sub {
    case "create":
        var p = ["agent": agentLabel()]
        if let f = opt("--from") {
            guard let d = FileManager.default.contents(atPath: f) else { die("cannot read \(f)", .notFound) }
            p["actions"] = String(decoding: d, as: UTF8.self)
        }
        if let t = opt("--title") { p["title"] = t }
        showPlan(rpc(client(), "plan.create", p)["plan"] ?? "{}")
    case "show":
        if let id = argv.first { showPlan(rpc(client(), "plan.show", ["id": id, "agent": agentLabel()])["plan"] ?? "{}"); break }
        let s = rpc(client(), "plan.show", ["agent": agentLabel()])["plans"] ?? "[]"
        if Out.json { Out.emit(["plans": (try? JSONSerialization.jsonObject(with: Data(s.utf8))) ?? []]); break }
        for p in (try? Vault.decoder.decode([CleanupPlan].self, from: Data(s.utf8))) ?? [] {
            print("\(p.id)  [\(p.status.rawValue)]  \(p.actions.count) actions  by \(p.createdBy)  \(p.title)")
        }
    case "apply":
        guard let id = argv.first else { die("plan apply needs a plan id") }
        var p = ["id": id, "agent": agentLabel()]
        if let a = opt("--actions") { p["actions"] = a }
        let r = rpc(client(), "plan.apply", p)
        showPlan(r["plan"] ?? "{}")
        if !Out.json { print("changed \(r["changed"] ?? "0") item(s), purged \(r["purged"] ?? "0") — undo with a `restore` plan; previous values are in item history") }
    default: die("unknown plan subcommand \(sub)")
    }

case "device", "sync":
    let sub = argv.first ?? (cmd == "sync" ? "status" : "list")
    if !argv.isEmpty { argv.removeFirst() }
    func statusObj(_ r: [String: String]) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data((r["status"] ?? "{}").utf8))) as? [String: Any] ?? [:]
    }
    func printDevices(_ st: [String: Any]) {
        print("this device: \(st["name"] ?? "?")  fp \(st["fingerprint"] ?? "?")\(st["isHomeNode"] as? Bool == true ? "  [home node]" : "")")
        guard st["initialized"] as? Bool == true else { print("not paired — run `agentkey device pair` on the home node, then `agentkey device pair <code>` here"); return }
        print("items in sync replica: \(st["items"] ?? 0), key version \(st["keyVersion"] ?? 0)")
        for d in st["devices"] as? [[String: Any]] ?? [] {
            var tags: [String] = []
            if d["isSelf"] as? Bool == true { tags.append("this") }
            if d["isHomeNode"] as? Bool == true { tags.append("home") }
            if d["revoked"] as? Bool == true { tags.append("REVOKED") }
            let last = (d["lastSync"] as? String) ?? "-"
            let id8 = String((d["deviceID"] as? String ?? "").prefix(8))
            let nm = (d["name"] as? String ?? "").padding(toLength: 18, withPad: " ", startingAt: 0)
            let fp = d["fingerprint"] as? String ?? ""
            let pend = d["pendingOut"] as? Int ?? 0
            let tagStr = tags.isEmpty ? "" : "  [" + tags.joined(separator: ",") + "]"
            print("  \(id8)  \(nm) \(fp)  last sync \(last)  pending \(pend)" + tagStr)
        }
    }
    switch (cmd, sub) {
    case ("device", "list"), ("sync", "status"):
        let st = statusObj(rpc(client(), "sync.status", ["agent": agentLabel()]))
        if Out.json { Out.emit(["sync": st]) } else { printDevices(st) }
    case ("device", "pair"):
        if let uri = argv.first(where: { $0.hasPrefix("agentkey-pair:") }) {
            guard let p = try? PairingPayload(uri: uri) else { die("invalid pairing code") }
            if !Out.json { err("joining \(p.nodeName) — verify this fingerprint matches the one shown on the home node:\n  \(p.fingerprint)") }
            let r = rpc(client(), "device.pair.join", ["uri": uri, "agent": agentLabel()])
            if Out.json {
                let o: [String: String] = ["deviceID": r["deviceID"] ?? "", "fingerprint": r["fingerprint"] ?? "", "node": p.nodeName, "nodeFingerprint": p.fingerprint]
                Out.emit(["paired": o])
            }
            else { print("✅ paired with \(p.nodeName). This device: \(r["fingerprint"] ?? "")\(r["vaultUnlocked"] == "true" ? "" : " (unlock the vault to merge items)")") }
        } else {
            _ = flag("--show")
            var p = ["agent": agentLabel()]
            if let h = opt("--host") { p["hosts"] = h }
            if let t = opt("--ttl") { p["ttl"] = t }
            let r = rpc(client(), "device.pair.offer", p)
            if Out.json {
                let hosts: [String] = (r["hosts"] ?? "").split(separator: ",").map(String.init)
                var o: [String: Any] = ["uri": r["uri"] ?? "", "fingerprint": r["fingerprint"] ?? "", "expires": r["expires"] ?? ""]
                o["hosts"] = hosts; o["port"] = Int(r["port"] ?? "") ?? 0
                Out.emit(["pairing": o])
            }
            else {
                print("One-time pairing code (expires \(r["expires"] ?? "?"); single use). Scan as QR or paste on the new device:\n")
                print("  agentkey device pair \(r["uri"] ?? "")\n")
                print("Home node fingerprint (confirm on the new device): \(r["fingerprint"] ?? "")")
                print("Reachable at: \(r["hosts"] ?? "") port \(r["port"] ?? "")   (add Tailscale/WireGuard names with --host)")
            }
        }
    case ("device", "revoke"):
        guard let d = argv.first else { die("usage: agentkey device revoke <device-id|name|fingerprint>") }
        let r = rpc(client(), "device.revoke", ["device": d, "agent": agentLabel()])
        if Out.json { Out.emit(["revoked": ["device": r["device"] ?? "", "keyVersion": Int(r["keyVersion"] ?? "") ?? 0]]) }
        else { print("✅ revoked \(r["device"] ?? d); vault key rotated. New records are unreadable to it; change any secret it may have seen.") }
    case ("sync", "now"):
        let r = rpc(client(), "sync.now", ["agent": agentLabel()])
        let peers = (try? JSONSerialization.jsonObject(with: Data((r["peers"] ?? "[]").utf8))) as? [[String: String]] ?? []
        if Out.json {
            var o: [String: Any] = ["peers": peers, "vaultUnlocked": r["vaultUnlocked"] == "true"]
            o["toReplica"] = Int(r["toReplica"] ?? "") ?? 0; o["toVault"] = Int(r["toVault"] ?? "") ?? 0
            Out.emit(["sync": o])
        }
        else {
            if peers.isEmpty { print("no peers with known addresses") }
            for p in peers {
                if p["ok"] == "true" { print("✅ \(p["name"] ?? ""): received \(p["received"] ?? "0"), sent \(p["sent"] ?? "0"), conflicts merged \(p["conflicts"] ?? "0")") }
                else { print("❌ \(p["name"] ?? ""): \(p["error"] ?? "")") }
            }
            if r["vaultUnlocked"] != "true" { print("(vault locked: replica synced; items merge into the vault on next unlock)") }
        }
    default:
        die("usage: agentkey device pair|list|revoke  /  agentkey sync now|status")
    }

case "backup":
    guard argv.count >= 2, ["export", "restore"].contains(argv[0]) else { die("usage: agentkey backup export|restore <file>") }
    let sub = argv[0], path = URL(fileURLWithPath: argv[1]).path
    let pass = readSecret("Backup passphrase: ", env: "AGENTKEY_BACKUP_PASSPHRASE")
    if sub == "export" {
        if ProcessInfo.processInfo.environment["AGENTKEY_BACKUP_PASSPHRASE"] == nil, isatty(STDIN_FILENO) == 1 {
            guard readSecret("Repeat passphrase: ") == pass else { die("passphrases do not match") }
        }
        let r = rpc(client(), "backup.export", ["path": path, "passphrase": pass, "agent": agentLabel()])
        if Out.json { Out.emit(["backup": ["path": path, "items": Int(r["items"] ?? "") ?? 0]]) }
        else { print("✅ wrote encrypted backup of \(r["items"] ?? "?") item(s) to \(path). Store the passphrase separately.") }
    } else {
        let r = rpc(client(), "backup.restore", ["path": path, "passphrase": pass, "agent": agentLabel()])
        if Out.json {
            let o: [String: Int] = ["added": Int(r["added"] ?? "") ?? 0, "updated": Int(r["updated"] ?? "") ?? 0, "inBackup": Int(r["inBackup"] ?? "") ?? 0]
            Out.emit(["restore": o])
        }
        else { print("✅ restored: \(r["added"] ?? "0") added, \(r["updated"] ?? "0") updated (of \(r["inBackup"] ?? "0") in backup)") }
    }

case "audit":
    let r = rpc(client(), "audit.verify", ["agent": agentLabel()])
    if r["ok"] == "true" {
        if Out.json { Out.emit(["audit": ["intact": true, "count": Int(r["count"] ?? "") ?? 0, "macChecked": r["macChecked"] == "true"]]) }
        else { print("✅ audit chain intact: \(r["count"] ?? "?") entries (mac checked: \(r["macChecked"] ?? "false"))") }
    } else {
        die("audit chain broken at seq \(r["seq"] ?? "?"): \(r["reason"] ?? "")", .auditBroken)
    }

default:
    die("unknown command \(cmd); see `agentkey help`")
}
