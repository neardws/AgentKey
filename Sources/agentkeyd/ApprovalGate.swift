// ApprovalGate.swift — Touch ID OR Apple Watch approval for agent secret requests.
// Adapted from the original prototype: fresh LAContext per request, reuse duration 0,
// no password fallback (fail closed), sanitized prompt text, correlation code, timeout.
import Foundation
import AgentKeyCore

public enum ApprovalError: Error, Sendable, CustomStringConvertible {
    case noApproverAvailable(String)   // no Touch ID keyboard AND no unlocked, nearby Watch
    case denied                         // user cancelled / auth failed
    case lockedOut                      // biometry lockout; type login password once at the Mac
    case notInteractive                 // no GUI session (SSH, launchd system daemon, locked screen)
    case timeout
    case other(Int)
    public var description: String {
        switch self {
        case .noApproverAvailable(let s): return "no approver available: \(s)"
        case .denied: return "denied by user"
        case .lockedOut: return "Touch ID locked out; enter the login password at the Mac once"
        case .notInteractive: return "no interactive GUI session (agentkeyd must run as a LaunchAgent in the Aqua session)"
        case .timeout: return "approval timed out"
        case .other(let c): return "LocalAuthentication error \(c)"
        }
    }
}

public struct ApproverStatus: Sendable {
    public let touchIDReady: Bool
    public let watchReady: Bool
    public let detail: String
}

public struct ApprovalRequest: Sendable {
    public var agent: String
    public var secretName: String
    public var mode: ReleaseMode
    public var code: String
    public var command: String?
    /// Text shown in the system sheet: "<App> is trying to <reason>".
    public var reason: String {
        let a = PromptSanitizer.clean(agent, max: 32), s = PromptSanitizer.clean(secretName, max: 40)
        switch mode {
        case .reveal: return "release PLAINTEXT of “\(s)” to agent “\(a)” [\(code)]"
        case .totp: return "give a one-time code for “\(s)” to agent “\(a)” [\(code)]"
        case .run:
            let c = command.map { " for: " + PromptSanitizer.clean($0, max: 60) } ?? ""
            return "inject “\(s)” into a process for agent “\(a)”\(c) [\(code)]"
        default: return "release “\(s)” (\(mode.rawValue)) to agent “\(a)” [\(code)]"
        }
    }
}

#if canImport(LocalAuthentication)
import LocalAuthentication

final class Flag: @unchecked Sendable { var value = false }

actor ApprovalGate {
    private var policy: LAPolicy {
        if #available(macOS 15.0, iOS 18.0, *) { return .deviceOwnerAuthenticationWithBiometricsOrCompanion }
        return .deviceOwnerAuthenticationWithBiometricsOrWatch   // same raw value (4) on older SDKs
    }

    func status() -> ApproverStatus {
        let bio = LAContext(); var e1: NSError?
        let touch = bio.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e1)
        var w = false; var e2: NSError?
        if #available(macOS 15.0, iOS 18.0, *) {
            w = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithCompanion, error: &e2)
        } else {
            #if os(macOS)
            w = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithWatch, error: &e2)
            #endif
        }
        return ApproverStatus(touchIDReady: touch, watchReady: w,
            detail: "touchID=\(e1.map { Self.describe($0) } ?? "ok"); watch=\(e2.map { Self.describe($0) } ?? "ok")")
    }

    /// Approve exactly one release. Never falls back to the login password.
    func approve(_ req: ApprovalRequest, timeout: TimeInterval) async throws {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0   // never reuse an earlier unlock
        ctx.localizedFallbackTitle = ""                        // hide "Use Password…"
        ctx.localizedCancelTitle = "Deny"
        var err: NSError?
        guard ctx.canEvaluatePolicy(policy, error: &err) else {
            throw ApprovalError.noApproverAvailable(Self.describe(err))
        }
        let fired = Flag()
        let timer = Task {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            fired.value = true
            ctx.invalidate()   // dismisses the sheet → .appCancel / .systemCancel
        }
        defer { timer.cancel() }
        do {
            let ok = try await ctx.evaluatePolicy(policy, localizedReason: req.reason)
            guard ok else { throw ApprovalError.denied }
        } catch let e as LAError {
            if fired.value { throw ApprovalError.timeout }
            switch e.code {
            case .userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback: throw ApprovalError.denied
            case .biometryLockout: throw ApprovalError.lockedOut
            case .notInteractive: throw ApprovalError.notInteractive
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryNotPaired, .biometryDisconnected:
                throw ApprovalError.noApproverAvailable(Self.describe(e as NSError))
            default:
                if #available(macOS 15.0, iOS 18.0, *), e.code == .companionNotAvailable {
                    throw ApprovalError.noApproverAvailable(Self.describe(e as NSError))
                }
                throw ApprovalError.other(e.errorCode)
            }
        }
    }

    static func describe(_ e: NSError?) -> String {
        guard let e else { return "unknown" }
        switch LAError.Code(rawValue: e.code) {
        case .biometryNotPaired?:     return "No Magic Keyboard with Touch ID paired to this Mac"
        case .biometryDisconnected?:  return "Touch ID keyboard paired but off / out of range"
        case .biometryNotEnrolled?:   return "Touch ID present but no fingerprints enrolled"
        case .biometryLockout?:       return "Touch ID locked after failed attempts"
        case .notInteractive?:        return "No interactive GUI session"
        default:
            if #available(macOS 15.0, iOS 18.0, *), LAError.Code(rawValue: e.code) == .companionNotAvailable {
                return "No Apple Watch available (Unlock with Apple Watch off, not worn/unlocked, or out of range)"
            }
            return "LAError \(e.code): \(e.localizedDescription)"
        }
    }
}

/// Optional hardening (roadmap, needs a signed app with keychain-access-groups entitlement):
/// keychain/Secure Enclave enforces the same gate. Ad-hoc SwiftPM binaries get -34018.
func makeGatedAccessControl() -> SecAccessControl? {
    if #available(macOS 15.0, iOS 18.0, *) {
        return SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                               [.biometryCurrentSet, .or, .companion], nil)
    }
    return nil
}

#else

/// Non-Apple platforms have no LocalAuthentication: fail closed.
/// DEBUG builds may set AGENTKEY_INSECURE_TEST_APPROVE=1|0 for Linux integration tests only.
actor ApprovalGate {
    func status() -> ApproverStatus {
        ApproverStatus(touchIDReady: false, watchReady: false, detail: "LocalAuthentication unavailable on this platform")
    }
    func approve(_ req: ApprovalRequest, timeout: TimeInterval) async throws {
        #if DEBUG
        switch ProcessInfo.processInfo.environment["AGENTKEY_INSECURE_TEST_APPROVE"] {
        case "1": FileHandle.standardError.write(Data("[TEST-APPROVE] \(req.reason)\n".utf8)); return
        case "0": throw ApprovalError.denied
        default: break
        }
        #endif
        throw ApprovalError.noApproverAvailable("LocalAuthentication unavailable on this platform")
    }
}
#endif

/// Serializes prompts: at most one system sheet at a time, FIFO.
actor ApprovalCoordinator {
    private let gate = ApprovalGate()
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func status() async -> ApproverStatus { await gate.status() }

    func approve(_ req: ApprovalRequest, timeout: TimeInterval) async throws {
        if busy { await withCheckedContinuation { waiters.append($0) } }
        busy = true
        defer {
            if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() }
        }
        try await gate.approve(req, timeout: timeout)
    }
}
