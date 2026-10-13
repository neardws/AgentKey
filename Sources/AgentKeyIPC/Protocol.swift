import Foundation
import AgentKeyCore

/// Wire format: 4-byte big-endian length + UTF-8 JSON (max 1 MiB), JSON-RPC 2.0 semantics.
/// Protocol id: "agentkey-ipc/1".
public enum IPC {
    public static let protocolID = "agentkey-ipc/1"
    public static let maxFrame = 1 << 20

    public enum ErrorCode: Int, Codable, Sendable {
        case usage = -32602, policyDenied = -32010, userDenied = -32011, timeout = -32012,
             noApprover = -32013, locked = -32014, notFound = -32015, internalError = -32603
        /// CLI exit codes (see docs/DESIGN.zh.md §12.2)
        public var exitCode: Int32 {
            switch self {
            case .usage: return 64
            case .policyDenied: return 65
            case .userDenied: return 66
            case .timeout: return 67
            case .noApprover: return 68
            case .locked, .notFound, .internalError: return 69
            }
        }
    }
}

public struct RPCRequest: Codable, Sendable {
    public var jsonrpc = "2.0"
    public var id: Int
    public var method: String
    public var params: [String: String]
    public init(id: Int, method: String, params: [String: String] = [:]) { self.id = id; self.method = method; self.params = params }
}

public struct RPCError: Codable, Error, Sendable, CustomStringConvertible {
    public var code: Int
    public var message: String
    public init(_ c: IPC.ErrorCode, _ m: String) { code = c.rawValue; message = m }
    public var kind: IPC.ErrorCode { IPC.ErrorCode(rawValue: code) ?? .internalError }
    public var description: String { "\(message) (\(code))" }
}

/// Either a final response (`id` set) or a progress notification (`method` = "progress").
public struct RPCMessage: Codable, Sendable {
    public var jsonrpc = "2.0"
    public var id: Int?
    public var method: String?
    public var result: [String: String]?
    public var error: RPCError?
    public var params: [String: String]?
    public init(id: Int?, result: [String: String]? = nil, error: RPCError? = nil, method: String? = nil, params: [String: String]? = nil) {
        self.id = id; self.result = result; self.error = error; self.method = method; self.params = params
    }
}

public enum Frame {
    public static func encode<T: Encodable>(_ v: T) throws -> Data {
        let body = try JSONEncoder().encode(v)
        var len = UInt32(body.count).bigEndian
        return Data(bytes: &len, count: 4) + body
    }
}
