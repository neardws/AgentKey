# Security Policy

AgentKey is a personal project at **v0.1**. It has **not** been independently audited.

## Reporting

Please report vulnerabilities privately via GitHub Security Advisories
(<https://github.com/neardws/AgentKey/security/advisories/new>), not public issues.

## Threat model (v0.1)

Protects against:
- Theft of `vault.akv` (laptop backup, cloud copy): needs master password **and** the device-only Secret Key.
- A prompt-injected or misbehaving agent: every release needs a fresh Touch ID / Apple Watch approval on the Mac,
  showing the agent label, item, mode (and command for `run`) plus a 4-char correlation code. `reveal` is off by default.
- Silent tampering with the audit log (hash chain + HMAC keyed from the vault key).
- Ciphertext swapping between items (AES-GCM AAD binds vault/item/revision).

Does **not** protect against (known limitations):
- Malware running as your user while the daemon is unlocked: it can talk to the socket and request approvals
  (you still have to approve each one), read process memory, or keylog the master password.
- A lying agent label: the `agent` name is self-reported. Trust the correlation code and the command, not the name.
- A child process launched with `run` that deliberately exfiltrates or transforms the secret; output redaction is best-effort.
- Master password sent from `agentkey unlock` to `agentkeyd` over the same-uid 0600 socket (Secure Enclave unlock is Phase 2).
- PBKDF2 is weaker than Argon2id against GPU attackers (mitigated by the 128-bit Secret Key); Argon2id is planned.
- Swift cannot guarantee secrets are zeroed from memory.

## Fail-closed rules

- No Touch ID keyboard and no available Apple Watch → deny. No password fallback.
- Not in a GUI (Aqua) session → deny. Timeout (default 60 s) → deny.
- Peer uid ≠ daemon uid → connection dropped.
- Non-Apple platforms always deny (DEBUG builds only may use `AGENTKEY_INSECURE_TEST_APPROVE` for tests).

## Import, hygiene and sync (v0.2)

- Imports read the export file into memory only (ZIP inflated in memory); AgentKey never writes plaintext to disk,
  but the export file you created still contains plaintext — delete it securely afterwards.
- Imported items get no agent release modes until you enable them.
- Vault health runs inside agentkeyd; agents receive findings (ids, refs, metrics) only. Reused-password groups use an
  HMAC keyed by a vault-derived key, so group ids cannot be compared across vaults or brute-forced offline.
- Cleanup plans are proposals; applying requires Touch ID / Apple Watch, can be partial, is audited per action, and
  (except `purge` of already-trashed items) is reversible. There is no MCP tool to apply plans. Note: any local process
  running as you can invoke `agentkey plan apply`, but it still cannot get past the biometric prompt.
- Sync uploads only AES-GCM ciphertext plus non-secret metadata (record id, Lamport clock, device id, deleted flag,
  key version) to your iCloud private database. The CloudKit adapter is not yet validated on a device.
