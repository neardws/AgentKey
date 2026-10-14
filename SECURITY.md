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
- (superseded) The CloudKit adapter is now a legacy module compiled only with `-DAGENTKEY_LEGACY_CLOUDKIT`; see below.

## Peer-to-peer sync (v0.3) — no external services

- No cloud, no server, no accounts. Devices sync with an always-on home node you own (e.g. a Mac mini) or directly.
- Channel: `Noise_XX_25519_ChaChaPoly_SHA256` (mutual authentication, forward secrecy, counter nonces → replayed,
  reordered or modified frames abort the session). Inside it, records stay AES-GCM-encrypted per item.
- Peers are accepted only if their static key is in the replicated device registry and not revoked (fail closed).
  Revocation is sticky (cannot be undone by merging an older registry) and rotates the sync key immediately.
- Pairing: QR / `agentkey-pair:` code with node address, one-time 32-byte secret (Noise psk), node key fingerprint;
  expires after 10 min, single use. The new device checks the fingerprint before revealing its own identity.
  Pairing, revocation, backup export and restore require Touch ID / Apple Watch on the device doing them.
- Home node compromise = compromise of the synced vault contents (it holds the sync keys). Treat it like your main Mac:
  FileVault, your account only, updates, and do **not** expose port 7373 to the internet — use Tailscale/WireGuard.
- A revoked device keeps whatever it already decrypted; rotate secrets it may have seen.
- Encrypted backup: PBKDF2-SHA256 600k over a ≥ 12-char passphrase, AES-256-GCM with the header as AAD.
- Bonjour advertisement (`_agentkey._tcp`) carries only a short key fingerprint and the protocol version; discovery is
  untrusted addressing — the full fingerprint is pinned in the handshake. Disable with `--no-bonjour`.
- Not yet validated on Apple hardware: Bonjour runtime behaviour, Keychain + Secure Enclave wrapping of
  the device identity key (on Linux it is a 0600 file).

## NAT traversal (v0.4)

- No AgentKey-operated server. External contacts: public STUN servers (binding requests only; they learn your public
  IP:port), and the BitTorrent Mainline DHT (stores ≤1000-byte items under keys derived from a per-pair secret,
  encrypted to the peer, signed with ed25519 — not linkable to your device identities). Both configurable;
  `agentkeyd --no-net` disables them.
- UDP hole-punch packets carry an HMAC from the per-pair key; streams open only from endpoints that completed an
  authenticated punch. The Noise handshake with the pinned fingerprint is still the trust anchor on every path.
- The UDP port (default 7373/udp) is open to whoever learns it; unauthenticated packets are dropped.
