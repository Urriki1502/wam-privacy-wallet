# Checkpoint metadata v2 — authenticated, unanchored REGTEST preparation

The journal reuses exact upstream WSP AES-GCM ciphertext, immutable generation
directories and ready-marker ordering from #149/#150. New v2 metadata adds
domain-separated HMAC-SHA256 over canonical metadata: WAM REGTEST genesis,
source pin, wallet scan-scope digest, generation, predecessor, tip, ciphertext
digest, declared checkpoint schema and explicit metadata-key epoch. Comparison
is constant-time. Unknown fields, duplicate/noncanonical encodings, boolean
integers, mismatched identities/schemas/epochs and absent MACs are refused.

The 32-byte metadata key must be independently random and secret. It must not
be a password, seed, spend key, scan key or a newly derived WSP key. The caller
selects exactly one key and epoch; no automatic fallback or rotation is allowed.
No key storage or credential-vault qualification is supplied. Python bytes are
not securely zeroized. The upstream WSP library remains solely responsible for
AES-GCM authentication/decryption and validating the actual enclosed DB schema;
metadata schema is only a separately authenticated declaration.

The exact pinned WSP Store exports checkpoint schema **3**. The MAC boundary
accepts only this source/schema pair; unknown positive versions and legacy
schema declarations require separate source/format requalification. Protected
reads still deny first. Explicit unanchored reads validate scope, generation,
schema, epoch and key shape before any disk read. Journal manifest schema 1,
outer MAC metadata schema 2 and upstream checkpoint schema 3 are distinct.
This does not decrypt the checkpoint or replace upstream schema validation.

Metadata is fsynced before the completion marker. Readers and writers acquire
nonblocking native inter-process directory locks. All path components are
opened with O_NOFOLLOW and directory descriptors; symlinked ancestors and `..`
are refused. Ownership/private mode checks apply to the final private directory
and its children. Shared system ancestors need not be 0700. Locks are advisory,
not protection from same-UID malicious code. A failed write may leave an
immutable incomplete candidate and cannot overwrite an older generation. A
late fsync failure may leave a structurally complete candidate; it is still
uncommitted relative to any external high-water mark. Never auto-select it.

`IndependentAnchorProvider` is an interface contract, not an approved adapter.
All `require_independent_anchor` calls refuse, even with a forged provider.
Protected reads refuse before any file/key access. Explicit synthetic REGTEST
inspection can authenticate a selected generation, but whole-directory replay
with a matching old key still authenticates. **HMAC, local locks, hash chains and
SQLite counters do not establish freshness.** #148/#151 stay OPEN until a
qualified independent challenge-bound monotonic CAS anchor is implemented.
Anchor-ahead recovery must STOP for reviewed disaster recovery; never downgrade.

27 adversarial tests cover real HMAC with public fixture ciphertext, identity
substitution, explicit key rotation/old-epoch denial, local marker rewriting,
fsync faults, torn writes, legacy refusal and actual Linux process locking.
The existing native pinned-WSP CI also exports real schema-3 ciphertext,
persists its authenticated metadata and restores unchanged bytes with real
WSP into fresh SQLite. Its chain RPC remains a synthetic peer, not WAM Core.
No signer, broadcast, production restore or real Core execution is enabled.
