# SEC-G1-EXEC-001 — First patch: RPC cookie path race hardening (OFFLINE)

**Scoped partial mitigation only; REAL WAM CORE EXECUTION STILL BLOCKED.**
This patch targets the local regtest diagnostic's cookie-reading function,
which previously checked path.lstat() and then used path.read_bytes() — a second
path lookup. A hostile workspace may replace that pathname between operations.

## Scope and controls

- Open the cookie **once** through os.open into a file descriptor; use
  O_NOFOLLOW where the native OS exposes it, and O_BINARY where available.
- Compare pathname lstat to descriptor fstat for regular-file identity,
  inode/device and size before accessing bytes.
- Read no more than 1,025 bytes and reject empty or over-1,024-byte cookies.
  Recheck descriptor metadata and pathname after reading.
- Never log raw cookie or credentials; use stable redacted errors.
- Two offline tests cover symlinks and simulated pathname replacement
  between the first precheck and the actual descriptor open.
- Raise the existing real-regtest-harness suite floor from 10 to 12, preserving
  all 19 existing suites. Target **19 suites / 196 cases** on all four
  native operating system/architecture configurations.

## Remaining hard blockers

This **does not close the executable verification-to-launch TOCTOU** in
verify_binary() followed by subprocess.Popen(path). The OS may open a
different binary after hashing. Nor does it certify defense from malicious
same-UID mutation, Windows reparse points/ACLs, or a different Windows
object-id interpretation. O_NOFOLLOW only applies where supported.

SEC-G1-EXEC-001 #36 remains OPEN/BLOCKED. A separate reviewed native or
isolated immutable executable and process-identity approach, independent
publisher proof, host confinement, and separately authorized safe
integration tests are prerequisites for real Core testing.

No WAM Core, RPC, wallet, scanner, signer or real funds were executed.
