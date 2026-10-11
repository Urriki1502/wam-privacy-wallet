# CORE-AUTH — official WAM v0.1.11 HTTPS metadata + signed archive review

## Purpose

This opt-in command reduces the need to manually supply **release metadata**
while retaining GnuPG's actual offline signature verification and archive-byte
inspection. The network client retrieves only three independently documented
publisher-origin files from https://wamcoin.org over system-verified TLS:

- \`https://wamcoin.org/SIGNING-KEY.asc\`
- \`https://wamcoin.org/downloads/v0.1.11/SHA256SUMS\`
- \`https://wamcoin.org/downloads/v0.1.11/SHA256SUMS.asc\`

The official release-signing primary-key fingerprint remains statically pinned
in \`core_signed_release.py\`:
\`4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4\`.
Check its current status/revocation independently at
https://wamcoin.org/security/. Metadata transport over HTTPS is **not**
itself a cryptographic publisher proof. Only a genuine detached GnuPG
signature verified with that reviewed pinned key, along with a matching
archive-byte digest, supports a **distribution-only** receipt.

## Opt-in use, no Core execution

Obtain the official WAM node archive through the operator's reviewed channel,
without running or extracting it, and identify a **trusted OS-installed GnuPG
executable** (not a copy shipped beside untrusted release files). Then:

\`\`\`sh
PYTHONPATH=src python -m tools.verify_core_release_official \
  --archive /ABSOLUTE/PATH/wam-coin-v0.1.11-arm64-apple-darwin.tar.gz \
  --gpg /ABSOLUTE/PATH/TO/REVIEWED/gpg
\`\`\`

On Linux or Windows use the exact official platform archive basename
recognized in \`RELEASE_ASSETS\`. The code never assumes that a macOS x64
binary, Windows x86 node archive, or a user-supplied URL is authentic.

The command uses the *existing* real GnuPG verification and bounded archive
inventory. Its network client only supports the three fixed HTTPS paths,
system TLS hostname validation, no arbitrary headers/URL, no redirects,
no proxy-environment fallback, no implicit compressed metadata, 6-second
request timeout and strict 32/128/16 KiB response caps. Untrusted failures
are mapped to fixed redacted errors; no raw GPG output, node hash secret,
network content, shell command or credential is logged. Metadata files live
in an owner-private disposable directory and are removed on success/failure.

The signed local archive **remains operator-provided**. This command does not
fetch the large binary, extract the archive, set execute permissions or launch
\`wamd\`. It never opens a wallet, starts RPC, imports keys or enables spend.
It does not accept mock metadata as a CLI mode or return a run permit.

If no official release files can be fetched with authenticated HTTPS, no
pinned-key GnuPG verification occurs and no receipt is emitted. Similarly a
missing or untrusted GnuPG executable must never be replaced by an arbitrary
downloaded binary or a Python fake.

## Trust boundaries and next gate

Even a valid signature means only that a specific **archive digest was signed
by the pinned WAM release key**. It does not yet prove current key revocation
status, a reproducible Core source/build correspondence, the extracted
\`wamd\` image's immutability, or that the kernel executed those bytes.
**CORE_EXECUTION_REVIEW_REQUIRED remains unconditional under #36**, and
actual two-node genuine Core E2E remains blocked under #9. No live funds,
testnet or mainnet; the operational target is isolated disposable **regtest**.

Native CI uses local synthetic network-response fixtures for adversarial
negative tests. Successful CI does not claim actual official metadata were
retrieved or a real WAM Core node was started. Real signed-release check must
be independently performed by an authorized operator on the selected
platform before considering an execution-image binding design.

## Development queue

1. Verify official signed v0.1.11 archive with genuine GnuPG on a trusted
   host and record redacted signer fingerprint, archive/node SHA-256 and
   reviewed exact release/build references. Do not embed a path to execute.
2. Add an OS-specific verified-bytes-to-process binding and isolated
   two-node launch review, with Windows reparse/ACL and POSIX file-identity
   negatives. **Do not remove existing launch interlock yet.**
3. After DEV WAM signoff, validate real Core two-node regtest identities,
   local P2P, fork/reorg and scanner recovery using disposable keyless nodes.
4. Gradually eliminate **mock inputs from operational integration paths**;
   keep synthetic adversarial fixtures for security regressions.
