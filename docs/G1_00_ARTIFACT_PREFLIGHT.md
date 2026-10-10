# G1-00 — WAM Core local binary SHA-256 preflight (not real regtest)

**Experimental / deliberately blocked:** real-node and two-node regtest
qualification is **not completed** by this check. This is a small opt-in
utility for future operators; CI uses **only a synthetic temporary file**.

## Scope

Reuses existing \`real_regtest.verify_binary()\` and
\`node.core_source_pin.load_core_manifest()\`, rather than creating new
hashing/auth/network code. It checks an explicitly supplied absolute local
file path against an explicitly supplied lowercase SHA-256, while retaining
the repository's pinned WAM regtest profile (genesis and 29554/29555 ports).
It does **not** invoke the candidate file, contact a node, read an existing
wallet/datadir, download anything, or create a RPC connection.

Example, **only after the operator has obtained the digest from an independent
trusted provenance source**:

\`\`\`sh
PYTHONPATH=src python tools/check_regtest_artifact_preflight.py \
  --binary /absolute/path/to/operator_supplied/wamd \
  --sha256 <64-lowercase-hex-from-independent-trusted-source>
\`\`\`

Expected output on matching bytes includes:
\`"status": "LOCAL_SHA256_MATCH_ONLY"\`,
\`"real_regtest_qualified": false\`,
\`"publisher_identity_verified": false\`,
\`"release_allowed": false\`.

**Important:** Anyone can calculate the SHA-256 of an arbitrary fake file.
A checksum match to an untrusted or self-calculated digest does not prove
genuine WAM Core provenance. This tool also does not prove the file is
executable or corresponds to the pinned Core commit. Only the separately
reviewed publisher artifact/identity and actual isolated runtime tests can
satisfy [REGTEST-E2E-001 #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9).

## Requirements before calling real WAM Core regtest PASS

1. Independently verify origin, exact version/commit and binary digest.
2. Build disposable isolated **two-node** regtest; no user home/wallet files,
   no public peers, no arbitrary binary downloads.
3. Prove RPC wire compatibility, cookie rotation, identity/genesis, stable
   profile and wrong-chain/error behavior on the actual binary.
4. Prove restart/reorg, state recovery and scanner lease behavior with
   independently reproducible evidence.
5. Review WSP-1 candidate Windows locks (PR #9), wallet PR #3/#16, and signoff.

Until all evidence exists, classify real-node G1 E2E **BLOCKED**.
Native Windows x86 GUI/crypto release also remains unqualified.

## Offline CI evidence

\`\`\`sh
PYTHONPATH=src python -m unittest discover -s tests -p test_regtest_artifact_preflight.py -v
\`\`\`

Seven cases verify digest mismatch, missing files, symlink, bad paths,
negative profiles, immutable evidence and that **no process is launched**.
Run with the existing consolidated offline matrix (Windows x86/x64,
macOS x64, Linux x64) plus unchanged GUI/Core/CodeQL gates.

This is **not** source or runtime authority. It never changes WAM Core.
