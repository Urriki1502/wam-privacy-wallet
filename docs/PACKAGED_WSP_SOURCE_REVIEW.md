# Packaged read-only WSP source qualification

The existing WSP source review and full-source closure implementation now lives
in `wam_privacy_wallet.integrations.wsp1_source_review` and
`wam_privacy_wallet.integrations.wsp1_source_closure`. The two original tool
commands re-export the same public functions/errors/constants and delegate to
the same CLI entrypoints. No second validator or source-pin manifest is created.

This makes the existing source qualification available from an installed wallet
package without importing the repository-only `tools` package. Native GUI CI
checks imports with isolated Python (`-I`), so the current working directory and
PYTHONPATH cannot hide a missing installed library dependency.

All pins, limits, symlink/hardlink checks, transitive source/dependency checks,
error codes and no-authority fields remain unchanged. Existing synthetic
adversarial tests now patch the actual packaged implementation, retain their
identities/floors, and remain denial/schema tests rather than real-source proof.
Native CI still checks the authentic exact WSP checkout at
`ac55f13423620252bdbf848c7e8a280c3b84721e` and runs the existing actual scanner
against synthetic loopback data. The path triggers include both packaged files.

Local actual-source inspection verified 34 blobs / 33 Python modules and the
four pinned API files. This establishes content identity only, not publisher
attestation, secure runtime loading, a signer approval or a real Core connection.
The full-source checker remains a qualification helper, not a production loader.

This is groundwork for a consent-gated, isolated, read-only PSBTv2 parser using
the unchanged upstream implementation. All Core/WSP/anti-rollback blockers and
CORE-003 exclusion remain unchanged; no keys, signing, broadcast or mainnet.
