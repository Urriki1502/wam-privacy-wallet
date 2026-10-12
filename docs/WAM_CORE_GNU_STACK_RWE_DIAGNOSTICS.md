# Official WAM Core v0.1.11 GNU_STACK RWE — DEV diagnostics (#84/#86)

**Status: confirmed static finding; no WAM Core execution.** No exploit or compromise is claimed.

## Evidence, scope and exact pins

- Genuine Linux signed archive `wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz`: SHA-256 `bd010ed615ab8063d5c12aa61236311ece7e9d19896d9541dacba1888dd9987a`.
- Member `wam-coin-v0.1.11/bin/wamd`: SHA-256 `625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4`.
- Independent read-only `readelf -W -l` finding: `PT_GNU_STACK RWE`; native source evidence: #85 and CI run `38150871291`.
- The strict static loader preflight in Draft #84 rejects this as `CORE_ELF_EXECUTABLE_STACK_DENIED`. **Keep that failure**; never downgrade acceptance to obtain a green CI or alter signed bytes in Wallet.
- Upstream `docs/BUILD.md` names static `tevador/RandomX` v1.2.1 archive, linked with `LIBS=".../librandomx.a -lpthread"` against patched Bitcoin Core v28.1. RandomX/assembler is a **lead to investigate, not a demonstrated cause**. JIT use alone does not prove that an executable *stack* is necessary.

## DEV-only root-cause sequence (on reproducible isolated build inputs)

1. Authenticate original builder's source revisions, build script, compiler, assembler, linker, flags and exact shipped member. Do not assume that rebuilding a different commit diagnoses the official artifact.
2. On authenticated member, record `readelf -W -l wamd` (GNU_STACK flags), `readelf -W -h wamd`, PIE/type, `PT_INTERP`, `PT_LOAD` W+X segments and `DT_NEEDED` names. **Do not execute the binary**.
3. Enumerate *all* object inputs and static archives in actual final link. For each ELF object, inspect `.note.GNU-stack` presence and executable section flags (`readelf -W -S object.o`), including RandomX assembler objects and WAM-specific code. Missing notes in legacy objects and executable note flags must both be investigated.
4. Inspect linker command/map for `-z execstack`, `--execstack`, assembler `--execstack`, and toolchain defaults. Determine which actual input/flag propagates `RWE`; preserve independent evidence logs.
5. If exec stack is not required, fix only the responsible upstream source/assembly/build options; rebuild, run required consensus/regtest and compatibility tests, ensure `PT_GNU_STACK RW` (non-X), and re-sign/publish a **new official artifact**. Do not alter the existing signed release or strip the ELF bit without testing.
6. If stack execution is genuinely required, DEV WAM documents why, supported host/kernel mitigations and explicit security exception policy. Project wallet must not invent this approval.
7. Cross-link source/build equivalence, dynamic loader/library integrity, signed-release provenance and #36 executable-to-process binding. The existing Wallet `CORE_EXECUTION_REVIEW_REQUIRED` interlock stays on.

## Safe handoff checklist

DEV WAM provides: (a) toolchain + object-level cause, (b) reviewed resolution or documented exception, (c) new release signature + exact archive/member SHA if rebuilt, (d) evidence of consensus/network correctness and security checks, (e) explicit regtest test authorization. Until then: #84 DRAFT/HOLD, #86 OPEN, #36/#9 BLOCKED.

No modification to WAM Core, live wallet, signing/broadcast or mainnet is made by this diagnostic plan.
