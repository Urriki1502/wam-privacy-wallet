# Explicit ELF stack policy — read-only preparation for #82

The sealed descriptor parser now requires exactly one PT_GNU_STACK with flags
PF_R | PF_W (0x6). Absent headers, duplicate headers, partial/unknown modes and
any PF_X are refused. This matches the existing successor archive policy's
explicit RW requirement; absence is never reported as an NX observation.

Linux uses the last PT_GNU_STACK header for stack executability. This wallet's
stricter preflight denies ambiguous duplicates. Primary reference:
https://www.kernel.org/doc/html/v6.10/userspace-api/ELF.html
The preflight's exact RW requirement is project policy, not a claim that every
otherwise valid ELF needs this permission mode.

Four new adversarial methods run on actual kernel-sealed NOEXEC fixture bytes,
with explicit unsupported-platform refusal on macOS/Windows. Existing official
v0.1.11 continues to deny CORE_ELF_EXECUTABLE_STACK_DENIED. Signed archive
provenance, dynamic loader/DSO trust, immutable executed-process binding and
DEV-approved two-node acceptance remain separate. No Core execution API or
launch permit is introduced, and #82/#86/#9 remain OPEN/BLOCKED.
