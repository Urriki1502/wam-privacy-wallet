# Native macOS encrypted scan envelope custody — REGTEST ONLY

`macos_encrypted_scan_backup` is a separate Darwin backend for already-encrypted
WSP scan envelopes. It does not change the Linux implementation or enable the
retained scanner runtime, SQLite custody, checkpoint restore or Qt backend.
Windows remains denied before I/O. The caller supplies an existing directory;
this code never creates a directory, decrypts an account or retains a password.

The backend reuses the no-follow ancestor descriptor walk from #199. The final
directory must have exact owner/0700/non-inheritable metadata and no extended
ACL. Each envelope must be exact bytes, have the pinned WAMSP02 header, and be
52 through 1,048,576 bytes. Header/size validation is not cryptographic or role
authentication: a separate source-qualified WSP `import_scan` must authenticate
and interpret the result. Never infer that arbitrary ciphertext is scan-only.

Provisioning holds a nonblocking native directory flock, creates an exclusive
randomized 0600 stage and keeps its descriptor through publication. Regular
files must be owner-held, non-inheritable and free of extended ACLs. Full file
flush precedes create-once hard-link publication. Both stage and canonical names
must refer to the expected inode. Success requires stage removal, single-link
canonical custody and directory fsync followed by identity checks. Cleanup,
flush or close failures return fixed refusals. A canonical file is never replaced
or removed after ambiguous publication. Cleanup refuses a replacement stage inode.

[Apple's fcntl documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describes `F_FULLFSYNC` as flushing file data and requesting a device-cache flush.
This adapter requires its native success; unsupported flush/filesystem results
refuse. Passing native tests is not a universal power-loss guarantee. Directory
fsync is checked separately. No Linux directory link-count assumption is used.

Reads open only a no-follow/nonblocking descriptor for the canonical name,
require a private 0600 single-link regular file with no ACL, and perform a bounded
read bracketed by inode, metadata and name identity checks. Symlinks, FIFOs,
extra hardlinks, truncation, modification and pathname substitution refuse.
No directory resolution, permission repair, auto-migration or mutable latest
selector is provided.

The mandatory filesystem suite has 33 cases: native roundtrip, boundaries,
create-once and concurrent publishers, directory/file ACLs, ancestor/final
symlinks, FIFO/hardlinks, replacement and read races, partial writes, full flush,
fsync, cleanup and close faults. Linux/Windows execute platform refusal cases
without skipping or loading the Darwin ACL library. Three additional proof
boundary cases preserve denial on non-Darwin/32-bit and optimized interpreters.

`tools.ci_macos_scan_backup_native` verifies exact ac55f134 source closure,
dependency versions, installed origin and absence of preloaded WSP before native
imports. With a public disposable scan scalar and fixed public test password,
it executes original WSP AES-GCM export/import through this storage boundary.
Seven exact identities verify native publication, scan-account roundtrip,
wrong-password and tamper refusal, create-once preservation, actual interprocess
publication and restart after terminating a flushed owner. Signing APIs
remain denied. The native macOS CI step supplements the unchanged original
scanner proof; synthetic filesystem bytes alone are not encryption evidence.

EXPERIMENTAL/disposable REGTEST preparation only. This is no independent
freshness anchor, whole-directory rollback defense, same-UID malware protection,
OS/mount attestation, memory zeroization, real Core E2E or production custody
qualification. Existing #9/#82/#86/#148/#151/#153 and WSP review holds remain.
Any future retained SQLite/session or GUI integration needs its own native proof.

The process recovery proof starts separately source-qualified publisher processes
and admits exactly one create-once winner. A second case terminates a real owner
after native F_FULLFSYNC but before publication: the canonical name must remain
absent, its private encrypted stage remains authenticated, and a fresh publisher
must regain the kernel lease and create an authenticated canonical envelope.
The orphan stage is preserved unchanged; this provides no automatic recovery,
stale-stage deletion, independent freshness or power-loss qualification. All
accounts/passwords are public fixtures; no production custody is enabled.
