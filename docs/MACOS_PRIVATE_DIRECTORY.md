# Native macOS private-directory custody — REGTEST preparation

`application.macos_private_directory` provides a separate Darwin-only boundary.
It returns a caller-owned, non-inheritable descriptor for an existing private
directory. Every ancestor is opened relative to a held directory descriptor
with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`; symlinks and `..` are refused.
Absolute exact-type paths and native directory-relative open support are
required. The final inode must belong to the effective UID, have exact `0700`
permissions and remain unchanged across native access inspection. Traversal is
bounded to 256 components. Shared system ancestors need not be private.

POSIX mode `0700` alone does not exclude access from macOS extended ACLs. The
boundary loads `/usr/lib/libSystem.B.dylib` by its absolute system path and
uses `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` on the held descriptor. It requires
the ACL property to be absent: every returned ACL object, including an explicit
empty ACL, is freed and refused. No ACL is removed or changed by the application.
Missing symbols, unsupported filesystem inspection and native errors refuse.

Apple's [ACL retrieval documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_fd_np.3.html)
describes descriptor retrieval and allocated-copy ownership. The public
[Darwin ACL header](https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h)
defines `ACL_TYPE_EXTENDED`. Apple's [descriptor implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c)
reads descriptor security properties; its [filesec implementation](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c)
reports `ENOENT` when the ACL property is absent. All other native error results
are refused. Real ephemeral fixtures verify both absent ACL acceptance and an
access ACL that remains effective while the directory mode stays `0700`.

Tests exercise native macOS directory traversal, ownership, inheritance flags,
symlink/FIFO refusal, access and inherited ACLs, descriptor cleanup, metadata
changes and replacement of an ancestor or final pathname. `/private/tmp` is
selected explicitly for fixtures because Darwin's `/tmp` is a symlink; the
boundary never silently resolves it. Linux and Windows run explicit no-I/O,
no-native-library refusal checks rather than skipped native cases.

This is a directory descriptor boundary, not scanner/storage qualification.
Existing Linux backup/checkpoint implementations, Windows protections, retained
runtime platform refusal, Qt workflow gates, WSP source pin and Core launch
interlocks remain unchanged. No file storage, SQLite lifecycle, encrypted
backup, checkpoint recovery, signing, broadcasting or Core process is enabled.
The checks describe an inode at validation time; they cannot stop later changes
by its owner, malicious same-UID code, mount/OS compromise or whole-directory
rollback. A future caller must revalidate before use and independently qualify
its file and durability handling. No anti-rollback or production claim follows.
