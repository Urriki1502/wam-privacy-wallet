"""Stage two private G1-reviewed regtest configs; NEVER launch WAM Core.

This is concrete host filesystem preparation (not synthetic mock config
generation), but the underlying G1 preview is still a candidate and has
not been qualified against the genuine WAM binary. No launcher, cookies,
wallet files, network sockets, blockchain reads, signing or spend authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Iterator

from .two_node_policy import TwoNodePolicyError, audit_two_node_policy
from .two_node_topology import TwoNodePlan


class TwoNodeWorkspaceError(ValueError):
    """Redacted error; does not echo local directories or network endpoints."""


@dataclass(frozen=True, slots=True)
class NodeWorkspace:
    label: str
    data_dir: Path = field(repr=False)
    conf_path: Path = field(repr=False)
    rpc_port: int
    p2p_port: int


@dataclass(frozen=True, slots=True)
class TwoNodeWorkspace:
    nodes: tuple[NodeWorkspace, NodeWorkspace]
    status: str = field(default="ISOLATED_CONFIG_FILES_ONLY", init=False)
    private_filesystem_prepared: bool = field(default=True, init=False)
    core_options_runtime_verified: bool = field(default=False, init=False)
    core_process_started: bool = field(default=False, init=False)
    actual_two_node_regtest_qualified: bool = field(default=False, init=False)
    p2p_connected: bool = field(default=False, init=False)
    scanner_enabled: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)
    signing_allowed: bool = field(default=False, init=False)
    broadcasting_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


@contextmanager
def prepare_private_two_node_workspace(
    candidate: object,
) -> Iterator[TwoNodeWorkspace]:
    """Write only exact audited G1 config previews to private POSIX temp dirs.

    The caller may inspect ephemeral config files but receives NO executable
    process, approved launch argument, wallet key, RPC cookie or authority.
    On Windows, no reviewed private ACL and reparse-safe directory creation
    contract exists, so deny before any filesystem side effect.
    """
    if sys.platform not in ("linux", "darwin") or os.name != "posix":
        raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_PLATFORM_REVIEW_REQUIRED")
    try:
        audit_two_node_policy(candidate)
        if type(candidate) is not TwoNodePlan:
            raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_POLICY_DENIED")
    except (TwoNodePolicyError, TypeError, ValueError):
        raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_POLICY_DENIED") from None

    try:
        scratch = tempfile.TemporaryDirectory(prefix="wam-2node-regtest-stage-")
    except (OSError, TypeError, ValueError):
        raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_IO_DENIED") from None
    with scratch as temp:
        try:
            root = Path(temp)
            root.chmod(0o700)
            result: list[NodeWorkspace] = []
            for node in candidate.nodes:
                if node.label not in ("node-a", "node-b"):
                    raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_POLICY_DENIED")
                data_dir = root / node.label
                data_dir.mkdir(mode=0o700, exist_ok=False)
                data_dir.chmod(0o700)
                conf_path = data_dir / "wam.conf"
                flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(conf_path, flags, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(node.config_preview.encode("ascii"))
                conf_path.chmod(0o600)
                info = conf_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_mode & 0o077 or info.st_size != len(node.config_preview)
                        or conf_path.read_bytes() != node.config_preview.encode("ascii")):
                    raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_INTEGRITY_DENIED")
                result.append(NodeWorkspace(
                    node.label, data_dir, conf_path, node.rpc_port, node.p2p_port,
                ))
        except TwoNodeWorkspaceError:
            raise
        except (OSError, TypeError, UnicodeError, IndexError, ValueError):
            raise TwoNodeWorkspaceError("REGTEST_WORKSPACE_IO_DENIED") from None
        # Outside staging error handler: the consumer's exception is not a
        # staging failure and must propagate unmodified after temp cleanup.
        yield TwoNodeWorkspace(nodes=(result[0], result[1]))
