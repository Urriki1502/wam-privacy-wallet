"""Offline help/example text-only comparison; NEVER executes Core.

Inputs must be independently captured inside DEV's authenticated exact-build
release environment. Matching arbitrary local files is NOT binary provenance.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from wam_privacy_wallet.node.core_help_example_parity import (
    CoreHelpExampleError, inspect_help_example_text, inspect_two_node_help_coverage,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WAM next-release help/example text inventory (NO EXEC)"
    )
    parser.add_argument("--captured-help", required=True)
    parser.add_argument("--example-conf", required=True)
    parser.add_argument("--two-node-ports", nargs=4, type=int,
                        metavar=("RPC_A", "P2P_A", "RPC_B", "P2P_B"),
                        help="Optional canonical two-node option-name coverage; no launch")
    args = parser.parse_args(argv)
    try:
        a = Path(args.captured_help)
        b = Path(args.example_conf)
        if (not a.is_absolute() or not b.is_absolute()
                or a.is_symlink() or b.is_symlink()
                or not a.is_file() or not b.is_file()
                or a.stat().st_size > 512 * 1024
                or b.stat().st_size > 256 * 1024):
            raise CoreHelpExampleError("CORE_CONFIG_INPUT_FILE_DENIED")
        evidence = inspect_help_example_text(a.read_bytes(), b.read_bytes())
        result = asdict(evidence)
        if args.two_node_ports is not None:
            from wam_privacy_wallet.node.two_node_topology import (
                TwoNodeTopologyError, plan_two_node_topology,
            )
            try:
                plan = plan_two_node_topology(tuple(args.two_node_ports))
            except TwoNodeTopologyError:
                raise CoreHelpExampleError("CORE_CONFIG_TWO_NODE_PLAN_DENIED") from None
            # Re-read content must be bound to the exact compared capture.
            captured = a.read_bytes()
            coverage = inspect_two_node_help_coverage(captured, plan)
            if coverage.help_text_sha256 != evidence.help_text_sha256:
                raise CoreHelpExampleError("CORE_CONFIG_HELP_CHANGED_DENIED")
            result["two_node_help_coverage"] = asdict(coverage)
    except CoreHelpExampleError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError:
        print("CORE_CONFIG_INPUT_FILE_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
