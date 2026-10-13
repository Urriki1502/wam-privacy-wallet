"""CI-only child proof: real Linux seccomp must reject socket and exec."""
from __future__ import annotations

import os
import subprocess
import sys


def probe_child_seccomp() -> None:
    if sys.platform != "linux" or os.name != "posix":
        raise RuntimeError("CI_SECCOMP_PROBE_PLATFORM_DENIED")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": "src",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    run = subprocess.run(
        [sys.executable, "-B", "-m", "tools.wsp_offline_signer_seccomp",
         "--network-probe"],
        check=False, capture_output=True, text=True, timeout=15, env=env,
    )
    if (run.returncode != 0 or run.stdout.strip() !=
            "WSP_OFFLINE_SIGNER_KERNEL_NETWORK_DENIED"):
        raise RuntimeError("CI_SECCOMP_PROBE_DENIED")
