"""Run exact-source upstream network regressions; never invoke Core or transport."""
from hashlib import sha1
from pathlib import Path
import sys
import unittest

PIN = "db3d2dcaa540f1129d540101813b761167d33174"
FILES = {
    "prototypes/network_privacy/model.py": "efba5aa0f4cd7d57615dfde47206e7e0dde8d865",
    "prototypes/network_privacy/policy.py": "3d24c9a9a010220503e6c81251da7c42309a63a0",
    "prototypes/network_privacy/__init__.py": "ef3f58721d2435771adbd5167247ae97d94f27d0",
    "tests/test_phase5_network_privacy.py": "a3a557b6cea793f184de3210c8d83fec82323ead",
}


def main():
    root = Path(sys.argv[1]).resolve()
    for path, expected in FILES.items():
        data = (root / path).read_bytes()
        actual = sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if actual != expected:
            raise SystemExit("PINNED_NETWORK_SOURCE_DENIED")
    # This dedicated process imports only the authenticated pure-model closure.
    suite = unittest.TestLoader().discover(str(root / "tests"), pattern="test_phase5_network_privacy.py")
    if suite.countTestCases() != 10:
        raise SystemExit("PINNED_NETWORK_DISCOVERY_DENIED")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses):
        raise SystemExit("PINNED_NETWORK_TESTS_DENIED")
    print(f"PINNED_NETWORK_NATIVE_OK {PIN} 10/10; no transport authority")


if __name__ == "__main__":
    main()
