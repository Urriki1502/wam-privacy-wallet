"""Run exact-source upstream privacy regressions; never invoke Core or transport."""
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


PAYJOIN_FILES = {
    "prototypes/payjoin_safety/model.py": "8e3e8be096a66fc960f75a56f1ac34daa9306017",
    "prototypes/payjoin_safety/validator.py": "598596a8bde118204b3baf69bb53a884c6dad21a",
    "prototypes/payjoin_safety/__init__.py": "59f1f5380eb071f6a010d6e57ec9e7937fe7291c",
    "tests/test_phase4_payjoin_safety.py": "e338a278e626c547ff84e34fd3f2ea7cee99c3bf",
}


COIN_FILES = {
    "prototypes/wallet_privacy/model.py": "c53df0c40f183bd51fbfaffe64d6a5aa899c8a43",
    "prototypes/wallet_privacy/policy.py": "4c37f9c78d1c0f2818bf6530871cd0a87f4741dd",
    "prototypes/wallet_privacy/__init__.py": "d1a5272b8e389add8ca5e13767ccfe0ec319b1ee",
    "tests/test_phase2_wallet_privacy.py": "ee573b99f0cc595bef54ba947276022424396ba4",
    "tests/test_phase2_wallet_properties.py": "6fc26a9be317a639cada1980c4052c4811e1f2a5",
}


def main():
    root = Path(sys.argv[1]).resolve()
    option = sys.argv[2] if len(sys.argv) == 3 else "--network"
    if len(sys.argv) not in (2, 3) or option not in ("--network", "--payjoin", "--coin-selection"):
        raise SystemExit("PINNED_PRIVACY_ARGUMENT_DENIED")
    files, patterns, minimum, label = {
        "--network": (FILES, ("test_phase5_network_privacy.py",), 10, "NETWORK"),
        "--payjoin": (PAYJOIN_FILES, ("test_phase4_payjoin_safety.py",), 16, "PAYJOIN"),
        "--coin-selection": (COIN_FILES, ("test_phase2_wallet_privacy.py", "test_phase2_wallet_properties.py"), 13, "COIN_SELECTION"),
    }[option]
    for path, expected in files.items():
        data = (root / path).read_bytes()
        actual = sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if actual != expected:
            raise SystemExit(f"PINNED_{label}_SOURCE_DENIED")
    # This dedicated process imports only the source-pinned pure-model closure.
    # Content hashes do not authenticate its publisher or runtime.
    suite = unittest.TestSuite()
    for pattern in patterns:
        suite.addTests(unittest.TestLoader().discover(str(root / "tests"), pattern=pattern))
    if suite.countTestCases() != minimum:
        raise SystemExit(f"PINNED_{label}_DISCOVERY_DENIED")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses):
        raise SystemExit(f"PINNED_{label}_TESTS_DENIED")
    print(f"PINNED_{label}_NATIVE_OK {PIN} {minimum}/{minimum}; no operational authority")


if __name__ == "__main__":
    main()
