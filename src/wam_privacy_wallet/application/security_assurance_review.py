"""Actual pinned WAM Security provenance helper, public synthetic fixture only.

An unsigned deterministic digest is not a publisher signature, SLSA assurance,
trusted runtime, anti-rollback anchor or release permission. No caller paths,
artifacts, statements, source identities or key material are accepted.
"""
from dataclasses import dataclass
from hashlib import sha1
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import tempfile

_PIN = "c9b1ce872c2b0b65276883d4e210b6a2f7c96467"
_BLOBS = {
    "__init__.py": "1b104e7230874318063feee859bffa757bc75840",
    "supplychain/__init__.py": "3ad8c5e25ad214d4cfca80699e78bd46b72e3cb3",
    "supplychain/identities.py": "71787690f7fa0f2d71273aa48d25f8f03834a683",
    "supplychain/provenance.py": "5578d80d091431e75b366a5cf30cd560ac02065d",
}
_PUBLIC_PROVENANCE_DIGEST = "0700a9000944f1188eebafb4448823f11c6df8723feb6f0cedd6ff1243eb7424"
_PUBLIC_ARTIFACT = b"PUBLIC WALLET ASSURANCE FIXTURE v1\n"


class SecurityAssuranceReviewError(ValueError):
    """Fixed error without library exceptions, private paths or contents."""


@dataclass(frozen=True, slots=True)
class SecurityAssuranceReview:
    provenance_digest: str
    subject_count: int = 1
    dependency_count: int = 3
    source_commit: str = _PIN
    evidence: str = "PINNED_UNSIGNED_PUBLIC_PROVENANCE_UNTRUSTED"
    publisher_authenticated: bool = False
    runtime_authenticated: bool = False
    release_allowed: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False


def _verify_source() -> Path:
    """Check raw pure-helper closure before importing it; content pin only."""
    spec = importlib.util.find_spec("wam_security")
    if spec is None or spec.origin is None: raise ValueError
    root = Path(spec.origin).parent
    for name, expected in _BLOBS.items():
        path = root / name
        if path.is_symlink() or path.stat().st_size > 100_000: raise ValueError
        with path.open("rb") as stream: data=stream.read(100_001)
        if len(data)>100_000 or sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()!=expected: raise ValueError
    # Keep qualification environments bytecode-free; this is not a hostile-code
    # loader or proof of an already-loaded module's runtime identity.
    if any(root.rglob("*.pyc")): raise ValueError
    return root


def _execute_public_fixture() -> SecurityAssuranceReview:
    """Worker-only implementation; source check precedes upstream import."""
    try:
        _verify_source()
        from wam_security.supplychain.provenance import (
            create_provenance, provenance_digest, verify_subjects,
        )
        # These are the recorded module identities used by wallet research,
        # not a Core audit identity or a mutable claim supplied by the caller.
        lock={"identities":[
            dict(name="wam-privacy", repository="https://github.com/Urriki1502/wam-privacy", ref="refs/heads/main", commit="db3d2dcaa540f1129d540101813b761167d33174", kind="source-dependency"),
            dict(name="wam-security", repository="https://github.com/Urriki1502/wam-security", ref="refs/heads/main", commit=_PIN, kind="source-dependency"),
            dict(name="wam-silent-payments", repository="https://github.com/Urriki1502/wam-silent-payments", ref="refs/pull/9/head", commit="ac55f13423620252bdbf848c7e8a280c3b84721e", kind="source-dependency"),
        ]}
        # Never pass an untrusted manifest/path to upstream verify_subjects.
        # Only the internally created statement and this disposable fixed file.
        with tempfile.TemporaryDirectory(prefix="wam-public-assurance-") as temporary:
            root=Path(temporary); artifact=root/"public-fixture.bin"
            with artifact.open("xb") as stream: stream.write(_PUBLIC_ARTIFACT)
            statement=create_provenance(source_repository="https://github.com/Urriki1502/wam-privacy-wallet", source_commit="0"*40, lock=lock, artifacts=[artifact], artifact_base=root,
                builder_id="urn:wam-wallet:public-fixture:unqualified-local",
                build_type="urn:wam-wallet:synthetic-offline-preview:v1",
                parameters={"scope":"synthetic-regtest","evidence":"PUBLIC_FIXTURE_NOT_A_BUILD_ATTESTATION"})
            verify_subjects(statement,root)
            digest=provenance_digest(statement)
            if (type(digest) is not str or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest)
                    or type(statement) is not dict or len(statement["subject"])!=1
                    or len(statement["predicate"]["buildDefinition"]["resolvedDependencies"])!=3):
                raise ValueError
        return SecurityAssuranceReview(digest)
    except Exception:
        raise SecurityAssuranceReviewError("APP_SECURITY_ASSURANCE_DENIED") from None


def review_public_assurance_fixture(*, scope: object, consent: object) -> SecurityAssuranceReview:
    """Fixed fresh child avoids cached/mutable upstream modules in GUI process."""
    if consent is not True or type(scope) is not str or scope != "synthetic-regtest":
        raise SecurityAssuranceReviewError("APP_SECURITY_ASSURANCE_DENIED")
    try:
        result=subprocess.run([sys.executable,"-I","-B","-m",
            "wam_privacy_wallet.application._security_assurance_worker"],
            input=b"PUBLIC_ASSURANCE_FIXTURE_V1\n", stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=15, check=False)
        if result.returncode!=0 or not 1<=len(result.stdout)<=2048:raise ValueError
        data=json.loads(result.stdout)
        expected={"provenance_digest","subject_count","dependency_count","source_commit","evidence",
            "publisher_authenticated","runtime_authenticated","release_allowed","sign_allowed","broadcast_allowed"}
        if (type(data) is not dict or set(data)!=expected
                or type(data["provenance_digest"]) is not str or len(data["provenance_digest"])!=64
                or data["provenance_digest"] != _PUBLIC_PROVENANCE_DIGEST
                or type(data["subject_count"]) is not int or data["subject_count"]!=1
                or type(data["dependency_count"]) is not int or data["dependency_count"]!=3
                or data["source_commit"]!=_PIN or data["evidence"]!="PINNED_UNSIGNED_PUBLIC_PROVENANCE_UNTRUSTED"
                or any(data[k] is not False for k in ("publisher_authenticated","runtime_authenticated",
                    "release_allowed","sign_allowed","broadcast_allowed"))):raise ValueError
        return SecurityAssuranceReview(data["provenance_digest"])
    except Exception:
        raise SecurityAssuranceReviewError("APP_SECURITY_ASSURANCE_DENIED") from None
