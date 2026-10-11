"""Fetch *only* official WAM release signing metadata over verified HTTPS.

This is an opt-in, nonexecuting input to the existing offline GnuPG verifier.
There is no arbitrary URL, redirect, proxy configuration, Core executable,
archive download, wallet data or authority grant in this module.

A successful TLS fetch alone is NOT proof of publisher identity: callers must
cryptographically verify the detached signature against the pinned WAM key.
"""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import ssl
import tempfile
from typing import Iterator

_HOST = "wamcoin.org"
_ASSETS = (
    ("key", "/SIGNING-KEY.asc", "SIGNING-KEY.asc", 32_768),
    ("checksums", "/downloads/v0.1.11/SHA256SUMS", "SHA256SUMS", 131_072),
    ("signature", "/downloads/v0.1.11/SHA256SUMS.asc", "SHA256SUMS.asc", 16_384),
)


class OfficialMetadataError(ValueError):
    """Redacted, stable errors without URLs, network traces or file bytes."""


def _fetch_fixed_asset(path: str, maximum: int, *, timeout: float = 6) -> bytes:
    """Read bounded exact response bytes; 3 fixed URLs, system TLS trust, no redirects.

    Do not use urllib's transparent proxies, redirects, implicit decompression
    or environment-derived destinations. A server-selected redirect is denied
    because HTTPSConnection never follows it.
    """
    if (type(path) is not str or path not in {part[1] for part in _ASSETS}
            or type(maximum) is not int
            or maximum != next(part[3] for part in _ASSETS if part[1] == path)
            or type(timeout) not in (int, float) or not 0 < timeout <= 15):
        raise OfficialMetadataError("CORE_OFFICIAL_REQUEST_DENIED")
    connection = None
    try:
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            _HOST, timeout=timeout, context=context,
        )
        connection.request(
            "GET", path, headers={
                "Accept": "application/octet-stream",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise OfficialMetadataError("CORE_OFFICIAL_HTTP_DENIED")
        encoding = response.getheader("Content-Encoding")
        if encoding is not None and encoding.strip().lower() != "identity":
            raise OfficialMetadataError("CORE_OFFICIAL_ENCODING_DENIED")
        announced = response.getheader("Content-Length")
        if announced is not None and (
            type(announced) is not str or not announced.isascii()
            or not announced.isdecimal() or len(announced) > 12
            or not 0 < int(announced) <= maximum
        ):
            raise OfficialMetadataError("CORE_OFFICIAL_SIZE_DENIED")
        data = response.read(maximum + 1)
        if (type(data) is not bytes or not 0 < len(data) <= maximum
                or (announced is not None and len(data) != int(announced))):
            raise OfficialMetadataError("CORE_OFFICIAL_SIZE_DENIED")
        return data
    except OfficialMetadataError:
        raise
    except (OSError, TimeoutError, ValueError, ssl.SSLError, http.client.HTTPException):
        raise OfficialMetadataError("CORE_OFFICIAL_TRANSPORT_DENIED") from None
    finally:
        if connection is not None:
            connection.close()


@contextmanager
def official_release_metadata() -> Iterator[dict[str, Path]]:
    """Download signed metadata to a disposable, owner-private directory.

    These files are inputs for signature verification, NOT automatically
    authentic release receipts. No download is retained after exit.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="wam-official-metadata-") as root:
            folder = Path(root)
            if os.name != "nt":
                folder.chmod(0o700)
            result: dict[str, Path] = {}
            for label, path, filename, maximum in _ASSETS:
                body = _fetch_fixed_asset(path, maximum)
                target = folder / filename
                flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY
                         | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
                fd = os.open(target, flags, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(body)
                result[label] = target
            yield result
    except OfficialMetadataError:
        raise
    except OSError:
        raise OfficialMetadataError("CORE_OFFICIAL_STORAGE_DENIED") from None
