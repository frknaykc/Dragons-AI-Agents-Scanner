"""Explicit online build provisioning; scanning and notice generation stay offline.

Only the reviewed, digest-pinned upstream sources are fetched. Run this during
CI dependency provisioning, never as a side effect of scanning or packaging.
"""

import argparse
import sys
import urllib.request
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.standalone_licenses import SOURCE_DIGESTS, LicenseError, cached_source, digest

MAX_SOURCE_BYTES = 8 * 1024 * 1024


def provision(cache: Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    for url, expected in SOURCE_DIGESTS.items():
        target = cache / digest(url.encode())
        if target.is_symlink():
            raise LicenseError("symlinked license source cache")
        if target.exists():
            cached_source(url, cache)  # Reject corruption rather than overwriting it.
            continue
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES or digest(data) != expected:
            raise LicenseError(f"upstream license source checksum mismatch: {url}")
        with target.open("xb") as output:
            output.write(data)
        cached_source(url, cache)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    provision(parser.parse_args().cache)


if __name__ == "__main__":
    main()
