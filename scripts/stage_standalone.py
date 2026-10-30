"""Stage exactly one native executable after its local smoke test."""

import platform
import shutil
import sys
import tomllib

from scripts.build_standalone import ROOT, artifact_name
from scripts.standalone_licenses import notice_directory, verify_notices


def main() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    name = artifact_name(sys.platform, platform.machine(), version)
    source = ROOT / "dist" / name
    destination = ROOT / "release-staging"
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"missing native executable: {name}")
    verify_notices(source)
    destination.mkdir(exist_ok=False)
    shutil.copy2(source, destination / name)
    shutil.copytree(notice_directory(source), notice_directory(destination / name))
    verify_notices(destination / name)
    print(f"Staged {name} and verified adjacent license texts")


if __name__ == "__main__":
    main()
