"""Inspect distributions without extracting them; reject private local artifacts."""

import tarfile
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN = {
    ".git", ".env", ".xdr-cli", ".claude", ".codex", ".cursor",
    "superpowers", "findings", "session-logs", "token_cache.json",
}


def check_names(names: list[str]) -> None:
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or FORBIDDEN.intersection(path.parts):
            raise ValueError(f"Private or unsafe distribution member: {name}")
        if path.suffix.lower() in {".pem", ".key", ".pfx", ".p12", ".db", ".sqlite"}:
            raise ValueError(f"Unexpected sensitive artifact type: {name}")


def main() -> None:
    wheels, sources = list(Path("dist").glob("*.whl")), list(Path("dist").glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        check_names(names)
        for prefix in ("xdr_cli/queries/", "xdr_cli/lists_seed/", "xdr_cli/schema_graph/data/"):
            if not any(name.startswith(prefix) for name in names):
                raise ValueError(f"Missing packaged resources: {prefix}")
    with tarfile.open(sources[0]) as archive:
        check_names(archive.getnames())
        if any(item.issym() or item.islnk() or item.isdev() for item in archive):
            raise ValueError("Source archive contains links or device nodes")
    print("Wheel and source archive contain the expected public package files.")


if __name__ == "__main__":
    main()
