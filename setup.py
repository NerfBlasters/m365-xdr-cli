"""Generate the installed investigation catalog from the versioned playbooks."""

import json
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPlaybookCatalog(build_py):
    def run(self):
        super().run()
        catalog = {}
        for path in sorted(Path("playbooks").glob("*.md")):
            if path.name in {"README.md", "index.md"}:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines[0] != "---" or not lines[1].startswith("inquiry: ") or lines[2] != "---":
                raise ValueError(f"Missing investigation metadata in {path}")
            catalog[path.stem] = json.loads(lines[1].removeprefix("inquiry: "))
        if not catalog:
            raise ValueError("Missing investigation playbooks")
        target = Path(self.build_lib) / "xdr_cli" / "inquiry_playbooks.json"
        target.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


setup(cmdclass={"build_py": BuildPlaybookCatalog})
