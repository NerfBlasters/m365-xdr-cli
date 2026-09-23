"""Application context passed through Typer commands."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from xdr_cli.auth import AuthManager
    from xdr_cli.client import XDRClient
    from xdr_cli.config import Config
    from xdr_cli.sessions import Recorder


@dataclass
class AppContext:
    """Shared state for all CLI commands."""

    config: Config
    no_interactive: bool = False
    debug: bool = False
    # Tri-state: None = auto (pipe detection), True = --quiet, False = --no-quiet.
    quiet: bool | None = None
    # Recorder for the current invocation; None when no session is active.
    recorder: Recorder | None = None
    # Pre-run intent captured via --rationale (Task 7); empty when not provided.
    rationale: str = ""
    # Subcommand chain captured by leaf-callback wrapping (see
    # main.py._install_leaf_hook). E.g. "hunt run".
    invoked_command: str | None = None
    session_attachment: str = "unattached"
    anchor_incident: str | None = None
    anchor_alert: str | None = None
    anchor_provenance: dict[str, str] = field(default_factory=dict)
    _auth: AuthManager | None = None
    _client: XDRClient | None = None

    @property
    def effective_quiet(self) -> bool:
        """Resolve quiet: explicit flag > stdout-is-pipe > False."""
        if self.quiet is not None:
            return self.quiet
        return not sys.stdout.isatty()

    @property
    def is_interactive(self) -> bool:
        """Whether we can prompt the user for input."""
        if self.no_interactive:
            return False
        return sys.stdin.isatty() and sys.stdout.isatty()

    @property
    def session_id(self) -> str | None:
        """Active session id, or None when no session is in scope."""
        if self.recorder is None or self.recorder.session is None:
            return None
        return self.recorder.session.id

    @property
    def session_label(self) -> str | None:
        """Active session label, or None when no session is in scope."""
        if self.recorder is None or self.recorder.session is None:
            return None
        return self.recorder.session.label
