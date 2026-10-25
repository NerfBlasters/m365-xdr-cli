"""Explicit capability errors for operations absent from a selected backend."""

from __future__ import annotations


def unavailable():
    from xdr_cli.backend_contract import UnsupportedBackendCapability

    return UnsupportedBackendCapability(
        "This Live Response operation is unavailable on the selected backend.",
        suggested_fix="Use portal-cookie for interactive sessions or official for batch actions.",
    )


class UnsupportedLiveResponse:
    async def lr_capabilities(self, machine_id):
        raise unavailable()

    async def lr_command_definitions(self, session_id):
        raise unavailable()

    async def lr_open_session(self, machine_id, *, comment):
        raise unavailable()

    async def lr_get_session(self, session_id):
        raise unavailable()

    async def lr_iter_sessions(self, *, machine_id):
        raise unavailable()
        yield  # pragma: no cover

    async def lr_close_session(self, session_id):
        raise unavailable()

    async def lr_submit(self, session_id, command):
        raise unavailable()

    async def lr_submit_batch(self, machine_id, commands, *, comment):
        raise unavailable()

    async def lr_get_command(self, session_id, command_id):
        raise unavailable()

    async def lr_iter_commands(self, session_id):
        raise unavailable()
        yield  # pragma: no cover

    async def lr_cancel(self, session_id, command_id):
        raise unavailable()

    async def lr_iter_output(self, session_id, command_id):
        raise unavailable()
        yield  # pragma: no cover

    async def lr_result_transfer(self, session_id, command_id, *, index=0):
        raise unavailable()

    async def lr_iter_library(self):
        raise unavailable()
        yield  # pragma: no cover

    async def lr_library_transfer(self, name):
        raise unavailable()

    async def lr_upload_library(
        self,
        path,
        *,
        description,
        parameters_description,
        has_parameters,
        overwrite,
    ):
        raise unavailable()

    async def lr_delete_library(self, name):
        raise unavailable()
