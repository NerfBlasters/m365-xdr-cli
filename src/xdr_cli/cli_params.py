"""Small Click converters preserving the values expected by command callbacks."""

from __future__ import annotations

from enum import Enum
from typing import Any

import click


class EnumValueChoice(click.Choice):
    """Match enum values (not member names), and deliver an enum member."""

    def __init__(self, enum: type[Enum], *, case_sensitive: bool = True) -> None:
        self.enum = enum
        super().__init__([member.value for member in enum], case_sensitive=case_sensitive)

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> Enum:
        if isinstance(value, self.enum):
            return value
        return self.enum(super().convert(value, param, ctx))


def optional_multiple(
    ctx: click.Context,
    param: click.Parameter,
    value: tuple[Any, ...],
) -> list[Any] | None:
    """Retain the CLI's optional-list binding: omitted is None, supplied is list."""
    return list(value) if value else None
