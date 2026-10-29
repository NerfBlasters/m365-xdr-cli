"""Microsoft cloud endpoints shared by authentication and transports.

References: https://learn.microsoft.com/en-us/graph/deployments
https://learn.microsoft.com/en-us/defender-endpoint/gov
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class CloudProfile:
    name: str
    authority: str
    graph: str
    mde: str
    mde_resource: str
    portal: str

    @property
    def graph_scopes(self) -> list[str]:
        return [f"{self.graph}/.default"]

    @property
    def mde_scopes(self) -> list[str]:
        return [f"{self.mde_resource}/.default"]

    @property
    def token_cache_filename(self) -> str:
        return "token_cache.json" if self.name == "commercial" else "token_cache_gcc-high.json"


PROFILES = {
    "commercial": CloudProfile(
        "commercial", "https://login.microsoftonline.com", "https://graph.microsoft.com",
        "https://api.security.microsoft.com", "https://api.securitycenter.microsoft.com",
        "https://security.microsoft.com",
    ),
    "gcc-high": CloudProfile(
        "gcc-high", "https://login.microsoftonline.us", "https://graph.microsoft.us",
        "https://api-gov.securitycenter.microsoft.us", "https://api-gov.securitycenter.microsoft.us",
        "https://security.microsoft.us",
    ),
}


def cloud_profile(name: str = "commercial") -> CloudProfile:
    from xdr_cli.exceptions import ConfigError

    if not isinstance(name, str) or name not in PROFILES:
        raise ConfigError("cloud must be commercial or gcc-high.")
    return PROFILES[name]
