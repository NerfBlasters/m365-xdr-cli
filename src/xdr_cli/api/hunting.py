"""Advanced Hunting through the selected operation backend."""
from xdr_cli.backend_contract import Backend
from xdr_cli.hunting_result import HuntingResult


async def run_query(client: Backend, kql: str) -> HuntingResult:
    """Run hunting without changing authentication backends on failure."""
    return await client.execute_hunting(kql)
