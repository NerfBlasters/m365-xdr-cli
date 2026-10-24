"""Add route labels to legacy count-only local-validation test responses."""

import json
import re
from functools import wraps

from xdr_cli.hunting_result import HuntingResult


def keyed_rows(rows, query):
    labels = re.findall(r'"PairKey","([^"]+)","TargetLocator","([^"]+)"', query)
    cohorts = re.findall(r"let _xdr_seeds_\d+ = dynamic\((\[.*?\])\);", query)
    if not labels:
        return rows
    result = []
    for index, (key, locator) in enumerate(labels):
        row = next(row for row in rows if row["TargetLocator"] == locator)
        result.append(
            {
                **row,
                "PairKey": key,
                "MatchedSeeds": min(row["MatchedSeeds"], len(json.loads(cohorts[index]))),
            }
        )
    return result


def keyed_validation_response(function):
    @wraps(function)
    async def wrapped(client, query):
        result = await function(client, query)
        result.results = keyed_rows(result.results, query)
        return result

    return wrapped


def route_response(rows):
    async def respond(client, query):
        return HuntingResult(results=keyed_rows(rows, query), schema=[], stats={})

    return respond
