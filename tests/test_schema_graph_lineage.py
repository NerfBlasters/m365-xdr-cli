import pytest

from xdr_cli.schema_graph.lineage import UnsupportedLineage, recover_field_origins
from xdr_cli.schema_graph.model import InterpretationRecord, field_id, interpretation_id
from xdr_cli.schema_graph.probe import compile_source_sampling_query


@pytest.mark.parametrize(
    "query,column,expected",
    [
        (
            "Events | where Text contains 'a|b' | project User=AccountUpn",
            "User",
            "Events.AccountUpn",
        ),
        (
            "// a comment\nEvents | project User=AccountUpn | project Who=User",
            "Who",
            "Events.AccountUpn",
        ),
        (
            'Events | extend User=tostring(parse_json(Raw)["UserId"]) | project User',
            "User",
            "Events.Raw#/UserId",
        ),
        ("Events | summarize Count=count() by User=AccountUpn", "User", "Events.AccountUpn"),
        ("Events | distinct AccountUpn", "AccountUpn", "Events.AccountUpn"),
        ("let term='a;b|c'; Events | where Name == term | project Name", "Name", "Events.Name"),
        ("Events | project-rename User=AccountUpn", "User", "Events.AccountUpn"),
    ],
)
def test_recover_origins(query, column, expected):
    assert str(recover_field_origins(query).origin(column)) == expected


@pytest.mark.parametrize(
    "query,column",
    [
        ("Events | extend AccountUpn=strcat('prefix', AccountUpn)", "AccountUpn"),
        ("Events | project User=tolower(AccountUpn)", "User"),
        ("Events | summarize Count=count() by AccountUpn", "Count"),
        ("Events | project-rename User=AccountUpn", "AccountUpn"),
        ("Events | project-away AccountUpn", "AccountUpn"),
        ("Events | project Name | project AccountUpn", "AccountUpn"),
        ("let AccountUpn='constant'; Events | project AccountUpn", "AccountUpn"),
    ],
)
def test_calculated_and_removed_columns_have_no_origin(query, column):
    assert recover_field_origins(query).origin(column) is None


@pytest.mark.parametrize(
    "query",
    [
        "Events | join (Other) on Id",
        "union Events, Other",
        "let Events=Other; Events | project Id",
        "Events | invoke fn()",
        "Events | mv-expand Values",
        "Events | summarize count()",
        "Events | project X=(Id",
        "Events | project X=Id); Other",
    ],
)
def test_unsupported_shapes_fail_explicitly(query):
    with pytest.raises(UnsupportedLineage):
        recover_field_origins(query)


def test_same_operator_calculated_alias_cannot_be_mistaken_for_physical_column():
    origins = recover_field_origins("Events | extend X=strcat(User, 'suffix'), Y=X")
    assert origins.origin("Y") is None


@pytest.mark.parametrize(
    "expression",
    [
        "parse_json(Raw)",
        "todynamic(Raw)",
        "tostring(parse_json(Raw))",
        "tostring(todynamic(Raw))",
        "parse_json(tostring(Raw))",
        "tostring(parse_json(tostring(Raw)))",
        "parse_json(parse_json(Raw))",
    ],
)
def test_decoded_root_scalar_is_excluded_without_losing_other_columns(expression):
    origins = recover_field_origins(f"Events | project User={expression}, AccountUpn")
    # Decoding Raw='"user@example.com"' removes quotes that the top-level
    # probe's tostring(Raw) would retain. Do not attribute that decoded seed.
    assert origins.origin("User") is None
    assert origins.to_dict()["columns"]["User"] is None
    assert str(origins.origin("AccountUpn")) == "Events.AccountUpn"


@pytest.mark.parametrize(
    "query",
    [
        "Events | extend Parsed=parse_json(Raw) | project User=Parsed",
        "Events | extend Parsed=parse_json(Raw) | project User=tostring(Parsed)",
        "Events | project Parsed=todynamic(Raw) | project-rename User=Parsed",
        "Events | project Parsed=parse_json(Raw) | summarize Count=count() by User=Parsed",
    ],
)
def test_aliases_and_grouping_cannot_restore_a_decoded_scalar_origin(query):
    assert recover_field_origins(query).origin("User") is None


@pytest.mark.parametrize(
    "query,path",
    [
        ("Events | project User=tostring(Raw.UserId)", ("UserId",)),
        ("Events | project User=tostring(parse_json(Raw).UserId)", ("UserId",)),
        ("Events | project User=tostring(todynamic(Raw)['UserId'])", ("UserId",)),
        (
            "Events | project User=tostring(parse_json(tostring(Raw))['UserId'])",
            ("UserId",),
        ),
        (
            "Events | project User=tostring(parse_json(parse_json(Raw)).UserId)",
            ("UserId",),
        ),
        (
            "Events | project User=tostring(parse_json(Raw).ResourceData.UserId)",
            ("ResourceData", "UserId"),
        ),
        (
            "Events | extend Parsed=parse_json(Raw) | project User=tostring(Parsed.UserId)",
            ("UserId",),
        ),
        (
            "Events | project Parsed=todynamic(Raw) | project-rename Bag=Parsed "
            "| project User=tostring(Bag.ResourceData['UserId'])",
            ("ResourceData", "UserId"),
        ),
        (
            "Events | extend Parsed=parse_json(Raw) | project Leaf=Parsed.ResourceData "
            "| project User=tostring(parse_json(Leaf).UserId)",
            ("ResourceData", "UserId"),
        ),
    ],
)
def test_supported_dynamic_paths_match_the_single_root_decode_probe(query, path):
    locator = recover_field_origins(query).origin("User")
    assert locator is not None
    assert (locator.table, locator.column, locator.json_path) == ("Events", "Raw", path)
    interpretation = InterpretationRecord(
        interpretation_id(locator, "entra-upn", "actor"),
        field_id(locator), "user", "entra-upn", "actor", "upn-lower",
    )
    compiled = compile_source_sampling_query(interpretation, locator)
    access = "".join(f'["{segment}"]' for segment in path)
    assert f'tostring(parse_json(tostring(Raw)){access})' in compiled.kql


@pytest.mark.parametrize(
    "query",
    [
        "Events | project User=parse_json(tostring(parse_json(Raw))).UserId",
        "Events | project User=tostring(parse_json(tostring(Raw.ResourceData)).UserId)",
        "Events | project User=tostring(parse_json(tostring(parse_json(Raw).ResourceData))"
        ".UserId)",
        "Events | project Encoded=tostring(parse_json(Raw).ResourceData) "
        "| project User=tostring(todynamic(Encoded).UserId)",
        "Events | extend Parsed=parse_json(Raw) | project Text=tostring(Parsed) "
        "| project User=parse_json(Text).UserId",
        "Events | project Text=tostring(Raw) | project User=Text.UserId",
    ],
)
def test_extra_decoding_and_property_access_on_strings_are_not_attributed(query):
    assert recover_field_origins(query).origin("User") is None


@pytest.mark.parametrize(
    "operators",
    [
        "project Parsed=strcat(AccountUpn, 'suffix')",
        "extend Parsed='constant'",
        "project-away Parsed",
        "project AccountUpn",
    ],
)
def test_removed_or_overwritten_dynamic_alias_cannot_recover_its_previous_origin(operators):
    origins = recover_field_origins(
        f"Events | project Parsed=parse_json(Raw), AccountUpn | {operators} "
        "| project User=Parsed.UserId"
    )
    assert origins.origin("User") is None


def test_same_operator_write_shadows_the_previous_dynamic_alias():
    origins = recover_field_origins(
        "Events | extend Parsed=parse_json(Raw) "
        "| extend Parsed='constant', User=Parsed.UserId"
    )
    assert origins.origin("User") is None


@pytest.mark.parametrize('literal', [
    '@"C:\\Users\\"',
    "@'C:\\Users\\'",
    '@"a""b|c;d\\"',
    '"a\\\"b|c"',
])
def test_filter_strings_cannot_hide_projection(literal):
    origins = recover_field_origins(
        f'Events | where FolderPath startswith {literal} '
        '| project SHA1=InitiatingProcessSHA1'
    )
    assert str(origins.origin('SHA1')) == 'Events.InitiatingProcessSHA1'


@pytest.mark.parametrize('suffix', [
    'where Name == "unterminated',
    "where Name == @'unterminated",
    'where true /* unterminated',
    'where Name == ```unsupported```',
])
def test_malformed_or_unsupported_lexemes_fail_closed(suffix):
    with pytest.raises(UnsupportedLineage):
        recover_field_origins(f'Events | {suffix} | project SHA1=Other')
