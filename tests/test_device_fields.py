"""Synthetic field contracts; no tenant records or browser bundles in fixtures."""
import pytest

from xdr_cli.device_fields import adapter_addresses, additional_device_fields, management_fields


@pytest.mark.parametrize('code', [True, False, None, '3', 3.0, -1, 45, 999])
def test_unknown_enrollment_does_not_invent_management(code):
    assert management_fields(code) == {}


def test_management_uses_enrollment_not_inventory():
    mapped, sources = additional_device_fields({'MemEnrollmentStatus': 3}, {'ManagedBy': 'Other'})
    assert mapped == {'managedBy': 'Intune', 'managedByStatus': 'Unknown'}
    assert sources['managedBy'] == 'device.MemEnrollmentStatus'


@pytest.mark.parametrize('code,status', [
    (1, 'Success'), (19, 'Success'), (20, 'Error'), (43, 'Success'),
    (44, 'Error'), (40, 'Error'), (36, 'Error'),
    (42, 'Error'), (16, 'Error'),
    (41, 'Error'), (15, 'Error'), (18, 'Error'), (5, 'Error'),
])
def test_management_status_distinguishes_enrollment_outcomes(code, status):
    assert management_fields(code)['managedByStatus'] == status


def test_tags_separate_cloud_and_system_labels_from_mde_tags():
    mapped, _ = additional_device_fields({
        'ExtendedMachineTags': {'UserDefinedTags': ['one', 'two'],
                                'McasTags': ['New'], 'BuiltInTags': ['group']},
        'DynamicRulesTags': ['two', 'rule'],
    })
    assert mapped['machineTags'] == ['one', 'two', 'rule']


@pytest.mark.parametrize('detail', [{}, {'ExtendedMachineTags': {}}, {
    'ExtendedMachineTags': {'UserDefinedTags': 'one'}, 'DynamicRulesTags': [],
}])
def test_missing_or_malformed_tags_are_not_reported_as_empty(detail):
    assert 'machineTags' not in additional_device_fields(detail)[0]


def test_empty_tags_are_an_observation():
    mapped, _ = additional_device_fields({
        'ExtendedMachineTags': {'UserDefinedTags': []}, 'DynamicRulesTags': [],
    })
    assert mapped['machineTags'] == []


def test_inventory_value_precedence_and_matching_group():
    inventory = {'AssetValue': 'Low', 'DynamicAssetValue': 'High',
                 'MachineGroup': 'synthetic group', 'RbacGroupId': 7}
    mapped, _ = additional_device_fields({'RbacGroupId': 7}, inventory)
    assert mapped == {'deviceValue': 'High', 'rbacGroupName': 'synthetic group'}
    inventory['RbacGroupId'] = 8
    assert 'rbacGroupName' not in additional_device_fields({'RbacGroupId': 7}, inventory)[0]


def test_explicit_default_is_distinct_from_absent_or_unknown_value():
    assert additional_device_fields({}, {'AssetValue': None, 'DynamicAssetValue': None})[0] == {
        'deviceValue': 'Normal',
    }
    for inventory in (
        {}, {'AssetValue': None}, {'AssetValue': 'Future', 'DynamicAssetValue': None},
    ):
        assert 'deviceValue' not in additional_device_fields({}, inventory)[0]


def test_merge_and_exclusion_absence_are_not_fabricated():
    assert additional_device_fields({})[0] == {}
    assert additional_device_fields({'IsExcluded': False, 'MergedIntoMachineId': None})[0] == {
        'exclusionReason': None, 'mergedIntoMachineId': None,
    }
    assert additional_device_fields({'MergedIntoMachineId': 'b' * 40})[0] == {
        'mergedIntoMachineId': 'b' * 40,
    }
    assert 'mergedIntoMachineId' not in additional_device_fields({'MergedIntoMachineId': 'bad'})[0]
    assert 'exclusionReason' not in additional_device_fields({'IsExcluded': True})[0]


def test_adapter_mapping_does_not_invent_loopbacks_or_missing_mac():
    rows = adapter_addresses({'IpAdapters': [{
        'InterfaceType': 'Ethernet', 'OperationalStatus': 'Up',
        'IpAddresses': [{'Address': '192.0.2.1'}, {'Address': '192.0.2.1'}],
    }]})
    assert rows == [{'ipAddress': '192.0.2.1', 'type': 'Ethernet', 'operationalStatus': 'Up'}]
    assert adapter_addresses({'IpAdapters': []}) == []
    assert adapter_addresses({}) is None
    assert adapter_addresses({'IpAdapters': [{'IpAddresses': ['bad']}]}) is None


@pytest.mark.parametrize('code,provider', [
    (0, 'Unknown'), (2, 'Unknown'), (23, 'Unknown'), (3, 'Intune'), (21, 'Intune'),
    (4, 'SystemCenterConfigurationManager'), (22, 'SystemCenterConfigurationManager'),
    (1, 'MicrosoftDefenderForEndpoint'), (5, 'MicrosoftDefenderForEndpoint'),
])
def test_provider_uses_official_enum_names(code, provider):
    assert management_fields(code)['managedBy'] == provider


def test_cloud_metadata_does_not_treat_missing_or_non_azure_resource_as_null():
    assert 'vmMetadata' not in additional_device_fields({}, {})[0]
    assert additional_device_fields({}, {'CloudResourceDetails': None})[0]['vmMetadata'] is None
    cloud = {'CloudEnvironment': 'Azure', 'VmId': 'synthetic-vm',
             'ResourceId': '/synthetic/resource', 'SubscriptionId': 'synthetic-subscription'}
    value = additional_device_fields({}, {'CloudResourceDetails': cloud})[0]['vmMetadata']
    assert value['cloudProvider'] == 'Azure'
    assert value['vmId'] == 'synthetic-vm'
    cloud['CloudEnvironment'] = 'OtherCloud'
    assert 'vmMetadata' not in additional_device_fields({}, {'CloudResourceDetails': cloud})[0]


@pytest.mark.parametrize('native,expected', [
    ('InactiveMachine', 'InactiveDevice'), ('DuplicateMachine', 'DuplicateDevice'),
    ('MachineNotExists', 'DeviceDoesNotExist'), ('MachineOutOfScope', 'DeviceOutOfScope'),
    ('Other', 'Other'), ('future', None), ([], None),
])
def test_exclusion_reason_uses_official_enum(native, expected):
    from xdr_cli.device_fields import exclusion_reason

    assert exclusion_reason({'Justification': native}) == expected
