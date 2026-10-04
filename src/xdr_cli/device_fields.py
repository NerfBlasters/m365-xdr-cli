"""Device-detail conversions from observed Defender UI contracts.

Keep native provenance: inventory and detail views are not interchangeable.
See docs/portal_cookie.md for source definitions and semantic differences.
"""
from __future__ import annotations

import re

# Device details enrollment codes observed in the portal UI (0..44).
# Official /api/$metadata restricts managedByStatus to Unknown/Success/Error.
# Future codes, strings, and booleans must not inherit an enrollment outcome.

def management_fields(code: object) -> dict:
    if type(code) is not int or code not in range(45):
        return {}
    if code in (0, 2, 23):
        provider = 'Unknown'
    elif code in (3, 21):
        provider = 'Intune'
    elif code in (4, 22):
        provider = 'SystemCenterConfigurationManager'
    else:
        provider = 'MicrosoftDefenderForEndpoint'
    if code in (0, 2, 3, 4, 21, 22, 23):
        status = 'Unknown'
    elif code in (1, 19, 34, 35, 39, 43):
        status = 'Success'
    else:
        status = 'Error'
    result = {'managedBy': provider, 'managedByStatus': status}
    return result


def additional_device_fields(detail: dict, inventory: dict | None = None) -> tuple[dict, dict]:
    """Return supported fields and their sources; never infer absent booleans."""
    mapped = management_fields(detail.get('MemEnrollmentStatus'))
    sources = {key: 'device.MemEnrollmentStatus' for key in mapped}
    if detail.get('IsExcluded') is False:
        mapped['exclusionReason'] = None
        sources['exclusionReason'] = 'device.IsExcluded=false'
    if 'MergedIntoMachineId' in detail:
        target = detail['MergedIntoMachineId']
        if target is None or (isinstance(target, str) and re.fullmatch(r'[0-9a-fA-F]{40}', target)):
            mapped['mergedIntoMachineId'] = target
            sources['mergedIntoMachineId'] = 'device.MergedIntoMachineId'
    # Cloud-app/system labels are not MDE machine tags. Do not copy McasTags.
    tags = detail.get('ExtendedMachineTags')
    if isinstance(tags, dict):
        user_tags = tags.get('UserDefinedTags')
        dynamic_tags = detail.get('DynamicRulesTags', tags.get('DynamicRulesTags'))
        if all(isinstance(v, list) and all(isinstance(t, str) for t in v)
               for v in (user_tags, dynamic_tags)):
            mapped['machineTags'] = list(dict.fromkeys(user_tags + dynamic_tags))
            sources['machineTags'] = 'device.ExtendedMachineTags.UserDefinedTags+DynamicRulesTags'
    if inventory is not None:
        if 'CloudResourceDetails' in inventory:
            cloud = inventory['CloudResourceDetails']
            if cloud is None:
                mapped['vmMetadata'] = None
            elif (isinstance(cloud, dict) and cloud.get('CloudEnvironment') == 'Azure'
                  and all(isinstance(cloud.get(k), str) and cloud[k]
                          for k in ('VmId', 'ResourceId', 'SubscriptionId'))):
                mapped['vmMetadata'] = {
                    'vmId': cloud['VmId'], 'resourceId': cloud['ResourceId'],
                    'subscriptionId': cloud['SubscriptionId'], 'cloudProvider': 'Azure',
                }
            if 'vmMetadata' in mapped:
                sources['vmMetadata'] = 'inventory.CloudResourceDetails'
        # Missing AssetValue differs from an explicitly null value: the UI
        # defaults the latter to Normal. A rule-set value takes precedence.
        if 'AssetValue' in inventory and 'DynamicAssetValue' in inventory:
            value = inventory['DynamicAssetValue']
            if value is None:
                value = inventory['AssetValue']
            if value is None:
                value = 'Normal'
            if value in ('Normal', 'Low', 'High'):
                mapped['deviceValue'] = value
                sources['deviceValue'] = 'inventory.DynamicAssetValue/AssetValue (null=Normal)'
        # Do not mistake an AD ParentGroups entry for an MDE RBAC group.
        if ('RbacGroupId' in detail and 'RbacGroupId' in inventory
                and type(inventory['RbacGroupId']) is type(detail['RbacGroupId'])
                and inventory['RbacGroupId'] == detail['RbacGroupId']
                and 'MachineGroup' in inventory
                and (inventory['MachineGroup'] is None
                     or isinstance(inventory['MachineGroup'], str))):
            mapped['rbacGroupName'] = inventory['MachineGroup']
            sources['rbacGroupName'] = 'inventory.MachineGroup (matched RbacGroupId)'
    return mapped, sources


def adapter_addresses(payload: dict) -> list[dict] | None:
    """Map reported adapters only; portal omission of loopbacks remains explicit."""
    adapters = payload.get('IpAdapters')
    if not isinstance(adapters, list):
        return None
    rows = []
    for adapter in adapters:
        if not isinstance(adapter, dict):
            return None
        ips = adapter.get('IpAddresses')
        if ips is None and isinstance(adapter.get('Ipv4Addresses'), list) and isinstance(
            adapter.get('Ipv6Addresses'), list,
        ):
            ips = adapter['Ipv4Addresses'] + adapter['Ipv6Addresses']
        if not isinstance(ips, list):
            return None
        for ip in ips:
            if not isinstance(ip, dict) or not isinstance(ip.get('Address'), str):
                return None
            fields = {'ipAddress': ip['Address']}
            for native, canonical in (
                ('PhysicalAddress', 'macAddress'), ('InterfaceType', 'type'),
                ('OperationalStatus', 'operationalStatus'),
            ):
                if native in adapter:
                    if adapter[native] is not None and not isinstance(adapter[native], str):
                        return None
                    fields[canonical] = adapter[native]
            if fields not in rows:
                rows.append(fields)
    return rows


def exclusion_reason(payload: dict) -> str | None:
    # Portal justification names differ from the official ExclusionReason enum.
    return {
        'InactiveMachine': 'InactiveDevice', 'DuplicateMachine': 'DuplicateDevice',
        'MachineNotExists': 'DeviceDoesNotExist', 'MachineOutOfScope': 'DeviceOutOfScope',
        'Other': 'Other',
    }.get(payload.get('Justification')) if isinstance(payload.get('Justification'), str) else None
