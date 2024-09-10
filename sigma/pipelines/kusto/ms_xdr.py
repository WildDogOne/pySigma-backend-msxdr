from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
    DropDetectionItemTransformation,
    ReplaceStringTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    MatchStringCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


def ms_xdr() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Microsoft Defender XDR",
        priority=30,
        allowed_backends=("ms_xdr"),
        items=[
            # DeviceProcessEvents
            ProcessingItem(
                identifier="device_process_events",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceProcessEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="process_creation"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping_device_process_events",
                transformation=FieldMappingTransformation(
                    mapping={
                        "ProcessId": ["ProcessId"],
                        "Image": ["FolderPath"],
                        "FileVersion": ["ProcessVersionInfoProductVersion"],
                        "Description": ["ProcessVersionInfoFileDescription"],
                        "Product": ["ProcessVersionInfoProductName"],
                        "Company": ["ProcessVersionInfoCompanyName"],
                        "OriginalFileName": ["ProcessVersionInfoOriginalFileName"],
                        "CommandLine": ["ProcessCommandLine"],
                        "User": ["AccountName"],
                        "LogonId": ["LogonId"],
                        "IntegrityLevel": ["ProcessIntegrityLevel"],
                        "sha1": ["SHA1"],
                        "sha256": ["SHA256"],
                        "md5": ["MD5"],
                        "Hashes": ["SHA1", "SHA256", "MD5"],
                        "ParentProcessId": ["InitiatingProcessId"],
                        "ParentProcessName": ["InitiatingProcessFileName"],
                        "ParentImage": ["InitiatingProcessFolderPath"],
                        "ParentCommandLine": ["InitiatingProcessCommandLine"],
                        "ParentUser": ["InitiatingProcessAccountName"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="process_creation"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping_device_process_events",
                transformation=ReplaceStringTransformation(
                    regex=".*/", replacement=""
                ),
                rule_conditions=[
                    LogsourceCondition(category="process_creation"),
                    
                ],
                field_name_conditions=[IncludeFieldCondition(fields=["InitiatingProcessFileName"], type="plain")]
            ),
            # DeviceImageLoadEvents
            ProcessingItem(
                identifier="device_image_load_events",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceImageLoadEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="image_load"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping_device_image_load_events",
                transformation=FieldMappingTransformation(
                    mapping={
                        "ProcessId": ["InitiatingProcessId"],
                        "Image": [
                            "InitiatingProcessFolderPath # File path of the process that loaded the image"
                        ],
                        "ImageLoaded": ["FolderPath"],
                        "FileVersion": ["InitiatingProcessVersionInfoProductVersion"],
                        "Description": ["InitiatingProcessVersionInfoFileDescription"],
                        "Product": ["InitiatingProcessVersionInfoProductName"],
                        "Company": ["InitiatingProcessVersionInfoCompanyName"],
                        "OriginalFileName": [
                            "InitiatingProcessVersionInfoOriginalFileName"
                        ],
                        "sha1": ["SHA1"],
                        "sha256": ["SHA256"],
                        "md5": ["MD5"],
                        "User": ["InitiatingProcessAccountName"],
                        "Hashes": ["SHA1", "SHA256", "MD5"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="image_load"),
                ],
            ),
            # DeviceNetworkEvents
            ProcessingItem(
                identifier="device_network_events",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceNetworkEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping_device_network_events",
                transformation=FieldMappingTransformation(
                    mapping={
                        "ProcessId": ["InitiatingProcessId"],
                        "Image": ["InitiatingProcessFolderPath"],
                        "User": ["InitiatingProcessAccountName"],
                        "FileName": ["InitiatingProcessFileName"],
                        "Protocol": ["Protocol"],
                        "SourceIp": ["LocalIP"],
                        "SourceHostname": ["DeviceName"],
                        "SourcePort": ["LocalPort"],
                        "DestinationIp": ["RemoteIP"],
                        "DestinationHostname": ["RemoteUrl"],
                        "DestinationPort": ["RemotePort"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
            ),
            # DeviceFileEvents
            ProcessingItem(
                identifier="device_file_events",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceFileEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="file_access"),
                    LogsourceCondition(category="file_change"),
                    LogsourceCondition(category="file_delete"),
                    LogsourceCondition(category="file_event"),
                    LogsourceCondition(category="file_rename"),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="field_mapping_device_file_events",
                transformation=FieldMappingTransformation(
                    mapping={
                        "ProcessId": ["InitiatingProcessId"],
                        "Image": ["InitiatingProcessFolderPath"],
                        "TargetFilename": ["FolderPath"],
                        "User": ["RequestAccountName"],
                        "sha1": ["SHA1"],
                        "sha256": ["SHA256"],
                        "md5": ["MD5"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="file_access"),
                    LogsourceCondition(category="file_change"),
                    LogsourceCondition(category="file_delete"),
                    LogsourceCondition(category="file_event"),
                    LogsourceCondition(category="file_rename"),
                ],
                rule_condition_linking=any,
            ),
            # DeviceRegistryEvents
            ProcessingItem(
                identifier="device_network_events",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceRegistryEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="registry_add"),
                    LogsourceCondition(category="registry_delete"),
                    LogsourceCondition(category="registry_event"),
                    LogsourceCondition(category="registry_set"),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="field_mapping_device_network_events",
                transformation=FieldMappingTransformation(
                    mapping={
                        "EventType": ["ActionType"],
                        "ProcessId": ["InitiatingProcessId"],
                        "Image": ["InitiatingProcessFolderPath"],
                        "TargetObject": ["RegistryKey"],
                        "Details": ["RegistryValueData"],
                        "User": ["InitiatingProcessAccountName"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="registry_add"),
                    LogsourceCondition(category="registry_delete"),
                    LogsourceCondition(category="registry_event"),
                    LogsourceCondition(category="registry_set"),
                ],
                rule_condition_linking=any,
            ),
            # EmailEvents
            ProcessingItem(
                identifier="EmailEvents",
                transformation=SetStateTransformation(
                    key="query_table", val="EmailEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="EmailEvents"),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="field_mapping_EmailEvents",
                transformation=FieldMappingTransformation(
                    mapping={
                        "EventType": ["ActionType"],
                        "User": ["InitiatingProcessAccountName"],
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="EmailEvents"),
                ],
                rule_condition_linking=any,
            ),
        ],
    )
