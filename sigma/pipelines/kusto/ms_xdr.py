from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
    DropDetectionItemTransformation,
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
                identifier="set_state",
                transformation=SetStateTransformation(
                    key="query_table", val="DeviceProcessEvents"
                ),
                rule_conditions=[
                    LogsourceCondition(category="process_creation"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping",
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
                        "ParentImage": ["InitiatingProcessFolderPath"],
                        "ParentCommandLine": ["InitiatingProcessCommandLine"],
                        "ParentUser": ["InitiatingProcessAccountName"],
                    }
                ),
            ),
        ],
    )
