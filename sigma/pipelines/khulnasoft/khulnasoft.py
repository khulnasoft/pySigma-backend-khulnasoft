from sigma.pipelines.common import (
    logsource_windows,
    logsource_windows_process_creation,
    logsource_windows_registry_add,
    logsource_windows_registry_delete,
    logsource_windows_registry_event,
    logsource_windows_registry_set,
    logsource_windows_file_event,
    logsource_linux_process_creation,
    generate_windows_logsource_items,
)
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    RuleFailureTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    ExcludeFieldCondition,
    RuleProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_sysmon_acceleration_keywords = {  # Map Sysmon event sources and keywords that are added to search for Sysmon optimization pipeline
    "process_creation": "ParentProcessGuid",
    "file_event": "TargetFilename",
}

khulnasoft_sysmon_process_creation_cim_mapping = {
    "CommandLine": "Processes.process",
    "Computer": "Processes.dest",
    "CurrentDirectory": "Processes.process_current_directory",
    "Image": "Processes.process_path",
    "IntegrityLevel": "Processes.process_integrity_level",
    "OriginalFileName": "Processes.original_file_name",
    "ParentCommandLine": "Processes.parent_process",
    "ParentImage": "Processes.parent_process_path",
    "ParentProcessGuid": "Processes.parent_process_guid",
    "ParentProcessId": "Processes.parent_process_id",
    "ProcessGuid": "Processes.process_guid",
    "ProcessId": "Processes.process_id",
    "User": "Processes.user",
}

khulnasoft_windows_registry_cim_mapping = {
    "Computer": "Registry.dest",
    "Details": "Registry.registry_value_data",
    "EventType": "Registry.action",  # EventType: DeleteKey is parsed to action: deleted
    "Image": "Registry.process_path",
    "ProcessGuid": "Registry.process_guid",
    "ProcessId": "Registry.process_id",
    "TargetObject": "Registry.registry_key_name",
}

khulnasoft_windows_file_event_cim_mapping = {
    "Computer": "Filesystem.dest",
    "CreationUtcTime": "Filesystem.file_create_time",
    "Image": "Filesystem.process_path",
    "ProcessGuid": "Filesystem.process_guid",
    "ProcessId": "Filesystem.process_id",
    "TargetFilename": "Filesystem.file_path",
}

khulnasoft_web_proxy_cim_mapping = {
    "c-uri": "Web.url",
    "c-uri-query": "Web.uri_query",
    "c-uri-stem": "Web.uri_path",
    "c-useragent": "Web.http_user_agent",
    "cs-method": "Web.http_method",
    "cs-host": "Web.dest",
    "cs-referrer": "Web.http_referrer",
    "src_ip": "Web.src",
    "dst_ip": "Web.dest_ip",
}


def khulnasoft_windows_pipeline():
    return ProcessingPipeline(
        name="Khulnasoft Windows log source conditions",
        allowed_backends={"khulnasoft"},
        priority=20,
        items=generate_windows_logsource_items("source", "WinEventLog:{source}")
        + [
            ProcessingItem(  # Field mappings
                identifier="khulnasoft_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "EventCode",
                    }
                ),
            )
        ],
    )


def khulnasoft_windows_sysmon_acceleration_keywords():
    return ProcessingPipeline(
        name="Khulnasoft Windows Sysmon search acceleration keywords",
        allowed_backends={"khulnasoft"},
        priority=25,
        items=[
            ProcessingItem(  # Some optimizations searching for characteristic keyword for specific log sources
                identifier="khulnasoft_windows_sysmon_process_creation",
                transformation=AddConditionTransformation(
                    {
                        None: keyword,
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(
                        category=sysmon_category,
                        product="windows",
                        service="sysmon",
                    )
                ],
            )
            for sysmon_category, keyword in windows_sysmon_acceleration_keywords.items()
        ],
    )


def khulnasoft_cim_data_model():
    return ProcessingPipeline(
        name="Khulnasoft CIM Data Model Mapping",
        allowed_backends={"khulnasoft"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_process_creation_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Khulnasoft Data Model Sigma backend supports only the following fields for process_creation log source: "
                    + ",".join(khulnasoft_sysmon_process_creation_cim_mapping.keys())
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=khulnasoft_sysmon_process_creation_cim_mapping.keys()
                    )
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_process_creation",
                transformation=FieldMappingTransformation(
                    khulnasoft_sysmon_process_creation_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_fields_sysmon_process_creation",
                transformation=SetStateTransformation(
                    "fields", khulnasoft_sysmon_process_creation_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_sysmon_process_creation_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Processes"
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_registry_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Khulnasoft Data Model Sigma backend supports only the following fields for registry log source: "
                    + ",".join(khulnasoft_windows_registry_cim_mapping.keys())
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=khulnasoft_windows_registry_cim_mapping.keys()
                    )
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_registry",
                transformation=FieldMappingTransformation(
                    khulnasoft_windows_registry_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_fields_sysmon_registry",
                transformation=SetStateTransformation(
                    "fields", khulnasoft_windows_registry_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_sysmon_registry_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Registry"
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_file_event_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Khulnasoft Data Model Sigma backend supports only the following fields for file_event log source: "
                    + ",".join(khulnasoft_windows_file_event_cim_mapping.keys())
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=khulnasoft_windows_file_event_cim_mapping.keys()
                    )
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_file_event",
                transformation=FieldMappingTransformation(
                    khulnasoft_windows_file_event_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_fields_sysmon_file_event",
                transformation=SetStateTransformation(
                    "fields", khulnasoft_windows_file_event_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_sysmon_file_event_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Filesystem"
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_web_proxy_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Khulnasoft Data Model Sigma backend supports only the following fields for web proxy log source: "
                    + ",".join(khulnasoft_web_proxy_cim_mapping.keys())
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=khulnasoft_web_proxy_cim_mapping.keys()
                    )
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_web_proxy",
                transformation=FieldMappingTransformation(
                    khulnasoft_web_proxy_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_fields_web_proxy",
                transformation=SetStateTransformation(
                    "fields", khulnasoft_web_proxy_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_web_proxy_data_model_set",
                transformation=SetStateTransformation("data_model_set", "Web.Proxy"),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="khulnasoft_dm_mapping_log_source_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not yet supported by the Khulnasoft data model CIM pipeline!"
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition(
                        "khulnasoft_dm_mapping_sysmon_process_creation"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "khulnasoft_dm_mapping_sysmon_registry"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "khulnasoft_dm_mapping_sysmon_file_event"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "khulnasoft_dm_mapping_web_proxy"
                    ),
                ],
            ),
        ],
    )
