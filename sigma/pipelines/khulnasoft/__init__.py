from .khulnasoft import (
    khulnasoft_windows_pipeline,
    khulnasoft_windows_sysmon_acceleration_keywords,
    khulnasoft_cim_data_model,
)

pipelines = {
    "khulnasoft_windows": khulnasoft_windows_pipeline,
    "khulnasoft_sysmon_acceleration": khulnasoft_windows_sysmon_acceleration_keywords,
    "khulnasoft_cim": khulnasoft_cim_data_model,
}
