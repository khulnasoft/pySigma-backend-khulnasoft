from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import pytest
from sigma.backends.khulnasoft import KhulnasoftBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.khulnasoft import khulnasoft_cim_data_model


@pytest.fixture
def khulnasoft_backend():
    return KhulnasoftBackend()


@pytest.fixture
def khulnasoft_custom_backend():
    return KhulnasoftBackend(
        query_settings=lambda x: {"custom.query.key": x.title},
        output_settings={"custom.key": "customvalue"},
    )


def test_khulnasoft_and_expression(khulnasoft_backend: KhulnasoftBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )

    assert khulnasoft_backend.convert(rule) == ['fieldA="valueA" fieldB="valueB"']


def test_khulnasoft_or_expression(khulnasoft_backend: KhulnasoftBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
    )
    assert khulnasoft_backend.convert(rule) == ['fieldA="valueA" OR fieldB="valueB"']


def test_khulnasoft_and_or_expression(khulnasoft_backend: KhulnasoftBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
    )
    assert khulnasoft_backend.convert(rule) == [
        'fieldA IN ("valueA1", "valueA2") fieldB IN ("valueB1", "valueB2")'
    ]


def test_khulnasoft_or_and_expression(khulnasoft_backend: KhulnasoftBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
    )
    assert khulnasoft_backend.convert(rule) == [
        '(fieldA="valueA1" fieldB="valueB1") OR (fieldA="valueA2" fieldB="valueB2")'
    ]


def test_khulnasoft_in_expression(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == ['fieldA IN ("valueA", "valueB", "valueC*")']
    )


def test_khulnasoft_field_name_with_whitespace(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: valueA
                condition: sel
        """
            )
        )
        == ['"field name"="valueA"']
    )


def test_khulnasoft_regex_query(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """
            )
        )
        == ['fieldB="foo" fieldC="bar"\n| regex fieldA="foo.*bar"']
    )


def test_khulnasoft_regex_query_implicit_or(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re:
                            - foo.*bar
                            - boo.*foo
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """
            )
        )
        == [
            '\n| rex field=fieldA "(?<fieldAMatch>foo.*bar)"\n| eval fieldACondition=if(isnotnull(fieldAMatch), "true", "false")\n| rex field=fieldA "(?<fieldAMatch2>boo.*foo)"\n| eval fieldACondition2=if(isnotnull(fieldAMatch2), "true", "false")\n| search fieldACondition="true" OR fieldACondition2="true" fieldB="foo" fieldC="bar"'
        ]
    )


def test_khulnasoft_regex_query_explicit_or(khulnasoft_backend: KhulnasoftBackend):

    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA|re: foo.*bar
                    sel2:
                        fieldB|re: boo.*foo
                    condition: sel1 or sel2
            """
            )
        )
        == [
            '\n| rex field=fieldA "(?<fieldAMatch>foo.*bar)"\n| eval fieldACondition=if(isnotnull(fieldAMatch), "true", "false")\n| rex field=fieldB "(?<fieldBMatch>boo.*foo)"\n| eval fieldBCondition=if(isnotnull(fieldBMatch), "true", "false")\n| search fieldACondition="true" OR fieldBCondition="true"'
        ]
    )


def test_khulnasoft_single_regex_query(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """
            )
        )
        == ['*\n| regex fieldA="foo.*bar"']
    )


def test_khulnasoft_cidr_query(khulnasoft_backend: KhulnasoftBackend):
    assert (
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """
            )
        )
        == ['fieldB="foo" fieldC="bar"\n| where cidrmatch("192.168.0.0/16", fieldA)']
    )


def test_khulnasoft_cidr_or(khulnasoft_backend: KhulnasoftBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing CIDR"):
        khulnasoft_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|cidr:
                            - 192.168.0.0/16
                            - 10.0.0.0/8
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """
            )
        )


def test_khulnasoft_fields_output(khulnasoft_backend: KhulnasoftBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            fields:
                - fieldA
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """
    )

    assert khulnasoft_backend.convert(rule) == ['fieldA="valueA" | table fieldA']


def test_khulnasoft_savedsearch_output(khulnasoft_backend: KhulnasoftBackend):
    rules = """
title: Test 1
description: |
  this is a description
  across two lines
status: test
logsource:
    category: test_category
    product: test_product
fields:
    - fieldA
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
fields:
    - fieldA
    - fieldB
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert (
        khulnasoft_backend.convert(SigmaCollection.from_yaml(rules), "savedsearches")
        == """
[default]
dispatch.earliest_time = -30d
dispatch.latest_time = now

[Test 1]
description = this is a description \\
across two lines
search = fieldB="foo" fieldC="bar" \\
| regex fieldA="foo.*bar" \\
| table fieldA

[Test 2]
description = 
search = fieldA="foo" fieldB="bar" \\
| table fieldA,fieldB"""
    )


def test_khulnasoft_savedsearch_output_custom(
    khulnasoft_custom_backend: KhulnasoftBackend,
):
    rules = """
title: Test 1
description: |
  this is a description
  across two lines
status: test
logsource:
    category: test_category
    product: test_product
fields:
    - fieldA
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
fields:
    - fieldA
    - fieldB
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert (
        khulnasoft_custom_backend.convert(
            SigmaCollection.from_yaml(rules), "savedsearches"
        )
        == """
[default]
dispatch.earliest_time = -30d
dispatch.latest_time = now
custom.key = customvalue

[Test 1]
custom.query.key = Test 1
description = this is a description \\
across two lines
search = fieldB="foo" fieldC="bar" \\
| regex fieldA="foo.*bar" \\
| table fieldA

[Test 2]
custom.query.key = Test 2
description = 
search = fieldA="foo" fieldB="bar" \\
| table fieldA,fieldB"""
    )


def test_khulnasoft_data_model_process_creation():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
Processes.process="test" by Processes.process Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level Processes.original_file_name Processes.parent_process
Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id Processes.process_guid Processes.process_id Processes.user
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_registry_add():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: registry_add
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_registry_delete():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: registry_delete
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_registry_event():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: registry_event
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """
| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", ""
        )
    ]


def test_khulnasoft_data_model_registry_event():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: registry_event
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_registry_set():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: registry_set
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_file_event():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where
Filesystem.file_path="test" by Filesystem.dest Filesystem.file_create_time Filesystem.process_path Filesystem.process_guid Filesystem.process_id Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_process_creation_linux():
    khulnasoft_backend = KhulnasoftBackend(
        processing_pipeline=khulnasoft_cim_data_model()
    )
    rule = """
title: Test
status: test
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    assert khulnasoft_backend.convert(
        SigmaCollection.from_yaml(rule), "data_model"
    ) == [
        """| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
Processes.process="test" by Processes.process Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level Processes.original_file_name Processes.parent_process
Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id Processes.process_guid Processes.process_id Processes.user
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )
    ]


def test_khulnasoft_data_model_no_data_model_specified():
    khulnasoft_backend = KhulnasoftBackend()
    rule = """
title: Test
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    with pytest.raises(
        SigmaFeatureNotSupportedByBackendError, match="No data model specified"
    ):
        khulnasoft_backend.convert(SigmaCollection.from_yaml(rule), "data_model")
