# Phantom

Publisher: Splunk <br>
Connector Version: 3.8.4 <br>
Product Vendor: Phantom <br>
Product Name: Phantom <br>
Minimum Product Version: 6.3.0

This App exposes various Phantom APIs as actions

The auth_token config parameter is for use with Phantom instances. If both the token and
username/password are given, the username and password will be used to authenticate to the Phantom
instance.

Note that the IP (or name) being used must match the allowed IP in the remote Phantom instance's
REST asset configuration.

In case the **phantom_server** configuration parameter is set to the current Phantom instance, i.e.,
the Phantom server through which the app is being used, then the **verify_certificate** should be
set to False in the asset configuration.

For information on how to obtain an authorization token, see Provisioning an Authorization Token in
the Phantom REST Overview documentation.

If the value provided in the **phantom_server** configuration parameter is 0.0.0.0 then the **test
connectivity** passes successfully and the actions will run on the current phantom instance, i.e.,
the server through which the app is being used.

See [KB article 7](https://my.phantom.us/kb/7/) and [KB article 16](https://my.phantom.us/kb/16/) on
how to create and verify a valid HTTPS certificate for your Phantom instance.

For security reasons, accessing 127.0.0.1 is not allowed.

For NRI instances, the Device IP/Hostname configuration parameter needs to specify the port number
as well. (Eg. x.x.x.x:9999)

## Playbook Backward Compatibility

- The existing action parameters have been modified in the actions given below. Hence, it is
  requested to the end-user to please update their existing playbooks by re-inserting the
  corresponding action blocks or by providing appropriate values to these action parameters to
  ensure the correct functioning of the playbooks created on the earlier versions of the app.

  - Update List - The **row_values_as_list** parameter, has been changed from the
    comma-separated new values to a JSON formatted list of new values. This will allow the user
    to provide a value containing a comma(',') character. The example for the same has been
    updated in the example values.

  - Add Artifact - The **contains** parameter, can take a string(or a comma-separated list of
    string) or a JSON dictionary, with the keys matching the keys of the **cef_dictionary** and
    the values being lists of possible contains for the CEF field. In case, the **contains**
    parameter is a string(or a comma-separated list of string), the provided value will map to
    the **cef_name** parameter.\
    The output datapaths, **action_result.summary.artifact id** and
    **action_result.summary.container id** have been replaced with
    **action_result.summary.artifact_id** and **action_result.summary.container_id** ,
    respectively.

  - Find Artifacts - The **action_result.summary.artifacts found** datapath has been replaced
    with **action_result.summary.artifacts_found.**

  - Find Listitem - The **action_result.summary.found matches** datapath has been replaced with
    **action_result.summary.found_matches.**

  - Update Artifact Tags - The following output datapaths have been added:

    - action_result.summary.tags_added
    - action_result.summary.tags_already_absent
    - action_result.summary.tags_already_present
    - action_result.summary.tags_removed

  - Update Artifact - The action parameters of this action have been modified. Please update
    your existing playbooks according to the new parameters. Below is the list of the added
    parameters:

    - name: Artifact name (Always overwrites, if provided)
    - label: Artifact label (Always overwrites, if provided)
    - severity: Artifact severity (Always overwrites, if provided)
    - cef_types_json: JSON format of the CEF types (e.g., {'myIP': ['ip', 'ipv6']})
    - tags: Comma-separated list of tags to add or replace in the artifact
    - overwrite: Overwrite artifacts with provided input (applies to: cef_json, contains_json,
      tags)
    - artifact_json: JSON format of entire artifact (Always overwrites provided keys)

    For further details, check the **update artifact** section.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Phantom server. Below are the default
ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Known Issues

- The **find listitem** action is unable to fetch the list, where the **list name** contains a
  forward slash('/') character.
- The **add listitem** action is unable to update the list, where the **list name** contains a
  forward slash('/') character.
- The **find artifacts** action does not work as per the expectation, for the case where we have a
  backslash('\\') character in the cef_value. This happens for both exact match and
  non-exact-match.
- The **find artifacts** action is unable to fetch the artifacts, where cef values contain Unicode
  character(s), on Phantom version 4.8.23319. The action works fine on Phantom version 4.5.15922.

### Configuration variables

This table lists the configuration variables required to operate Phantom. These variables are specified when configuring a Phantom asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**phantom_server** | required | string | Phantom IP or Hostname (e.g. 10.1.1.10 or valid_phantom_hostname) |
**auth_token** | optional | password | Phantom Auth token |
**username** | optional | string | Username (for HTTP basic auth) |
**password** | optional | password | Password (for HTTP basic auth) |
**verify_certificate** | optional | boolean | Verify HTTPS certificate (default: false) |
**deflate_item_extensions** | optional | string | Only files with the specified extensions (comma-separated) will be deflated. If blank, file extension will not be checked |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity <br>
[update artifact](#action-update-artifact) - Update or overwrite Phantom artifact with the provided input <br>
[add note](#action-add-note) - Add a note to a container <br>
[update artifact tags](#action-update-artifact-tags) - Add/Remove tags from an artifact <br>
[find artifacts](#action-find-artifacts) - Find artifacts containing a CEF value <br>
[add listitem](#action-add-listitem) - Add value to a custom list <br>
[find listitem](#action-find-listitem) - Find value in a custom list <br>
[add artifact](#action-add-artifact) - Add a new artifact to a container <br>
[deflate item](#action-deflate-item) - Deflates an item from the vault <br>
[export container](#action-export-container) - Export local container to the configured Phantom asset <br>
[import container](#action-import-container) - Import a container from an external Phantom instance <br>
[create container](#action-create-container) - Create a new container on a Phantom instance <br>
[get action result](#action-get-action-result) - Find the results of a previously run action <br>
[update list](#action-update-list) - Update a list <br>
[no op](#action-no-op) - Wait for the specified number of seconds

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'update artifact'

Update or overwrite Phantom artifact with the provided input

Type: **generic** <br>
Read only: **False**

<h4>Overwrite</h4>By default, this action will append or update these fields: "cef_json", "cef_types_json", and "tags", unless "overwrite" is enabled. In which case, those parameters will replace the entirety of current versions of what that artifact contains.<h4>Optional Fields</h4>While all are not required, for the action to run, at least one of the following optional parameters need to be provided:<table><thead><tr><th>PARAMETER</th><th>EXAMPLE</th></tr></thead><tbody><tr><td>name</td><td>Artifact Name</td></tr><tr><td>label</td><td>artifact_label</td></tr><tr><td>severity</td><td>high</td></tr><tr><td>cef_json</td><td>{"key1": "value1", "goodDomain": "www.splunk.com", "remove_me": ""}</td></tr><tr><td>cef_types_json</td><td>{"goodDomain": ["domain"]}</td></tr><tr><td>tags</td><td>tag1, tag3 <i>or</i> ["tag2", "tag4"]</td></tr><tr><td>artifact_json</td><td>{"source_data_identifier": "myTicket1234", "label": "new_label"}</td></tr></tbody></table><h4>Artifact JSON</h4>Artifact JSON should be used for more advanced aspects of Phantom artifacts. See Phantom REST API docs, specifically regarding artifacts.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | ID of artifact to update | string | `phantom artifact id` |
**name** | optional | Artifact name (Always overwrites, if provided) | string | |
**label** | optional | Artifact label (Always overwrites, if provided) | string | |
**severity** | optional | Artifact severity (Always overwrites, if provided) | string | |
**cef_json** | optional | JSON format of the CEF fields you want in the artifact | string | |
**cef_types_json** | optional | JSON format of the CEF types (e.g., {'myIP': ['ip', 'ipv6']}) | string | |
**tags** | optional | Comma-separated list of tags to add or replace in the artifact | string | |
**overwrite** | optional | Overwrite artifacts with provided input (applies to: cef_json, contains_json, tags) | boolean | |
**artifact_json** | optional | JSON format of entire artifact (Always overwrites provided keys) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.artifact_id | string | `phantom artifact id` | 2388 |
action_result.parameter.artifact_json | string | | {"severity": "high", "label": "test label", "description": "Artifact added by Me", "source_data_identifier": "my_custom_sdi"} |
action_result.parameter.cef_json | string | | {"new_field": "new_value", "deleted_field": ""} |
action_result.parameter.cef_types_json | string | | {"new_field": ["new contains"]} |
action_result.parameter.label | string | | test label |
action_result.parameter.name | string | | New Name |
action_result.parameter.overwrite | boolean | | True False |
action_result.parameter.severity | string | | high |
action_result.parameter.tags | string | | ["tag2"] |
action_result.data.\*.requested_artifact.cef.deleted_field | string | | |
action_result.data.\*.requested_artifact.cef.new_field | string | | new_value |
action_result.data.\*.requested_artifact.cef.test | string | | fff |
action_result.data.\*.requested_artifact.cef_types.new_field | string | | new contains |
action_result.data.\*.requested_artifact.description | string | | Artifact added by Me |
action_result.data.\*.requested_artifact.label | string | | test label |
action_result.data.\*.requested_artifact.name | string | | New Name |
action_result.data.\*.requested_artifact.severity | string | | high |
action_result.data.\*.requested_artifact.source_data_identifier | string | | my_custom_sdi |
action_result.data.\*.requested_artifact.tags | string | | tag2 |
action_result.data.\*.response.id | numeric | | 2388 |
action_result.data.\*.response.success | boolean | | True False |
action_result.summary | string | | |
action_result.message | string | | Artifact updated successfully. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add note'

Add a note to a container

Type: **generic** <br>
Read only: **False**

If the <b>container_id</b> parameter is left empty, then it will be initialized to the current container's id (from where the action is being run) and the status will be reflected accordingly. If the container is a case, a <b>phase_id</b> parameter can be provided to associate the note to a particular phase.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**title** | required | Title for the note | string | |
**content** | optional | Note content | string | |
**container_id** | optional | The container id (defaults to current container) | numeric | `phantom container id` |
**phase_id** | optional | Phase the note will be associated with | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | numeric | `phantom container id` | 35 |
action_result.parameter.content | string | | Adding a note via app action |
action_result.parameter.phase_id | string | | |
action_result.parameter.title | string | | Note test |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Note created |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update artifact tags'

Add/Remove tags from an artifact

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | The artifact id | string | `phantom artifact id` |
**add_tags** | optional | Comma-separated list of tags to add to the artifact | string | |
**remove_tags** | optional | Comma-separated list of tags to remove from the artifact | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.add_tags | string | | tag1, tag3 |
action_result.parameter.artifact_id | string | `phantom artifact id` | 94 |
action_result.parameter.remove_tags | string | | tag2, tag4 |
action_result.data | string | | |
action_result.summary.tags_added | string | | tag1 |
action_result.summary.tags_already_absent | string | | tag4 |
action_result.summary.tags_already_present | string | | tag3 |
action_result.summary.tags_removed | string | | tag2 |
action_result.message | string | | Tags added: tag1, Tags removed: tag2, Tags already present: tag3, Tags already absent: tag4 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'find artifacts'

Find artifacts containing a CEF value

Type: **investigate** <br>
Read only: **True**

If the <b>limit_search</b> parameter is set to true, then the action will search the required artifact in the provided <b>container_ids</b> only. Otherwise, the <b>container_ids</b> parameter will be ignored.<br><br>If any non-integer value is provided in the <b>container_ids</b> parameter, then all the non-integer values will be removed and the parameter will be updated accordingly. If the value of the <b>container_ids</b> parameter is <b>current</b>, then it will be replaced by the current container's id(from which the action is being run) and the status will be reflected accordingly.<br><br>If the <b>exact_match</b> parameter is set to false, then the action will return all those artifacts for which the <b>values</b> parameter is a substring of any one of its cef values. Otherwise it will return those artifacts for which any one of its cef value matches exactly with the <b>values</b> parameter.<br><br>For the <b>values</b> of type integer, float or string, it is suggested to set the <b>exact_match</b> parameter to false.<br><br>By default, 10 artifacts are returned. If you would like to return more or less than 10 artifacts, update the <b>max_results</b> parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cef_key** | optional | Key of the cef dict you are querying: act, app, applicationProtocol, baseEventCount, bytesIn, etc. It will search the entire cef dictionary if blank | string | |
**values** | required | Find this value in artifacts | string | `\*` |
**exact_match** | optional | Exact match (default: true) | boolean | |
**limit_search** | optional | Limit search to specified containers (default: false) | boolean | |
**container_ids** | optional | List of space or comma separated container ids. the word "current" will be replaced by the current container id | string | |
**max_results** | optional | Maximum number of artifacts to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cef_key | string | | act app applicationProtocol |
action_result.parameter.container_ids | string | | current |
action_result.parameter.exact_match | boolean | | True False |
action_result.parameter.limit_search | boolean | | True False |
action_result.parameter.values | string | `\*` | test_value |
action_result.data.\*.container | numeric | | 1234 |
action_result.data.\*.container_name | string | | phantom_test |
action_result.data.\*.found in | string | | test_key |
action_result.data.\*.id | numeric | | 12345 |
action_result.data.\*.matched | string | | test_value |
action_result.data.\*.name | string | | Artifact_demo |
action_result.summary.artifacts_found | numeric | | 1 |
action_result.summary.server | string | | https://10.1.1.10 |
action_result.message | string | | Artifacts found: 1, Server: https://10.1.1.10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.max_results | numeric | | 2 |

## action: 'add listitem'

Add value to a custom list

Type: **generic** <br>
Read only: **False**

To add a row containing a single value to a list simply pass the value. However, to pass multiple values in a row, format it like a JSON array (e.g. ["item1", "item2", "item3"]).<br><br>The action will update the <b>list</b>, if the <b>list</b> already exists (even if the <b>create</b> parameter is set to true).<br><br>After creating or updating a list through this action, if the same list is updated from the UI, then the user needs to save those changes before updating the list through this action again, otherwise, the changes made from the UI will be overridden.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** | required | Name or ID of a custom list | string | |
**new_row** | required | New Row (string or JSON list) | string | `\*` |
**create** | optional | Create list if it does not exist (default: false) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.create | boolean | | True False |
action_result.parameter.list | string | | demo_list |
action_result.parameter.new_row | string | `\*` | ["value1","value2","value3"] |
action_result.data.\*.failed | boolean | | |
action_result.data.\*.success | boolean | | True False |
action_result.summary.server | string | `url` | https://10.1.1.10 |
action_result.message | string | | Server: https://10.1.1.10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'find listitem'

Find value in a custom list

Type: **investigate** <br>
Read only: **True**

Row and column coordinates for each matching value can be found in the result summary under "locations". The match is case sensitive.<br><br>If the <b>exact_match</b> parameter is set to false, then the action will return all those strings for which the <b>values</b> parameter is its substring. Otherwise it will return those strings which match exactly with the <b>values</b> parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** | required | Name or ID of a custom list | string | |
**column_index** | optional | Search in column number (0 based) | numeric | |
**values** | required | Value to search for | string | `\*` |
**exact_match** | optional | Exact match (default: true) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.column_index | numeric | | |
action_result.parameter.exact_match | boolean | | True False |
action_result.parameter.list | string | | list_demo |
action_result.parameter.values | string | `\*` | value1 |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.summary.found_matches | numeric | | 1 |
action_result.summary.list_id | numeric | | 18 |
action_result.summary.locations | numeric | | |
action_result.summary.locations.\* | numeric | | |
action_result.summary.server | string | `url` | https://10.1.1.10 |
action_result.message | string | | Server: https://10.1.1.10, Found matches: 1, Locations: [(1, 0)], List id: 18 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add artifact'

Add a new artifact to a container

Type: **generic** <br>
Read only: **False**

If the <b>container_id</b> parameter is left empty, then it will be initialized to the current container's id (from which the action is being run) and the status will be reflected accordingly.<br><br>CEF fields can be added to the artifact in two ways, either by using the <b>cef_name</b> and <b>cef_value</b> parameter or by using the <b>cef_dictionary</b> parameter. If the <b>cef_name</b>, <b>cef_value</b>, and <b>cef_dictionary</b> parameters are all included, the action will add the <b>cef_name</b> field to the <b>cef_dictionary</b>.<br><br>Using only the <b>cef_name</b> and <b>cef_value</b> parameter will result in the artifact having one CEF field.<br><br>The <b>cef_dictionary</b> parameter takes a JSON dictionary with key-value pairs representing CEF key-value pairs. To provide values containing double-quotes("), add a backslash(\\) before the double-quotes.<br>For e.g., {"X-Universally-Unique-Identifier":"test","Content-Type":"multipart/alternative; boundary=<b>\\"</b>Apple-Mail=\_0DA95D7E-B791-4751-8043-175949088A2C<b>\\"</b>>","Message-Id":"<abc@xyz.com>"}<br><br>The <b>contains</b> parameter can take a JSON dictionary, with the keys matching the keys of the <b>cef_dictionary</b> and the values being lists of possible contains for the CEF field. If a given value in the <b>cef_dictionary</b> is not present in the <b>contains</b> dictionary, the action will first check the list of default CEF fields. If not a default CEF field, then the action will attempt to identify the appropriate value for contains.<br>The <b>contains</b> parameter can also take a string(or a comma-separated list of strings) representing the contains for the <b>cef_value</b> parameter. This method should be used only if the <b>cef_name</b> and <b>cef_value</b> parameters are used.<br><br>If the <b>run_automation</b> parameter is set to true then the active playbooks will run automatically after the artifact is added. The active playbooks will run on the same container in which the artifact is added.<br><br>See the <a href="https://docs.splunk.com/Documentation/Phantom/4.8/PlatformAPI/RESTArtifacts" target="_blank">REST API Documentation</a> for more information on artifacts, CEF fields, and contains.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | optional | Name of the new artifact | string | |
**container_id** | optional | Numeric container ID for the new artifact | numeric | `phantom container id` |
**label** | optional | Artifact label (default: event) | string | |
**source_data_identifier** | required | Source Data Idenitifier | string | |
**cef_name** | optional | CEF Name | string | |
**cef_value** | optional | Value | string | `\*` |
**cef_dictionary** | optional | CEF JSON | string | |
**contains** | optional | Data type for each CEF field | string | |
**run_automation** | optional | Run automation on newly created artifact(s) (default: false) | boolean | |
**determine_contains** | optional | Determine contains for any CEF fields without a provided contains value (default: true) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cef_dictionary | string | | {"test_key": "test_value"} |
action_result.parameter.cef_name | string | | |
action_result.parameter.cef_value | string | `\*` | |
action_result.parameter.container_id | numeric | `phantom container id` | 1234 |
action_result.parameter.contains | string | | domain |
action_result.parameter.label | string | | event |
action_result.parameter.name | string | | Artifact_demo |
action_result.parameter.run_automation | string | | True False |
action_result.parameter.source_data_identifier | string | | |
action_result.parameter.determine_contains | boolean | | |
action_result.data.\*.existing_artifact_id | numeric | | |
action_result.data.\*.failed | boolean | | |
action_result.data.\*.id | numeric | | 123 |
action_result.data.\*.success | boolean | | True False |
action_result.summary.artifact_id | numeric | | 12345 |
action_result.summary.container_id | numeric | | 1234 |
action_result.summary.server | string | `url` | https://10.1.1.10 |
action_result.message | string | | Artifact id: 12345, Container id: 1234, Server: https://10.1.1.10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'deflate item'

Deflates an item from the vault

Type: **generic** <br>
Read only: **False**

The action will be supported only if the <b>phantom_server</b> parameter (in the asset configurations) is configured to the local Phantom instance, i.e., the instance from which the action is being run.<br><br>The action detects if the input vault item is a compressed file and deflates it. Every file found after deflation is then added to the vault. If <b>container_id</b> is specified will add to its vault, else to the current (the container whose context the action is executed) container. The action supports <b>zip</b>, <b>gzip</b>, <b>bz2</b>, <b>tar</b>, and <b>tgz</b> file types. In the case where the compressed file contains another compressed file in it, set the <b>recursive</b> parameter to true to deflate the inner compressed file.<br><br>If recursion is enabled and a password is specified, the application will use the password for given zip file only. The inner zip file will be extracted only if the file is not password protected. Among the different compression methods, only the zip supports password protection functionality.<br><br>For certain Unicode characters, the file name is not unzipped as it is, by the zipfile module.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID | string | `sha1` `vault id` |
**container_id** | optional | Destination container id | numeric | `phantom container id` |
**password** | optional | Password for the file | string | |
**recursive** | optional | Extract recursively (default: false) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | numeric | `phantom container id` | 3 |
action_result.parameter.password | string | | P@$$w0rd |
action_result.parameter.recursive | boolean | | True False |
action_result.parameter.vault_id | string | `sha1` `vault id` | f582ed9120fa3be94852c73e1cd188f2948f677f |
action_result.data.\*.aka.\* | string | | test.txt |
action_result.data.\*.container | string | | phantom_test |
action_result.data.\*.container_id | numeric | `phantom container id` | 1234 |
action_result.data.\*.contains.\* | string | | vault id |
action_result.data.\*.create_time | string | | 0 minutes ago |
action_result.data.\*.created_via | string | | automation |
action_result.data.\*.hash | string | `sha1` | 0a0e6c7ab7f77d058efd444279b81c4c6a9cf4ce |
action_result.data.\*.id | numeric | | 12 |
action_result.data.\*.metadata.contains | string | | vault id |
action_result.data.\*.metadata.md5 | string | `md5` | 0db33a0790b6d6d5c2e4425646eee7fc |
action_result.data.\*.metadata.sha1 | string | `sha1` | fece6c7ab7f77d058efd444279b81c4c6a9cf4ce |
action_result.data.\*.metadata.sha256 | string | `sha256` | 4f2155212cb0f74207bd0e4fd5ecae548ee2bae1d2dcd36c1d0ba0b6254bd4a1 |
action_result.data.\*.metadata.size | numeric | | 33 |
action_result.data.\*.mime_type | string | | text/plain |
action_result.data.\*.name | string | | tgz-test |
action_result.data.\*.path | string | | |
action_result.data.\*.size | numeric | | 10240 |
action_result.data.\*.task | string | | |
action_result.data.\*.user | string | | |
action_result.data.\*.vault_document | numeric | | |
action_result.data.\*.vault_id | string | `sha1` `vault id` | b90e6c7ab7f77d058efd444279b81c4c6a9cf4ce |
action_result.summary.total_vault_items | numeric | | 9 |
action_result.message | string | | Total vault items: 9 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'export container'

Export local container to the configured Phantom asset

Type: **generic** <br>
Read only: **False**

This action exports a container (that matches the <b>container_id</b>) from the local Phantom instance (the instance from where the action is being run) to the configured Phantom asset (that the action is being executed on).<br><br>The action will fail with an error message like <b>severity instance with name u'critical' does not exist</b>, if the container metadata on the local phantom instance and the configured Phantom asset does not match.<br><br>Set the <b>keep_owner</b> parameter to true if you want the owner of the container on the configured Phantom instance to match the owner on the local instance. Note that this will be based on Owner ID, not Owner Name.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | required | Container ID to copy | numeric | `phantom container id` |
**keep_owner** | optional | Keep Owner | boolean | |
**label** | optional | Label to name the export container. If blank, the export container will have the same name as the local container | string | |
**run_automation** | optional | Run active playbooks | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | numeric | `phantom container id` | 3 |
action_result.parameter.keep_owner | boolean | | True False |
action_result.parameter.label | string | | events |
action_result.parameter.run_automation | boolean | | True False |
action_result.data | string | | |
action_result.summary.artifact_count | numeric | | 268 |
action_result.summary.container_id | numeric | `phantom container id` | 94 |
action_result.message | string | | Container id: 94, Artifact count: 268 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'import container'

Import a container from an external Phantom instance

Type: **generic** <br>
Read only: **False**

This action imports a container (that matches the <b>container_id</b>) from the configured Phantom asset (that the action is being executed on) into the local Phantom instance (the instance from where the action is being run).<br><br>The action will fail with an error message like <b>severity instance with name u'critical' does not exist</b>, if the container metadata on the configured Phantom asset and the local phantom instance does not match.<br><br>Set the <b>keep_owner</b> parameter to true if you want the owner of the container on the local Phantom instance to match the owner on the configured instance. Note that this will be based on Owner ID, not Owner Name.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | required | Container ID to copy | numeric | `phantom container id` |
**keep_owner** | optional | Keep Owner | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | string | `phantom container id` | 3 |
action_result.parameter.keep_owner | boolean | | True False |
action_result.data | string | | |
action_result.summary.artifact_count | numeric | | 268 |
action_result.summary.container_id | numeric | `phantom container id` | 94 |
action_result.message | string | | Container id: 94, Artifact count: 268 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create container'

Create a new container on a Phantom instance

Type: **generic** <br>
Read only: **False**

This action creates a new container on the Phantom server, which is configured in the <b>phantom_server</b> asset parameter. The <b>container_json</b> parameter needs to be a JSON string. It is mandatory to provide a <b>label</b> key in the <b>container_json</b> parameter. The action will fail if the <b>container_json</b> has a label that does not exist on the destination Phantom asset.<br>E.g., {"name":"Test Container","label":"events"}<br><br>The <b>container_artifacts</b> is an optional parameter that needs to be a list of artifact objects as a JSON string. Each artifact JSON object should contain the following keys: <b>cef, cef_types, data, description, end_time, ingest_app_id, kill_chain, label, name, owner_id, severity, source_data_identifier, start_time, tags, type</b>. All other keys will be ignored.<br>E.g., [{"name": "artifact 1", "label":"label1", "cef": {"test": "123"}},{"name": "artifact 2", "label":"label2", "cef": {"test": "456"}}]<br><br>See <a href="https://docs.splunk.com/Documentation/Phantom/4.8/PlatformAPI/RESTArtifacts" target="_blank"><b>Splunk Phantom Documentation</b></a> for further details.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_json** | required | The container JSON object | string | |
**container_artifacts** | optional | List of artifact JSON objects | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_artifacts | string | | [{"name": "A human friendly name for artifact (1)", "label": "event", "source_data_identifier": 1},{"name": "A human friendly name for artifact (2)", "label": "event", "source_data_identifier": 2},{"name": "A human friendly name for artifact (3)", "label": "event", "source_data_identifier": 3}] |
action_result.parameter.container_json | string | | {"severity": "medium", "label": "events", "version": 1, "asset": 7, "status": "new", "description": "New Container from Phantom Helper", "tags": [], "data": {}, "name": "This is a container"} |
action_result.data | string | | |
action_result.summary.artifact_count | numeric | | 3 |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.failed_artifact_count | numeric | | 7 |
action_result.message | string | | Container id: 82, Artifact count: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get action result'

Find the results of a previously run action

Type: **investigate** <br>
Read only: **True**

This action returns the most recent results of the given <b>action_name</b> launched with the given <b>parameters</b> within the given <b>time_limit</b>.<br><br>The action will limit the number of results returned to the value in <b>max_results</b>. By default, the limit is 10. To get all the results, set the<b>max_results</b> parameter to 0.<br><br>The <b>parameters</b> parameter takes a JSON string in the format:<br><br><pre>{<br> "parameter_name1": "parameter_value1"<br> "parameter_name2": "parameter_value2"<br> ...<br>}</pre><br>The <b>app</b> parameter takes an app name, and if it is included, the action will only search for action results from that app. Similarly, the <b>asset</b> parameter takes an asset name, and if it is included, the action will only search for action results from that asset.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** | required | Action name | string | |
**parameters** | optional | JSON string of action parameters | string | |
**app** | optional | App name | string | |
**asset** | optional | Asset name | string | |
**time_limit** | optional | Number of hours to search back | numeric | |
**max_results** | optional | Maximum number of action results to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action_name | string | | blacklist ip |
action_result.parameter.app | string | | Phantom |
action_result.parameter.asset | string | | test_phantom |
action_result.parameter.max_results | numeric | | 5 |
action_result.parameter.parameters | string | | {"ip": "1.8.9.0"} |
action_result.parameter.time_limit | numeric | | 24 |
action_result.data.\*.action | string | | blacklist ip |
action_result.data.\*.action_run | numeric | | 2724 |
action_result.data.\*.app | numeric | | 121 |
action_result.data.\*.app_name | string | | Phantom |
action_result.data.\*.app_version | string | | 1.0.0 |
action_result.data.\*.asset | numeric | | 137 |
action_result.data.\*.container | numeric | | 1154 |
action_result.data.\*.effective_user | string | | |
action_result.data.\*.end_time | string | | 2017-11-06T20:30:27.991000Z |
action_result.data.\*.exception_occured | boolean | | True False |
action_result.data.\*.extra_data | string | | |
action_result.data.\*.id | numeric | | 2761 |
action_result.data.\*.message | string | | Successfully blacklisted IP |
action_result.data.\*.playbook_run | numeric | | 1056 |
action_result.data.\*.result_data.\*.data | numeric | | |
action_result.data.\*.result_data.\*.message | string | | IP blacklisted successfully |
action_result.data.\*.result_data.\*.parameter | string | | |
action_result.data.\*.result_data.\*.parameter.context.artifact_id | numeric | | 0 |
action_result.data.\*.result_data.\*.parameter.context.guid | string | | 293d0369-4801-417d-a1af-a73cf1200d3d |
action_result.data.\*.result_data.\*.parameter.context.parent_action_run | string | | |
action_result.data.\*.result_data.\*.status | string | | success |
action_result.data.\*.result_data.\*.summary | string | | |
action_result.data.\*.result_summary.total_objects | numeric | | 1 |
action_result.data.\*.result_summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.start_time | string | | 2017-11-06T20:30:04.879000Z |
action_result.data.\*.status | string | | success failed |
action_result.data.\*.version | numeric | | 1 |
action_result.summary.action_run_id | numeric | | 2761 |
action_result.summary.num_results | numeric | | |
action_result.message | string | | Action run id: 2761 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update list'

Update a list

Type: **generic** <br>
Read only: **False**

Either the <b>list_name</b> or </b>id</b> is required. If both, <b>list_name</b> and <b>id</b> parameters are provided and both of them point to different lists, then the <b>list_name</b> parameter will be preferred and the action will update the list specified in the list_name parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_name** | optional | List name | string | |
**id** | optional | List id | numeric | |
**row_number** | required | Row number in list to be modified | numeric | |
**row_values_as_list** | required | JSON formatted list of new values for the row | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | numeric | | |
action_result.parameter.list_name | string | | my first list |
action_result.parameter.row_number | numeric | | 0 |
action_result.parameter.row_values_as_list | string | | ["this", "is", "a", "test"] |
action_result.data.\*.success | boolean | | True |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'no op'

Wait for the specified number of seconds

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sleep_seconds** | required | Sleep for this many seconds | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.sleep_seconds | numeric | | 15 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Slept for 15 seconds |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
