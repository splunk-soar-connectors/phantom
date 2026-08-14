# Phantom

Publisher: Splunk <br>
Connector Version: 5.0.0 <br>
Product Vendor: Phantom <br>
Product Name: Phantom <br>
Minimum Product Version: 8.6.0

This app integrates with the Phantom platform to perform investigative and containment actions

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
**verify_certificate** | optional | boolean | Verify HTTPS certificate (default: true) |
**deflate_item_extensions** | optional | string | Only files with the specified extensions (comma-separated) will be deflated. If blank, file extension will not be checked |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[add artifact](#action-add-artifact) - Add an artifact to a container <br>
[add listitem](#action-add-listitem) - Add a new row to a list <br>
[add note](#action-add-note) - Add a note to a container <br>
[create container](#action-create-container) - Create a new container <br>
[deflate item](#action-deflate-item) - Deflate a compressed item in the vault, adding the deflated items back to the vault <br>
[export container](#action-export-container) - Export a container from this Phantom instance to another Phantom instance <br>
[find artifacts](#action-find-artifacts) - Find all artifacts that have a certain value <br>
[find listitem](#action-find-listitem) - Find a value in a custom list <br>
[get action result](#action-get-action-result) - Find the results of a previously run action <br>
[import container](#action-import-container) - Import a container from another Phantom instance to this Phantom instance <br>
[make request](#action-make-request) - make request <br>
[no op](#action-no-op) - Performs no action, and can be used to introduce a configurable delay in a playbook <br>
[update artifact tags](#action-update-artifact-tags) - Add/remove tags from an artifact <br>
[update artifact](#action-update-artifact) - Update an artifact <br>
[update list](#action-update-list) - Update rows in an existing list

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add artifact'

Add an artifact to a container

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | optional | Name of artifact | string | |
**container_id** | optional | Container to add the artifact to | numeric | `phantom container id` |
**label** | optional | Artifact label | string | |
**source_data_identifier** | required | Source data identifier | string | |
**cef_name** | optional | Name of a CEF field | string | |
**cef_value** | optional | Value for the CEF field | string | `\*` |
**cef_dictionary** | optional | JSON string of CEF fields and values | string | |
**contains** | optional | Data type for the CEF field | string | |
**run_automation** | optional | Run active playbooks | boolean | |
**determine_contains** | optional | Determine the contains for the CEF fields | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.name | string | | |
action_result.parameter.container_id | numeric | `phantom container id` | |
action_result.parameter.label | string | | |
action_result.parameter.source_data_identifier | string | | |
action_result.parameter.cef_name | string | | |
action_result.parameter.cef_value | string | `\*` | |
action_result.parameter.cef_dictionary | string | | |
action_result.parameter.contains | string | | |
action_result.parameter.run_automation | boolean | | |
action_result.parameter.determine_contains | boolean | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.success | boolean | | True False |
action_result.data.\*.failed | boolean | | True False |
action_result.data.\*.existing_artifact_id | numeric | | |
action_result.summary.artifact_id | numeric | | |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.server | string | `url` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add listitem'

Add a new row to a list

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** | required | Name/ID of the list to append to | string | |
**new_row** | required | Value(s) to append to the list | string | `\*` |
**create** | optional | Create the list if it does not exist | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.list | string | | |
action_result.parameter.new_row | string | `\*` | |
action_result.parameter.create | boolean | | |
action_result.data.\*.status | string | | success failed |
action_result.summary.server | string | `url` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add note'

Add a note to a container

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**title** | required | Title of note | string | |
**content** | optional | Content of note | string | |
**container_id** | optional | Container ID | numeric | `phantom container id` |
**phase_id** | optional | Phase ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.title | string | | |
action_result.parameter.content | string | | |
action_result.parameter.container_id | numeric | `phantom container id` | |
action_result.parameter.phase_id | string | | |
action_result.data.\*.message | string | | Note created |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create container'

Create a new container

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_json** | required | JSON string of the container | string | |
**container_artifacts** | optional | List of artifact objects in JSON format | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.container_json | string | | |
action_result.parameter.container_artifacts | string | | |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.artifact_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'deflate item'

Deflate a compressed item in the vault, adding the deflated items back to the vault

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of the item to deflate | string | `sha1` `vault id` |
**container_id** | optional | Container to add the deflated items to | numeric | `phantom container id` |
**password** | optional | Password for the archive | password | |
**recursive** | optional | Recursively deflate the item | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `sha1` `vault id` | |
action_result.parameter.container_id | numeric | `phantom container id` | |
action_result.parameter.password | string | | |
action_result.parameter.recursive | boolean | | |
action_result.data.\*.name | string | | |
action_result.data.\*.hash | string | `sha1` | |
action_result.data.\*.container_id | numeric | `phantom container id` | |
action_result.data.\*.vault_id | string | `sha1` `vault id` | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.metadata.md5 | string | `md5` | |
action_result.data.\*.metadata.sha1 | string | `sha1` | |
action_result.data.\*.metadata.sha256 | string | `sha256` | |
action_result.summary.total_vault_items | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'export container'

Export a container from this Phantom instance to another Phantom instance

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | required | Container ID to export to configured Phantom asset | numeric | `phantom container id` |
**keep_owner** | optional | Attempt to keep the same container owner | boolean | |
**label** | optional | Label to apply to the exported container | string | |
**run_automation** | optional | Enable active playbooks on the new container | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.container_id | numeric | `phantom container id` | |
action_result.parameter.keep_owner | boolean | | |
action_result.parameter.label | string | | |
action_result.parameter.run_automation | boolean | | |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.artifact_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'find artifacts'

Find all artifacts that have a certain value

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cef_key** | optional | CEF key to search on | string | |
**values** | required | Value to search for | string | `\*` |
**exact_match** | optional | Value must match exactly | boolean | |
**limit_search** | optional | Limit search to given container IDs | boolean | |
**container_ids** | optional | Container IDs to limit the search to | string | |
**max_results** | optional | Max number of artifacts to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.cef_key | string | | |
action_result.parameter.values | string | `\*` | |
action_result.parameter.exact_match | boolean | | |
action_result.parameter.limit_search | boolean | | |
action_result.parameter.container_ids | string | | |
action_result.parameter.max_results | numeric | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.container | numeric | | |
action_result.data.\*.container_name | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.found in | string | | |
action_result.data.\*.matched | string | | |
action_result.summary.artifacts_found | numeric | | |
action_result.summary.server | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'find listitem'

Find a value in a custom list

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** | required | Name/ID of the list to search | string | |
**column_index** | optional | Column index to match against (indexing starts at 0) | numeric | |
**values** | required | Value to search for | string | `\*` |
**exact_match** | optional | List value must match exactly | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.list | string | | |
action_result.parameter.column_index | numeric | | |
action_result.parameter.values | string | `\*` | |
action_result.parameter.exact_match | boolean | | |
action_result.data.\*.list_name | string | | |
action_result.data.\*.row.\* | string | | |
action_result.data.\*.found_at | string | | |
action_result.summary.server | string | `url` | |
action_result.summary.found_matches | numeric | | |
action_result.summary.list_id | numeric | | |
action_result.summary.locations.\*.\* | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get action result'

Find the results of a previously run action

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** | required | Name of action to search for | string | |
**parameters** | optional | Parameters to search for, in JSON format | string | |
**app** | optional | App to filter on | string | |
**asset** | optional | Asset to filter on | string | |
**time_limit** | optional | Hours to search back | numeric | |
**max_results** | optional | Max number of results to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.action_name | string | | |
action_result.parameter.parameters | string | | |
action_result.parameter.app | string | | |
action_result.parameter.asset | string | | |
action_result.parameter.time_limit | numeric | | |
action_result.parameter.max_results | numeric | | |
action_result.summary.num_results | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'import container'

Import a container from another Phantom instance to this Phantom instance

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | required | Container ID on the configured Phantom asset to import | numeric | `phantom container id` |
**keep_owner** | optional | Attempt to keep the same container owner | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.container_id | numeric | `phantom container id` | |
action_result.parameter.keep_owner | boolean | | |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.artifact_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Phantom REST endpoint to call, appended to the asset base URL. Example: '/rest/version' | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | {"version": "6.0.0"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'no op'

Performs no action, and can be used to introduce a configurable delay in a playbook

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sleep_seconds** | required | Number of seconds to wait | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.sleep_seconds | numeric | | |
action_result.data.\*.message | string | | Slept for 15 seconds |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update artifact tags'

Add/remove tags from an artifact

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | Artifact ID to update | string | `phantom artifact id` |
**add_tags** | optional | Comma separated list of tags to add | string | |
**remove_tags** | optional | Comma separated list of tags to remove | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.artifact_id | string | `phantom artifact id` | |
action_result.parameter.add_tags | string | | |
action_result.parameter.remove_tags | string | | |
action_result.data.\*.status | string | | success |
action_result.summary.tags_added | string | | |
action_result.summary.tags_removed | string | | |
action_result.summary.tags_already_present | string | | |
action_result.summary.tags_already_absent | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update artifact'

Update an artifact

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | Artifact ID to update | string | `phantom artifact id` |
**name** | optional | Name of artifact | string | |
**label** | optional | Label of artifact | string | |
**severity** | optional | Severity of artifact | string | |
**cef_json** | optional | JSON string of CEF fields | string | |
**cef_types_json** | optional | JSON string of CEF data types (contains) | string | |
**tags** | optional | Comma separated list of tags | string | |
**overwrite** | optional | Overwrite artifact with provided values | boolean | |
**artifact_json** | optional | JSON string of the whole artifact to overwrite | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.artifact_id | string | `phantom artifact id` | |
action_result.parameter.name | string | | |
action_result.parameter.label | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.cef_json | string | | |
action_result.parameter.cef_types_json | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.overwrite | boolean | | |
action_result.parameter.artifact_json | string | | |
action_result.data.\*.response.success | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update list'

Update rows in an existing list

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_name** | optional | Name of the custom list | string | |
**id** | optional | ID of the custom list | numeric | |
**row_number** | required | Row number of the list to update (index starts from 0) | numeric | |
**row_values_as_list** | required | Values to set the row to, as a JSON formatted list | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.list_name | string | | |
action_result.parameter.id | numeric | | |
action_result.parameter.row_number | numeric | | |
action_result.parameter.row_values_as_list | string | | |
action_result.data.\*.success | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
