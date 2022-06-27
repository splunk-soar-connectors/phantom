[comment]: # "Auto-generated SOAR connector documentation"
# Phantom

Publisher: Splunk  
Connector Version: 3\.6\.0  
Product Vendor: Phantom  
Product Name: Phantom  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This App exposes various Phantom APIs as actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
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

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting the
    corresponding action blocks or by providing appropriate values to these action parameters to
    ensure the correct functioning of the playbooks created on the earlier versions of the app.

      

    -   Update List - The **row_values_as_list** parameter, has been changed from the
        comma-separated new values to a JSON formatted list of new values. This will allow the user
        to provide a value containing a comma(',') character. The example for the same has been
        updated in the example values.

    -   Add Artifact - The **contains** parameter, can take a string(or a comma-separated list of
        string) or a JSON dictionary, with the keys matching the keys of the **cef_dictionary** and
        the values being lists of possible contains for the CEF field. In case, the **contains**
        parameter is a string(or a comma-separated list of string), the provided value will map to
        the **cef_name** parameter.  
        The output datapaths, **action_result.summary.artifact id** and
        **action_result.summary.container id** have been replaced with
        **action_result.summary.artifact_id** and **action_result.summary.container_id** ,
        respectively.

    -   Find Artifacts - The **action_result.summary.artifacts found** datapath has been replaced
        with **action_result.summary.artifacts_found.**

    -   Find Listitem - The **action_result.summary.found matches** datapath has been replaced with
        **action_result.summary.found_matches.**

    -   Update Artifact Tags - The following output datapaths have been added:

          

        -   action_result.summary.tags_added
        -   action_result.summary.tags_already_absent
        -   action_result.summary.tags_already_present
        -   action_result.summary.tags_removed

    -   Update Artifact - The action parameters of this action have been modified. Please update
        your existing playbooks according to the new parameters. Below is the list of the added
        parameters:

          

        -   name: Artifact name (Always overwrites, if provided)
        -   label: Artifact label (Always overwrites, if provided)
        -   severity: Artifact severity (Always overwrites, if provided)
        -   cef_types_json: JSON format of the CEF types (e.g., {'myIP': \['ip', 'ipv6'\]})
        -   tags: Comma-separated list of tags to add or replace in the artifact
        -   overwrite: Overwrite artifacts with provided input (applies to: cef_json, contains_json,
            tags)
        -   artifact_json: JSON format of entire artifact (Always overwrites provided keys)

        For further details, check the **update artifact** section.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Phantom server. Below are the default
ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

## Known Issues

-   The **find listitem** action is unable to fetch the list, where the **list name** contains a
    forward slash('/') character.
-   The **add listitem** action is unable to update the list, where the **list name** contains a
    forward slash('/') character.
-   The **find artifacts** action does not work as per the expectation, for the case where we have a
    backslash('\\') character in the cef_value. This happens for both exact match and
    non-exact-match.
-   The **find artifacts** action is unable to fetch the artifacts, where cef values contain Unicode
    character(s), on Phantom version 4.8.23319. The action works fine on Phantom version 4.5.15922.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Phantom asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**phantom\_server** |  required  | string | Phantom IP or Hostname \(e\.g\. 10\.1\.1\.10 or valid\_phantom\_hostname\)
**auth\_token** |  optional  | password | Phantom Auth token
**username** |  optional  | string | Username \(for HTTP basic auth\)
**password** |  optional  | password | Password \(for HTTP basic auth\)
**verify\_certificate** |  optional  | boolean | Verify HTTPS certificate \(default\: false\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[update artifact](#action-update-artifact) - Update or overwrite Phantom artifact with the provided input  
[add note](#action-add-note) - Add a note to a container  
[update artifact tags](#action-update-artifact-tags) - Add/Remove tags from an artifact  
[find artifacts](#action-find-artifacts) - Find artifacts containing a CEF value  
[add listitem](#action-add-listitem) - Add value to a custom list  
[find listitem](#action-find-listitem) - Find value in a custom list  
[add artifact](#action-add-artifact) - Add a new artifact to a container  
[deflate item](#action-deflate-item) - Deflates an item from the vault  
[export container](#action-export-container) - Export local container to the configured Phantom asset  
[import container](#action-import-container) - Import a container from an external Phantom instance  
[create container](#action-create-container) - Create a new container on a Phantom instance  
[get action result](#action-get-action-result) - Find the results of a previously run action  
[update list](#action-update-list) - Update a list  
[no op](#action-no-op) - Wait for the specified number of seconds  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'update artifact'
Update or overwrite Phantom artifact with the provided input

Type: **generic**  
Read only: **False**

<h4>Overwrite</h4>By default, this action will append or update these fields\: "cef\_json", "cef\_types\_json", and "tags", unless "overwrite" is enabled\. In which case, those parameters will replace the entirety of current versions of what that artifact contains\.<h4>Optional Fields</h4>While all are not required, for the action to run, at least one of the following optional parameters need to be provided\:<table><thead><tr><th>PARAMETER</th><th>EXAMPLE</th></tr></thead><tbody><tr><td>name</td><td>Artifact Name</td></tr><tr><td>label</td><td>artifact\_label</td></tr><tr><td>severity</td><td>high</td></tr><tr><td>cef\_json</td><td>\{"key1"\: "value1", "goodDomain"\: "www\.splunk\.com", "remove\_me"\: ""\}</td></tr><tr><td>cef\_types\_json</td><td>\{"goodDomain"\: \["domain"\]\}</td></tr><tr><td>tags</td><td>tag1, tag3 <i>or</i> \["tag2", "tag4"\]</td></tr><tr><td>artifact\_json</td><td>\{"source\_data\_identifier"\: "myTicket1234", "label"\: "new\_label"\}</td></tr></tbody></table><h4>Artifact JSON</h4>Artifact JSON should be used for more advanced aspects of Phantom artifacts\. See Phantom REST API docs, specifically regarding artifacts\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact\_id** |  required  | ID of artifact to update | string |  `phantom artifact id` 
**name** |  optional  | Artifact name \(Always overwrites, if provided\) | string | 
**label** |  optional  | Artifact label \(Always overwrites, if provided\) | string | 
**severity** |  optional  | Artifact severity \(Always overwrites, if provided\) | string | 
**cef\_json** |  optional  | JSON format of the CEF fields you want in the artifact | string | 
**cef\_types\_json** |  optional  | JSON format of the CEF types \(e\.g\., \{'myIP'\: \['ip', 'ipv6'\]\}\) | string | 
**tags** |  optional  | Comma\-separated list of tags to add or replace in the artifact | string | 
**overwrite** |  optional  | Overwrite artifacts with provided input \(applies to\: cef\_json, contains\_json, tags\) | boolean | 
**artifact\_json** |  optional  | JSON format of entire artifact \(Always overwrites provided keys\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.artifact\_id | string |  `phantom artifact id` 
action\_result\.parameter\.artifact\_json | string | 
action\_result\.parameter\.cef\_json | string | 
action\_result\.parameter\.cef\_types\_json | string | 
action\_result\.parameter\.label | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.overwrite | boolean | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data\.\*\.requested\_artifact\.cef\.deleted\_field | string | 
action\_result\.data\.\*\.requested\_artifact\.cef\.new\_field | string | 
action\_result\.data\.\*\.requested\_artifact\.cef\.test | string | 
action\_result\.data\.\*\.requested\_artifact\.cef\_types\.new\_field | string | 
action\_result\.data\.\*\.requested\_artifact\.description | string | 
action\_result\.data\.\*\.requested\_artifact\.label | string | 
action\_result\.data\.\*\.requested\_artifact\.name | string | 
action\_result\.data\.\*\.requested\_artifact\.severity | string | 
action\_result\.data\.\*\.requested\_artifact\.source\_data\_identifier | string | 
action\_result\.data\.\*\.requested\_artifact\.tags | string | 
action\_result\.data\.\*\.response\.id | numeric | 
action\_result\.data\.\*\.response\.success | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add note'
Add a note to a container

Type: **generic**  
Read only: **False**

If the <b>container\_id</b> parameter is left empty, then it will be initialized to the current container's id \(from where the action is being run\) and the status will be reflected accordingly\. If the container is a case, a <b>phase\_id</b> parameter can be provided to associate the note to a particular phase\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**title** |  required  | Title for the note | string | 
**content** |  optional  | Note content | string | 
**container\_id** |  optional  | The container id \(defaults to current container\) | numeric |  `phantom container id` 
**phase\_id** |  optional  | Phase the note will be associated with | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.content | string | 
action\_result\.parameter\.phase\_id | string | 
action\_result\.parameter\.title | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update artifact tags'
Add/Remove tags from an artifact

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact\_id** |  required  | The artifact id | string |  `phantom artifact id` 
**add\_tags** |  optional  | Comma\-separated list of tags to add to the artifact | string | 
**remove\_tags** |  optional  | Comma\-separated list of tags to remove from the artifact | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.add\_tags | string | 
action\_result\.parameter\.artifact\_id | string |  `phantom artifact id` 
action\_result\.parameter\.remove\_tags | string | 
action\_result\.data | string | 
action\_result\.summary\.tags\_added | string | 
action\_result\.summary\.tags\_already\_absent | string | 
action\_result\.summary\.tags\_already\_present | string | 
action\_result\.summary\.tags\_removed | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'find artifacts'
Find artifacts containing a CEF value

Type: **investigate**  
Read only: **True**

If the <b>limit\_search</b> parameter is set to true, then the action will search the required artifact in the provided <b>container\_ids</b> only\. Otherwise, the <b>container\_ids</b> parameter will be ignored\.<br><br>If any non\-integer value is provided in the <b>container\_ids</b> parameter, then all the non\-integer values will be removed and the parameter will be updated accordingly\. If the value of the <b>container\_ids</b> parameter is <b>current</b>, then it will be replaced by the current container's id\(from which the action is being run\) and the status will be reflected accordingly\.<br><br>If the <b>exact\_match</b> parameter is set to false, then the action will return all those artifacts for which the <b>values</b> parameter is a substring of any one of its cef values\. Otherwise it will return those artifacts for which any one of its cef value matches exactly with the <b>values</b> parameter\.<br><br>For the <b>values</b> of type integer, float or string, it is suggested to set the <b>exact\_match</b> parameter to false\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cef\_key** |  optional  | Key of the cef dict you are querying\: act, app, applicationProtocol, baseEventCount, bytesIn, etc\. It will search the entire cef dictionary if blank | string | 
**values** |  required  | Find this value in artifacts | string |  `\*` 
**exact\_match** |  optional  | Exact match \(default\: true\) | boolean | 
**limit\_search** |  optional  | Limit search to specified containers \(default\: false\) | boolean | 
**container\_ids** |  optional  | List of space or comma separated container ids\. the word "current" will be replaced by the current container id | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cef\_key | string | 
action\_result\.parameter\.container\_ids | string | 
action\_result\.parameter\.exact\_match | boolean | 
action\_result\.parameter\.limit\_search | boolean | 
action\_result\.parameter\.values | string |  `\*` 
action\_result\.data\.\*\.container | numeric | 
action\_result\.data\.\*\.container\_name | string | 
action\_result\.data\.\*\.found in | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.matched | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.artifacts\_found | numeric | 
action\_result\.summary\.server | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add listitem'
Add value to a custom list

Type: **generic**  
Read only: **False**

To add a row containing a single value to a list simply pass the value\. However, to pass multiple values in a row, format it like a JSON array \(e\.g\. \["item1", "item2", "item3"\]\)\.<br><br>The action will update the <b>list</b>, if the <b>list</b> already exists \(even if the <b>create</b> parameter is set to true\)\.<br><br>After creating or updating a list through this action, if the same list is updated from the UI, then the user needs to save those changes before updating the list through this action again, otherwise, the changes made from the UI will be overridden\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** |  required  | Name or ID of a custom list | string | 
**new\_row** |  required  | New Row \(string or JSON list\) | string |  `\*` 
**create** |  optional  | Create list if it does not exist \(default\: false\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.create | boolean | 
action\_result\.parameter\.list | string | 
action\_result\.parameter\.new\_row | string |  `\*` 
action\_result\.data\.\*\.failed | boolean | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.server | string |  `url` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'find listitem'
Find value in a custom list

Type: **investigate**  
Read only: **True**

Row and column coordinates for each matching value can be found in the result summary under "locations"\. The match is case sensitive\.<br><br>If the <b>exact\_match</b> parameter is set to false, then the action will return all those strings for which the <b>values</b> parameter is its substring\. Otherwise it will return those strings which match exactly with the <b>values</b> parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list** |  required  | Name or ID of a custom list | string | 
**column\_index** |  optional  | Search in column number \(0 based\) | numeric | 
**values** |  required  | Value to search for | string |  `\*` 
**exact\_match** |  optional  | Exact match \(default\: true\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.column\_index | numeric | 
action\_result\.parameter\.exact\_match | boolean | 
action\_result\.parameter\.list | string | 
action\_result\.parameter\.values | string |  `\*` 
action\_result\.data | string | 
action\_result\.data\.\* | string | 
action\_result\.summary\.found\_matches | numeric | 
action\_result\.summary\.list\_id | numeric | 
action\_result\.summary\.locations | numeric | 
action\_result\.summary\.locations\.\* | numeric | 
action\_result\.summary\.server | string |  `url` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add artifact'
Add a new artifact to a container

Type: **generic**  
Read only: **False**

If the <b>container\_id</b> parameter is left empty, then it will be initialized to the current container's id \(from which the action is being run\) and the status will be reflected accordingly\.<br><br>CEF fields can be added to the artifact in two ways, either by using the <b>cef\_name</b> and <b>cef\_value</b> parameter or by using the <b>cef\_dictionary</b> parameter\. If the <b>cef\_name</b>, <b>cef\_value</b>, and <b>cef\_dictionary</b> parameters are all included, the action will add the <b>cef\_name</b> field to the <b>cef\_dictionary</b>\.<br><br>Using only the <b>cef\_name</b> and <b>cef\_value</b> parameter will result in the artifact having one CEF field\.<br><br>The <b>cef\_dictionary</b> parameter takes a JSON dictionary with key\-value pairs representing CEF key\-value pairs\. To provide values containing double\-quotes\("\), add a backslash\(\\\) before the double\-quotes\.<br>For e\.g\., \{"X\-Universally\-Unique\-Identifier"\:"test","Content\-Type"\:"multipart/alternative; boundary=<b>\\"</b>Apple\-Mail=\_0DA95D7E\-B791\-4751\-8043\-175949088A2C<b>\\"</b>>","Message\-Id"\:"<abc\@xyz\.com>"\}<br><br>The <b>contains</b> parameter can take a JSON dictionary, with the keys matching the keys of the <b>cef\_dictionary</b> and the values being lists of possible contains for the CEF field\. If a given value in the <b>cef\_dictionary</b> is not present in the <b>contains</b> dictionary, the action will first check the list of default CEF fields\. If not a default CEF field, then the action will attempt to identify the appropriate value for contains\.<br>The <b>contains</b> parameter can also take a string\(or a comma\-separated list of strings\) representing the contains for the <b>cef\_value</b> parameter\. This method should be used only if the <b>cef\_name</b> and <b>cef\_value</b> parameters are used\.<br><br>If the <b>run\_automation</b> parameter is set to true then the active playbooks will run automatically after the artifact is added\. The active playbooks will run on the same container in which the artifact is added\.<br><br>See the <a href="https\://docs\.splunk\.com/Documentation/Phantom/4\.8/PlatformAPI/RESTArtifacts" target="\_blank">REST API Documentation</a> for more information on artifacts, CEF fields, and contains\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | Name of the new artifact | string | 
**container\_id** |  optional  | Numeric container ID for the new artifact | numeric |  `phantom container id` 
**label** |  optional  | Artifact label \(default\: event\) | string | 
**source\_data\_identifier** |  required  | Source Data Idenitifier | string | 
**cef\_name** |  optional  | CEF Name | string | 
**cef\_value** |  optional  | Value | string |  `\*` 
**cef\_dictionary** |  optional  | CEF JSON | string | 
**contains** |  optional  | Data type for each CEF field | string | 
**run\_automation** |  optional  | Run automation on newly created artifact\(s\) \(default\: false\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cef\_dictionary | string | 
action\_result\.parameter\.cef\_name | string | 
action\_result\.parameter\.cef\_value | string |  `\*` 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.contains | string | 
action\_result\.parameter\.label | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.run\_automation | string | 
action\_result\.parameter\.source\_data\_identifier | string | 
action\_result\.data\.\*\.existing\_artifact\_id | numeric | 
action\_result\.data\.\*\.failed | boolean | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.artifact\_id | numeric | 
action\_result\.summary\.container\_id | numeric | 
action\_result\.summary\.server | string |  `url` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'deflate item'
Deflates an item from the vault

Type: **generic**  
Read only: **False**

The action will be supported only if the <b>phantom\_server</b> parameter \(in the asset configurations\) is configured to the local Phantom instance, i\.e\., the instance from which the action is being run\.<br><br>The action detects if the input vault item is a compressed file and deflates it\. Every file found after deflation is then added to the vault\. If <b>container\_id</b> is specified will add to its vault, else to the current \(the container whose context the action is executed\) container\. The action supports <b>zip</b>, <b>gzip</b>, <b>bz2</b>, <b>tar</b>, and <b>tgz</b> file types\. In the case where the compressed file contains another compressed file in it, set the <b>recursive</b> parameter to true to deflate the inner compressed file\.<br><br>If recursion is enabled and a password is specified, the application will use the password for given zip file only\. The inner zip file will be extracted only if the file is not password protected\. Among the different compression methods, only the zip supports password protection functionality\.<br><br>For certain Unicode characters, the file name is not unzipped as it is, by the zipfile module\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID | string |  `sha1`  `vault id` 
**container\_id** |  optional  | Destination container id | numeric |  `phantom container id` 
**password** |  optional  | Password for the file | string | 
**recursive** |  optional  | Extract recursively  \(default\: false\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.password | string | 
action\_result\.parameter\.recursive | boolean | 
action\_result\.parameter\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.data\.\*\.aka\.\* | string | 
action\_result\.data\.\*\.container | string | 
action\_result\.data\.\*\.container\_id | numeric |  `phantom container id` 
action\_result\.data\.\*\.contains\.\* | string | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.created\_via | string | 
action\_result\.data\.\*\.hash | string |  `sha1` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.metadata\.contains | string | 
action\_result\.data\.\*\.metadata\.md5 | string |  `md5` 
action\_result\.data\.\*\.metadata\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.metadata\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.metadata\.size | numeric | 
action\_result\.data\.\*\.mime\_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.path | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.task | string | 
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.vault\_document | numeric | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.summary\.total\_vault\_items | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'export container'
Export local container to the configured Phantom asset

Type: **generic**  
Read only: **False**

This action exports a container \(that matches the <b>container\_id</b>\) from the local Phantom instance \(the instance from where the action is being run\) to the configured Phantom asset \(that the action is being executed on\)\.<br><br>The action will fail with an error message like <b>severity instance with name u'critical' does not exist</b>, if the container metadata on the local phantom instance and the configured Phantom asset does not match\.<br><br>Set the <b>keep\_owner</b> parameter to true if you want the owner of the container on the configured Phantom instance to match the owner on the local instance\. Note that this will be based on Owner ID, not Owner Name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  required  | Container ID to copy | numeric |  `phantom container id` 
**keep\_owner** |  optional  | Keep Owner | boolean | 
**label** |  optional  | Label to name the export container\. If blank, the export container will have the same name as the local container | string | 
**run\_automation** |  optional  | Run active playbooks | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.keep\_owner | boolean | 
action\_result\.parameter\.label | string | 
action\_result\.parameter\.run\_automation | boolean | 
action\_result\.data | string | 
action\_result\.summary\.artifact\_count | numeric | 
action\_result\.summary\.container\_id | numeric |  `phantom container id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import container'
Import a container from an external Phantom instance

Type: **generic**  
Read only: **False**

This action imports a container \(that matches the <b>container\_id</b>\) from the configured Phantom asset \(that the action is being executed on\) into the local Phantom instance \(the instance from where the action is being run\)\.<br><br>The action will fail with an error message like <b>severity instance with name u'critical' does not exist</b>, if the container metadata on the configured Phantom asset and the local phantom instance does not match\.<br><br>Set the <b>keep\_owner</b> parameter to true if you want the owner of the container on the local Phantom instance to match the owner on the configured instance\. Note that this will be based on Owner ID, not Owner Name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  required  | Container ID to copy | numeric |  `phantom container id` 
**keep\_owner** |  optional  | Keep Owner | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | string |  `phantom container id` 
action\_result\.parameter\.keep\_owner | boolean | 
action\_result\.data | string | 
action\_result\.summary\.artifact\_count | numeric | 
action\_result\.summary\.container\_id | numeric |  `phantom container id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create container'
Create a new container on a Phantom instance

Type: **generic**  
Read only: **False**

This action creates a new container on the Phantom server, which is configured in the <b>phantom\_server</b> asset parameter\. The <b>container\_json</b> parameter needs to be a JSON string\. It is mandatory to provide a <b>label</b> key in the <b>container\_json</b> parameter\. The action will fail if the <b>container\_json</b> has a label that does not exist on the destination Phantom asset\.<br>E\.g\., \{"name"\:"Test Container","label"\:"events"\}<br><br>The <b>container\_artifacts</b> is an optional parameter that needs to be a list of artifact objects as a JSON string\. Each artifact JSON object should contain the following keys\: <b>cef, cef\_types, data, description, end\_time, ingest\_app\_id, kill\_chain, label, name, owner\_id, severity, source\_data\_identifier, start\_time, tags, type</b>\. All other keys will be ignored\.<br>E\.g\., \[\{"name"\: "artifact 1", "label"\:"label1", "cef"\: \{"test"\: "123"\}\},\{"name"\: "artifact 2", "label"\:"label2", "cef"\: \{"test"\: "456"\}\}\]<br><br>See <a href="https\://docs\.splunk\.com/Documentation/Phantom/4\.8/PlatformAPI/RESTArtifacts" target="\_blank"><b>Splunk Phantom Documentation</b></a> for further details\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_json** |  required  | The container JSON object | string | 
**container\_artifacts** |  optional  | List of artifact JSON objects | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_artifacts | string | 
action\_result\.parameter\.container\_json | string | 
action\_result\.data | string | 
action\_result\.summary\.artifact\_count | numeric | 
action\_result\.summary\.container\_id | numeric |  `phantom container id` 
action\_result\.summary\.failed\_artifact\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get action result'
Find the results of a previously run action

Type: **investigate**  
Read only: **True**

This action returns the most recent results of the given <b>action\_name</b> launched with the given <b>parameters</b> within the given <b>time\_limit</b>\.<br><br>The action will limit the number of results returned to the value in <b>max\_results</b>\. By default, the limit is 10\. To get all the results, set the<b>max\_results</b> parameter to 0\.<br><br>The <b>parameters</b> parameter takes a JSON string in the format\:<br><br><pre>\{<br>    &quot;parameter\_name1&quot;\: &quot;parameter\_value1&quot;<br>    &quot;parameter\_name2&quot;\: &quot;parameter\_value2&quot;<br>    \.\.\.<br>\}</pre><br>The <b>app</b> parameter takes an app name, and if it is included, the action will only search for action results from that app\. Similarly, the <b>asset</b> parameter takes an asset name, and if it is included, the action will only search for action results from that asset\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action\_name** |  required  | Action name | string | 
**parameters** |  optional  | JSON string of action parameters | string | 
**app** |  optional  | App name | string | 
**asset** |  optional  | Asset name | string | 
**time\_limit** |  optional  | Number of hours to search back | numeric | 
**max\_results** |  optional  | Maximum number of action results to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action\_name | string | 
action\_result\.parameter\.app | string | 
action\_result\.parameter\.asset | string | 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.parameter\.parameters | string | 
action\_result\.parameter\.time\_limit | numeric | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.action\_run | numeric | 
action\_result\.data\.\*\.app | numeric | 
action\_result\.data\.\*\.app\_name | string | 
action\_result\.data\.\*\.app\_version | string | 
action\_result\.data\.\*\.asset | numeric | 
action\_result\.data\.\*\.container | numeric | 
action\_result\.data\.\*\.effective\_user | string | 
action\_result\.data\.\*\.end\_time | string | 
action\_result\.data\.\*\.exception\_occured | boolean | 
action\_result\.data\.\*\.extra\_data | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.playbook\_run | numeric | 
action\_result\.data\.\*\.result\_data\.\*\.data | numeric | 
action\_result\.data\.\*\.result\_data\.\*\.message | string | 
action\_result\.data\.\*\.result\_data\.\*\.parameter | string | 
action\_result\.data\.\*\.result\_data\.\*\.parameter\.context\.artifact\_id | numeric | 
action\_result\.data\.\*\.result\_data\.\*\.parameter\.context\.guid | string | 
action\_result\.data\.\*\.result\_data\.\*\.parameter\.context\.parent\_action\_run | string | 
action\_result\.data\.\*\.result\_data\.\*\.status | string | 
action\_result\.data\.\*\.result\_data\.\*\.summary | string | 
action\_result\.data\.\*\.result\_summary\.total\_objects | numeric | 
action\_result\.data\.\*\.result\_summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.start\_time | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.version | numeric | 
action\_result\.summary\.action\_run\_id | numeric | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update list'
Update a list

Type: **generic**  
Read only: **False**

Either the <b>list\_name</b> or </b>id</b> is required\. If both, <b>list\_name</b> and <b>id</b> parameters are provided and both of them point to different lists, then the <b>list\_name</b> parameter will be preferred and the action will update the list specified in the list\_name parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list\_name** |  optional  | List name | string | 
**id** |  optional  | List id | numeric | 
**row\_number** |  required  | Row number in list to be modified | numeric | 
**row\_values\_as\_list** |  required  | JSON formatted list of new values for the row | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | numeric | 
action\_result\.parameter\.list\_name | string | 
action\_result\.parameter\.row\_number | numeric | 
action\_result\.parameter\.row\_values\_as\_list | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'no op'
Wait for the specified number of seconds

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sleep\_seconds** |  required  | Sleep for this many seconds | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.sleep\_seconds | numeric | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 