[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
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
The app uses HTTP/ HTTPS protocol for communicating with the Phantom server. Below are the default ports used by Splunk SOAR.

SERVICE NAME | TRANSPORT PROTOCOL | PORT
------------ | ------------------ | ----
**http** | tcp | 80
**https** | tcp | 443

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
