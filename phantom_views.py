# File: phantom_views.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import sys

from bs4 import UnicodeDammit


def find_artifacts(provides, all_results, context):

    headers = ['Container ID', 'Container', 'Artifact ID', 'Artifact Name', 'Found in field', 'Matched Value']

    context['results'] = results = []
    context['headers'] = headers

    for summary, action_results in all_results:
        for result in action_results:
            table = {}
            table['data'] = table_data = []
            base = result.get_summary().get('server')
            data = result.get_data()
            for item in data:
                row = []

                c_link = base + '/mission/{}'.format(item.get('container'))
                c_link_artifact = c_link + '/analyst/artifacts'
                row.append({ 'value': c_link, 'link': item.get('container') })
                row.append({ 'value': c_link, 'link': item.get('container_name') })
                row.append({ 'value': c_link_artifact, 'link': item.get('id') })
                row.append({ 'value': c_link_artifact, 'link': item.get('name') })
                row.append({ 'value': item.get('found in') })
                row.append({ 'value': item.get('matched') })
                table_data.append(row)
            results.append(table)

    return 'phantom_multiple_actions.html'


def add_artifact(provides, all_results, context):

    headers = ['Artifact ID', 'Container ID']

    context['results'] = results = []
    context['headers'] = headers

    for summary, action_results in all_results:
        for result in action_results:
            table = {}
            table['data'] = table_data = []
            summary = result.get_summary()
            base = summary.get('server')
            data = result.get_data()
            for item in data:
                row = []

                c_link = base + '/mission/{}'.format(summary.get('container_id'))
                c_link_artifact = c_link + '/analyst/artifacts'
                row.append({ 'value': c_link_artifact, 'link': summary.get('artifact_id') })
                row.append({ 'value': c_link, 'link': summary.get('container_id') })
                table_data.append(row)
            results.append(table)

    return 'phantom_multiple_actions.html'


def find_listitem(provides, all_results, context):

    # Fetching the Python major version
    python_version = 2
    try:
        python_version = int(sys.version_info[0])
    except:
        python_version = 2

    headers = ['List Name', 'Matched Row', 'Found at']

    context['results'] = results = []
    context['headers'] = headers

    for summary, action_results in all_results:
        for result in action_results:
            table = {}
            table['data'] = table_data = []
            summary = result.get_summary()
            param = result.get_param()
            data = result.get_data()
            locations = summary.get('locations')
            if not locations:
                locations = 'Not Found'
            for idx, item in enumerate(data):
                row = []
                item_str = ""
                for i in item:
                    if i:
                        i = UnicodeDammit(i).unicode_markup.encode('utf-8') if python_version == 2 else i
                    item_str = '{0}"{1}",'.format(item_str, i)
                item_str = item_str[:-1]

                row.append({ 'value': param.get('list') })
                row.append({ 'value': item_str })
                len_of_list = len(locations) > idx and locations[idx] or 'Missing Data'
                if type(len_of_list) == str:
                    row.append({ 'value': len_of_list})
                else:
                    row.append({ 'value': 'Row {}, Column {}'.format(len_of_list[0], len_of_list[1])})
                table_data.append(row)
            results.append(table)

    return 'phantom_multiple_actions.html'
