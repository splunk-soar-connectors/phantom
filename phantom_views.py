# --
# File: phantom_views.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

from django.http import HttpResponse
import json


def find_artifacts(provides, all_results, context):

    headers = ['Container ID', 'Container', 'Artifact ID', 'Artifact Name', 'Found in field', 'Matched Value']

    context['ajax'] = True
    context['allow_links'] = [0, 1]
    if 'start' not in context['QS']:
        context['headers'] = headers
        return '/widgets/generic_table.html'

    start = int(context['QS']['start'][0])
    length = int(context['QS'].get('length', ['5'])[0])
    end = start + length
    cur_pos = 0
    rows = []
    total = 0
    for summary, action_results in all_results:
        for result in action_results:
            base = result.get_summary().get('server')
            data = result.get_data()
            total += len(data)
            for item in data:
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                c_link = base + '/mission/{}'.format(item.get('container'))
                row.append({ 'value': c_link, 'link': item.get('container') })
                row.append({ 'value': c_link, 'link': item.get('container_name') })
                row.append({ 'value': item.get('id'), 'link': item.get('id') })
                row.append({ 'value': item.get('name'), 'link': item.get('name') })
                row.append({ 'value': item.get('found in') })
                row.append({ 'value': item.get('matched') })
                rows.append(row)

    content = {
      "data": rows,
      "recordsTotal": total,
      "recordsFiltered": total,
    }
    return HttpResponse(json.dumps(content), content_type='text/javascript')


def add_artifact(provides, all_results, context):

    headers = ['Artifact ID', 'Container ID']

    context['ajax'] = True
    context['allow_links'] = [1]
    if 'start' not in context['QS']:
        context['headers'] = headers
        return '/widgets/generic_table.html'

    start = int(context['QS']['start'][0])
    length = int(context['QS'].get('length', ['5'])[0])
    end = start + length
    cur_pos = 0
    rows = []
    total = 0
    for summary, action_results in all_results:
        for result in action_results:
            summary = result.get_summary()
            base = summary.get('server')
            data = result.get_data()
            total += len(data)
            for item in data:
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                c_link = base + '/mission/{}'.format(summary.get('container id'))
                row.append({ 'value': summary.get('artifact id'), 'link': summary.get('artifact id') })
                row.append({ 'value': c_link, 'link': summary.get('container id') })
                rows.append(row)

    content = {
      "data": rows,
      "recordsTotal": total,
      "recordsFiltered": total,
    }
    return HttpResponse(json.dumps(content), content_type='text/javascript')


def find_listitem(provides, all_results, context):

    headers = ['List Name', 'Matched Row', 'Found at']

    context['ajax'] = True
    context['allow_links'] = [0, 1]
    if 'start' not in context['QS']:
        context['headers'] = headers
        return '/widgets/generic_table.html'

    start = int(context['QS']['start'][0])
    length = int(context['QS'].get('length', ['5'])[0])
    end = start + length
    cur_pos = 0
    rows = []
    total = 0
    for summary, action_results in all_results:
        for result in action_results:
            summary = result.get_summary()
            param = result.get_param()
            data = result.get_data()
            total += len(data)
            locations = summary.get('locations')
            if not locations:
                locations = 'Not Found'
            for idx, item in enumerate(data):
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                row.append({ 'value': param.get('list') })
                row.append({ 'value': json.dumps(item) })
                l = len(locations) > idx and locations[idx] or 'Missing Data'
                if type(l) == str:
                    row.append({ 'value': l})
                else:
                    row.append({ 'value': 'Row {}, Column {}'.format(l[0], l[1])})
                rows.append(row)

    content = {
      "data": rows,
      "recordsTotal": total,
      "recordsFiltered": total,
    }
    return HttpResponse(json.dumps(content), content_type='text/javascript')
