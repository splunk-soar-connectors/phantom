# File: phantom_testme.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.




from phantom_connector import PhantomConnector
from phantom_connector import determine_contains

ph = PhantomConnector()

ph.config = {
    'phantom_server': '192.168.7.225',
    'auth_token': 'VT4ZZOZa4yhPkCrcWKkB2yWb+YVOeGWY8NQN4SEux4s=',
    'verify_certificate': False
}

ph.initialize()

ph.container_id = 190

# ph.action_identifier = 'update_task'

# ph.handle_action(
#     {
#         'phase_name': 'DetECtion',
#         'task_name': 'Analyze precursors and indicators',
#         'note': '<p>Hello</p>',
#         'note_title': 'This is a note title'
#     }
# )

# ph.action_identifier = 'set_current_phase'

# ph.handle_action(
#     {
#         'phase_name': 'Eradicate'
#     }
# )

# ph.action_identifier = 'get_indicator'

# ph.handle_action(
#     {
#         'ioc_value': 'http://familiapaixao.coconet-us.com/tmMTo.exe' ,
#         'include_artifact_data': True
#     }
# )

# ph.action_identifier = 'get_indicator'

# ph.handle_action(
#     {
#         'ioc_id': 641
#     }
# )

ph.action_identifier = 'modify_indicator_tag'

ph.handle_action(
    {
        'ioc_list': '[{"ioc_value": "http://familiapaixao.coconet-us.com/tmMTo.exe", "tags_to_add": ["risk_score-10"], "tags_to_remove": ["malicious"]}, {"ioc_id": 640, "tags_to_add": ["risk_score-0"], "tags_to_remove": ["risk_score-5"]}]'
    }
)