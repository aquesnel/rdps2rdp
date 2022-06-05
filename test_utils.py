import os
import json

from parser_v2 import RdpContext, ChannelDef
import parser_v2_context

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            line = line.split('#')[0]
            result += ''.join(line.lstrip(' ').split(' '))
    return bytes.fromhex(result)

def extract_as_context(values):
    return RdpContext(**values)

SELF_DIR = os.path.dirname(__file__)
def load_snapshot(file_name):
    with open(SELF_DIR + '/test_data/' + file_name, 'r') as f:
        snapshot = parser_v2_context.RdpStreamSnapshot.from_json(json.load(f))
    return snapshot
