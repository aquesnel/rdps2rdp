
from parser_v2 import RdpContext, ChannelDef

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            line = line.split('#')[0]
            result += ''.join(line.lstrip(' ').split(' '))
    return bytes.fromhex(result)

def extract_as_context(values):
    return RdpContext(**values)