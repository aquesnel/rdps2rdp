
from parser_v2 import RdpContext

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            line = line.split('#')[0]
            result += ''.join(line.lstrip(' ').split(' '))
    return bytes.fromhex(result)

def extract_as_context(values):
    rdp_context = RdpContext()
    for k,v in values.items():
        setattr(rdp_context, k, v)
    return rdp_context