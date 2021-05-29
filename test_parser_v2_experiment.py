


import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse_pdu_length, RdpContext

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            line = line.split('#')[0]
            result += ''.join(line.lstrip(' ').split(' '))
    return bytes.fromhex(result)

def as_hex_str(b):
    return " ".join("{:02x}".format(x) for x in b)

class TestParsing(unittest.TestCase):

    def test_parse_length_ex_1(self):
        data = extract_as_bytes("00 83 63 8b")

        rdp_context = RdpContext()
        rdp_context.pre_capability_exchange = True
        length = parse_pdu_length(data, rdp_context)
        
        self.assertEqual(length, len(data))
        
        
if __name__ == '__main__':
    unittest.main()
