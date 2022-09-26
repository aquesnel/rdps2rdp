


import unittest

import test_utils

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

import parser_v2
import parser_v2_context

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

    @unittest.skip("skip old explore code")
    def test_parse_length_ex_1(self):
        data = extract_as_bytes("00 83 63 8b")

        rdp_context = parser_v2_context.RdpContext()
        rdp_context.pre_capability_exchange = False
        length = parser_v2.parse_pdu_length(data, rdp_context)
        
        # self.assertEqual(length, len(data))
        
    # @unittest.skip("skip after changing rdp80 cmpression input struct")
    @unittest.skip("skip for debugging")
    def test_parse_from_snapshot_1(self):
        # A PDU from a real connection
        # copied from the output of:
        # ```
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.xrdp.rail.fail-2.pcap -if pcap -of snapshot -o 78 -l 1 > output.xrdp.rail.fail-2.pdu-78.json
        # ```
        snapshot = test_utils.load_snapshot('output.xrdp.rail.fail-2.pdu-78.json')
        
        # import compression_rdp80; compression_rdp80.DEBUG = True
        # import compression_mppc;  compression_mppc.DEBUG = True
        # import compression_utils; compression_utils.DEBUG = True
            

        # compressed_data = snapshot.pdu_bytes

        # c = compression.CompressionFactory.new_RDP_80()
        # d = compression.CompressionFactory.new_RDP_80()
        # d = snapshot.rdp_context.clone().get_compression_engine(compression_constants.CompressionTypes.RDP_80)
        # try:
        #     pdu = parser_v2.parse(snapshot.pdu_source, snapshot.pdu_bytes, snapshot.rdp_context)
        # except parser_v2.ParserException as e:
        #     err = e.__cause__
        #     pdu = e.pdu
        pdu = parser_v2.parse(snapshot.pdu_source, snapshot.pdu_bytes, snapshot.rdp_context)

        
    # @unittest.skip("skip for debugging")
    def test_parse_from_snapshot_2(self):
        # import compression_rdp80; compression_rdp80.DEBUG = True
        import compression_mppc;  compression_mppc.DEBUG = True
        # import compression_utils; compression_utils.DEBUG = True
        parser_config = parser_v2_context.ParserConfig(
            # strict_parsing = False,
            # compression_enabled = False,
            debug_pdu_paths = [
                # 'channel.payload',
            ])
        # snapshot = test_utils.load_snapshot('output.win10.full.rail.pdu-370.json')
        snapshot = test_utils.load_snapshot('output.win10.rail.full-2.pud-491.json')
        pdu = parser_v2.parse(snapshot.pdu_source, snapshot.pdu_bytes, snapshot.rdp_context, parser_config)

if __name__ == '__main__':
    unittest.main()
