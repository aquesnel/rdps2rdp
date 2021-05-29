
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

    def test_parse_length_crdpssp_Negotiate(self):
        data = extract_as_bytes("30 2f a0 03 02 01 06 a1 28 30 26 30 24 a0 22 04 20 4e 54 4c 4d 53 53 50 00 01 00 00 00 37 82 08 e0 00 00 00 00 20 00 00 00 00 00 00 00 20 00 00 00")
        """
        TSRequest:
         version=6
         negoTokens=NegoData:
          NegoToken:
           negoToken=0x4e544c4d5353500001000000378208e000000000200000000000000020000000

        <class 'spnego._ntlm_raw.messages.Negotiate'>:
            MESSAGE_TYPE: MessageType.negotiate
            MINIMUM_LENGTH: 32
            _data: <memory at 0x7f1c5024bf28>
            _encoding: windows-1252
            _payload_offset: 32
            domain_name: None
            flags: 3758654007
            pack: <bound method Negotiate.pack of <spnego._ntlm_raw.messages.Negotiate object at 0x7f1c4fb91250>>
            signature: NTLMSSP
            unpack: <function unpack at 0x7f1c50766b18>
            version: None
            workstation: None
        """
        
        rdp_context = RdpContext()
        length = parse_pdu_length(data, rdp_context)
        
        self.assertEqual(length, len(data))
        
        
if __name__ == '__main__':
    unittest.main()
