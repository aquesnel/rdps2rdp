
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

from test_utils import extract_as_bytes, extract_as_context


class TestParsing(unittest.TestCase):

    def test_parse_capability_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        data = extract_as_bytes("""
            03 00 00 22 # TPKT(len=34)
            02 f0 80    # X224(len=2, type=data)
            68 00 01 03 f2 f0 14 # Mcs(len=20, type=SEND_DATA_FROM_SERVER)
            0c 00 00 00 03 00 00 00 # CHANNEL_PDU_HEADER(len=12, flags=First|Last)
            50 # Dyvc(Cmd=capability)
            00 # pad
            03 00 # Dyvc(version = 3)
            33 33 # Dyvc.PriorityCharge0 
            11 11 # Dyvc.PriorityCharge1
            3d 0a # Dyvc.PriorityCharge2 
            a7 04 # Dyvc.PriorityCharge3 
            """)
        
        rdp_context = extract_as_context({'channel_defs': [{'options': {8388608, 2147483648}, 'type': 'STATIC', 'name': 'rdpdr', 'channel_id': 1004}, {'options': {1073741824, 2147483648}, 'type': 'STATIC', 'name': 'rdpsnd', 'channel_id': 1005}, {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail', 'channel_id': 1006}, {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail_wi', 'channel_id': 1007}, {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail_ri', 'channel_id': 1008}, {'options': {8388608, 1073741824, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'cliprdr', 'channel_id': 1009}, {'options': {8388608, 1073741824, 2147483648}, 'type': 'STATIC', 'name': 'drdynvc', 'channel_id': 1010}, {'options': 0, 'type': 'STATIC', 'name': 'I/O Channel', 'channel_id': 1003}, {'options': 0, 'type': 'STATIC', 'name': 'McsMessageChannel', 'channel_id': 1011}], 'auto_logon': True, 'domain': '', 'password': 'P@ssw0rd!', 'pre_capability_exchange': False, 'user_name': 'runneradmin', 'encrypted_client_random': None, 'is_gcc_confrence': True, 'compression_type': 1536, 'rail_enabled': True, 'working_dir': '', 'encryption_method': 0, 'encryption_level': 0, 'pdu_source': None, 'alternate_shell': 'rdpinit.exe', 'channels': {1008: {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail_ri', 'channel_id': 1008}, 1009: {'options': {8388608, 1073741824, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'cliprdr', 'channel_id': 1009}, 1010: {'options': {8388608, 1073741824, 2147483648}, 'type': 'STATIC', 'name': 'drdynvc', 'channel_id': 1010}, 1011: {'options': 0, 'type': 'STATIC', 'name': 'McsMessageChannel', 'channel_id': 1011}, 1003: {'options': 0, 'type': 'STATIC', 'name': 'I/O Channel', 'channel_id': 1003}, 1004: {'options': {8388608, 2147483648}, 'type': 'STATIC', 'name': 'rdpdr', 'channel_id': 1004}, 1005: {'options': {1073741824, 2147483648}, 'type': 'STATIC', 'name': 'rdpsnd', 'channel_id': 1005}, 1006: {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail', 'channel_id': 1006}, 1007: {'options': {8388608, 1073741824, 1048576, 2097152, 2147483648}, 'type': 'STATIC', 'name': 'rail_wi', 'channel_id': 1007}}})
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 34)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)   

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1010)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0xf0)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0xf0)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.flags, {Rdp.Channel.CHANNEL_FLAG_FIRST, Rdp.Channel.CHANNEL_FLAG_LAST})
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_header.cbId, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_header.Pri, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_header.Cmd, Rdp.DynamicVirtualChannels.COMMAND_CAPABILITIES)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_capabilities.Version, 3)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_capabilities.PriorityCharge0, 0x3333)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_capabilities.PriorityCharge1, 0x1111)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_capabilities.PriorityCharge2, 0x0a3d)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc_capabilities.PriorityCharge3, 0x04a7)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
       
    
if __name__ == '__main__':
    unittest.main()