
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

from test_utils import extract_as_bytes, extract_as_context


class TestParsing(unittest.TestCase):

    @unittest.skip("unittest not implemented yet")
    def test_parse_primary_drawing_order_unknown_1(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        # OUTPUTPCAP = 'output.win10.rail.no-all-compression.no-gfx.failed.pcap' ; SERVER_PORT = 19119 ; offset = 64 ; limit = 1 ;
        data = extract_as_bytes("""
            00 84 0c # FastPath (len=1036)
            00 06 04 # FastPath Update (len=1030, type=FASTPATH_UPDATETYPE_ORDERS)
            0c 01 # Orders (items=268)
            
            # Order 0
            36 00 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_START)
            
            # Order 1
            49 # DRAWING_ORDER (type=TS_STANDARD, controlFlags: {'TS_PRIMARY_TYPE_CHANGE (8)', 'TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 (64)'}
            0d # PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            39 # PRIMARY_DRAWING_ORDER (fieldFlags)
            02 00 40 00 40 00 cc # MEMBLT_ORDER fields present
            
            # Order 2
            51 # b'0101 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {TS_DELTA_COORDINATES, 'TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 (64)'}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            02 # PRIMARY_DRAWING_ORDER (fieldFlags)
            40 # MEMBLT_ORDER fields present
            
            # Order 3-21: same as order 2
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            
            # Order 22
            03 1d 00 # DRAWING_ORDER (type=SECONDARY, len=29+13=42)
            22 0d 05 # SECONDARY_DRAWING_ORDER (type=TS_CACHE_BITMAP_COMPRESSED_REV2)
            c7 c9 d2 03 f6 e0 dd 25 14 40 
            40 16 ff ff 10 84 00 00 00 00 
            00 00 00 00 f0 e8 04 84 00 00 
            00 00 00 00 00 00             # TS_CACHE_BITMAP_COMPRESSED_REV2 - compressed data
            
            # Order 23
            11 # b'0001 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {TS_DELTA_COORDINATES}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            0a 01 # PRIMARY_DRAWING_ORDER (fieldFlags)
            40 d4 ff 7f # MEMBLT_ORDER fields present
            
            # Order 24
            01 # b'0001 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {None}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            0e 01 # PRIMARY_DRAWING_ORDER (fieldFlags)
            00 00 40 00 40 00 00 00 # MEMBLT_ORDER fields present
            
            # Order 25-44: same as order 2
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            
            # Order 45
            03 1c 00 # DRAWING_ORDER (type=SECONDARY, len=28+13=41)
            22 05 05 # SECONDARY_DRAWING_ORDER (type=TS_CACHE_BITMAP_COMPRESSED_REV2)
            c7 c9 d2 03 f6 e0 dd 25 14 40 40 16 22 10 84 00 00 00 00 00 00 00 00 f0 e8 04 84 00 00 00 00 00 00 00 00 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 00 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 00 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 00 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 40 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 00 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 40 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 36 01 00 00 00
            """)
        
        rdp_context = extract_as_context({'auto_logon': True, 'password': 'P@ssw0rd!', 'channel_defs': [{'options': {2147483648}, 'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail', 'channel_id': 1006, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152}, 'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC'}, {'options': 0, 'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC'}, {'options': 0, 'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 3, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'ECHO', 'channel_id': 8, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Control::v08.01', 'channel_id': 9, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Data::v08.01', 'channel_id': 10, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Geometry::v08.01', 'channel_id': 11, 'type': 'DYNAMIC'}], 'previous_primary_drawing_orders': {}, 'encryption_level': 0, 'domain': '', 'pre_capability_exchange': False, 'encrypted_client_random': None, 'pdu_source': None, 'compression_virtual_chan_cs_encoder': None, 'user_name': 'runneradmin', 'rail_enabled': True, 'encryption_method': 0, 'alternate_shell': 'rdpinit.exe', 'compression_type': None, 'is_gcc_confrence': True, 'working_dir': ''} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 0)
        self.assertEqual(pdu.rdp_fp.header.flags, set())
        self.assertEqual(pdu.rdp_fp.length, 1030)
        self.assertEqual(pdu.rdp_fp.fipsInformation, None)
        self.assertEqual(pdu.rdp_fp.dataSignature, None)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateCode, "TODO: implement this test")
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
    def test_parse_alt_sec_drawing_order_frame_mark(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/b69a751e-34df-4326-b4e1-0e582ff7ea97
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        data = extract_as_bytes("""
            00 11 # FastPath (len=17)
            00 0c 00 # FastPath Update (len=12, type=FASTPATH_UPDATETYPE_ORDERS)
            02 00 # Orders (items=2)
            36 00 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_START)
            36 01 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_END)
            """)
        
        rdp_context = extract_as_context({'auto_logon': True, 'password': 'P@ssw0rd!', 'channel_defs': [{'options': {2147483648}, 'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail', 'channel_id': 1006, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152}, 'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC'}, {'options': 0, 'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC'}, {'options': 0, 'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 3, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'ECHO', 'channel_id': 8, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Control::v08.01', 'channel_id': 9, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Data::v08.01', 'channel_id': 10, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Geometry::v08.01', 'channel_id': 11, 'type': 'DYNAMIC'}], 'previous_primary_drawing_orders': {}, 'encryption_level': 0, 'domain': '', 'pre_capability_exchange': False, 'encrypted_client_random': None, 'pdu_source': None, 'compression_virtual_chan_cs_encoder': None, 'user_name': 'runneradmin', 'rail_enabled': True, 'encryption_method': 0, 'alternate_shell': 'rdpinit.exe', 'compression_type': None, 'is_gcc_confrence': True, 'working_dir': ''} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 0)
        self.assertEqual(pdu.rdp_fp.header.flags, set())
        self.assertEqual(pdu.rdp_fp.length, 17)
        self.assertEqual(pdu.rdp_fp.fipsInformation, None)
        self.assertEqual(pdu.rdp_fp.dataSignature, None)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateCode, Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].fragmentation, Rdp.FastPath.FASTPATH_FRAGMENT_SINGLE)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compression, 0)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compressionFlags, None)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].size, 12)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.numberOrders, 2)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].orderSpecificData.altSecondaryOrderData.action, 0)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].orderSpecificData.altSecondaryOrderData.action, 1)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
      

    
if __name__ == '__main__':
    unittest.main()

