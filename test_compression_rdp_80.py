import unittest
import binascii
import json

import compression
import compression_constants
import data_model_v2_rdp
import parser_v2
import parser_v2_context
import utils
import test_utils
from compression_utils import (
    CompressionArgs,
)
import os

SELF_DIR = os.path.dirname(__file__)

class TestCompressionRdp80(unittest.TestCase):
    
    def test_one_char_at_a_time(self):
        pass

    @unittest.skip("skip after changing rdp80 cmpression input struct")
    # @unittest.skip("skip for debugging")
    def test_from_snapshot(self):
        # A PDU from a real connection
        # copied from the output of:
        # ```
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of snapshot -o 67 -l 1 > test_data/output.win10.rail.no-compression.success.pdu-67.json
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of snapshot -o 215 -l 1 > test_data/output.win10.rail.no-compression.success.pdu-215.json
        # ```
        with open(SELF_DIR + '/test_data/output.win10.rail.no-compression.success.pdu-215.json', 'r') as f:
            snapshot = parser_v2_context.RdpStreamSnapshot.from_json(json.load(f))
        
        compressed_data = snapshot.pdu_bytes

        # c = compression.CompressionFactory.new_RDP_80()
        # d = compression.CompressionFactory.new_RDP_80()
        d = snapshot.rdp_context.clone().get_compression_engine(compression_constants.CompressionTypes.RDP_80)
        try:
            pdu = parser_v2.parse(snapshot.pdu_source, snapshot.pdu_bytes, snapshot.rdp_context)#, allow_partial_parsing = ALLOW_PARTIAL_PARSING)
        except parser_v2.ParserException as e:
            err = e.__cause__
            pdu = e.pdu
        bulkData = pdu.tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.payload.bulkData
        if bulkData is not None:
            bulk_datas = [bulkData]
        else:
            bulk_datas = [segment.bulkData for segment in pdu.tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.payload.segmentArray]
        for bulkData in bulk_datas:
            flags = data_model_v2_rdp.Rdp.GraphicsPipelineExtention.Compression.to_compression_flags(bulkData.header_CompressionFlags)
            compressed_data = getattr(bulkData, '__HIDDEN__compression_bytes_for_(field=data)')
            
            import compression_rdp80; compression_rdp80.DEBUG = True
            # import compression_mppc;  compression_mppc.DEBUG = True
            # import compression_utils; compression_utils.DEBUG = True
            print("flags:          ",flags)
            print("history:        ",binascii.hexlify(d._decompression_history_manager._history[:d._decompression_history_manager._historyOffset]))
            print("compressed_data:",binascii.hexlify(compressed_data))
            inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = flags, type = compression_constants.CompressionTypes.RDP_80))
            print("flags:          ",flags)
            print("compressed_data:",binascii.hexlify(compressed_data))
            print("inflated 1:     ",binascii.hexlify(inflated_1))
            # self.assertEqual(inflated_1, data)
            # self.assertEqual(inflated_1.hex(), data.hex())
            
            # deflated_1 = c.compress(data)
            # self.assertEqual(deflated_1.data.hex(), compressed_data.hex())
            # inflated_1 = d.decompress(deflated_1)
            # self.assertEqual(inflated_1, data)
            # # print("data 1    :     ",binascii.hexlify(data))
            # # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
            # print("inflated 1:     ",binascii.hexlify(inflated_1))
            
            # deflated_2 = c.compress(data)
            # # print("data 2    :     ",binascii.hexlify(data))
            # # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
            # # print("inflated 2:     ",binascii.hexlify(inflated_2))

            # inflated_2 = d.decompress(deflated_2)
            # self.assertEqual(inflated_2, data)

    def test_decompress_single_part_from_gfx_capture_1(self):
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        # OUTPUTPCAP = 'output.win10.rail.no-compression.success.pcap' ; SERVER_PORT = 33930
        # offset = 63
        compressed_data = test_utils.extract_as_bytes("""
            # 03 00 00 28 # TPKT(len=40)
            # 02 f0 80 # X224(len=2, type=data)
            # 68 00 01 03 f2 f0 1a # Mcs(len=26, type=TPDU_DATA)
            # 12 00 00 00 03 00 00 00 # CHANNEL_PDU_HEADER(len=18, flags=FIRST|LAST)
            # 38 07 # DYNVC_DATA_FIRST(type=COMMAND_DATA, channel=7)
            e0 # RDP_SEGMENTED_DATA(type=SINGLE)
            24 # RDP8_BULK_ENCODING(flags=COMPRESSED | COMPRESSION_RDP80)
            09 e3 18 0a 44 8c 70 e9 8d d1 44 63 18 00 # compressed bytes
            # RDPGFX_CMDID_CAPSCONFIRM
            # 13 00 00 00 # version
            # 14 00 00 00 # capsDataLength
            # 00 06 0a 00 04 00 00 00 00 00 00 00 # capsData
            """)
        data = test_utils.extract_as_bytes("""
            # RDPGFX_CMDID_CAPSCONFIRM
            13 00 00 00 # version
            14 00 00 00 # capsDataLength
            00 06 0a 00 04 00 00 00 00 00 00 00 # capsData
            """)

        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        # flags = {compression_constants.CompressionFlags.COMPRESSED}
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_80))
        self.assertEqual(inflated_1.hex(), data.hex())
        self.assertEqual(inflated_1, data)

    def test_decompress_single_part(self):
        # copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecZGfx.c /* Sample from [MS-RDPEGFX] */
        data = b"The quick brown fox jumps over the lazy dog"
        # TEST_FOX_DATA_SINGLE
        compressed_data = b"\xE0\x04\x54\x68\x65\x20\x71\x75\x69\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20\x66\x6F\x78\x20\x6A\x75\x6D\x70\x73\x20\x6F\x76\x65\x72\x20\x74\x68\x65\x20\x6C\x61\x7A\x79\x20\x64\x6F\x67"

        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        # flags = {compression_constants.CompressionFlags.COMPRESSED}
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_80))
        self.assertEqual(inflated_1.hex(), data.hex())
        self.assertEqual(inflated_1, data)

    def test_decompress_multipart(self):
        # copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecZGfx.c /* Sample from [MS-RDPEGFX] */
        data = b"The quick brown fox jumps over the lazy dog"
        # TEST_FOX_DATA_MULTIPART
        compressed_data = b"\xE1\x03\x00\x2B\x00\x00\x00\x11\x00\x00\x00\x04\x54\x68\x65\x20\x71\x75\x69\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20\x0E\x00\x00\x00\x04\x66\x6F\x78\x20\x6A\x75\x6D\x70\x73\x20\x6F\x76\x65\x10\x00\x00\x00\x24\x39\x08\x0E\x91\xF8\xD8\x61\x3D\x1E\x44\x06\x43\x79\x9C\x02"
        
        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        # flags = {compression_constants.CompressionFlags.COMPRESSED}
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_80))
        self.assertEqual(inflated_1.hex(), data.hex())
        self.assertEqual(inflated_1, data)

    @unittest.skip("skip after changing rdp80 cmpression input struct")
    # @unittest.skip("multipart is not yet supported")
    def test_decompress_multipart_old(self):
        # copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecZGfx.c /* Sample from [MS-RDPEGFX] */
        data = b"The quick brown fox jumps over the lazy dog"
        # TEST_FOX_DATA_MULTIPART
        header = [
            test_utils.extract_as_bytes("""
            # MULTIPART
            E1
            # segment count = 3
            0300
            # uncompressed size = 43
            2B000000
            # segment #1
            # size = 17
            11000000
            # header = uncompressed
            04
            """),
            test_utils.extract_as_bytes("""
            # segment #2
            # size = 14
            0e000000
            # header = uncompressed
            04
            """),
            test_utils.extract_as_bytes("""
            # segment #3
            # size = 16
            10000000
            # header = compressed
            24
            """),
        ]
        header_flags = [
            set(),
            set(),
            {compression_constants.CompressionFlags.COMPRESSED}
        ]
        compressed_data = b"\xE1\x03\x00\x2B\x00\x00\x00\x11\x00\x00\x00\x04\x54\x68\x65\x20\x71\x75\x69\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20\x0E\x00\x00\x00\x04\x66\x6F\x78\x20\x6A\x75\x6D\x70\x73\x20\x6F\x76\x65\x10\x00\x00\x00\x24\x39\x08\x0E\x91\xF8\xD8\x61\x3D\x1E\x44\x06\x43\x79\x9C\x02"
        compressed_datas = [                                              b"\x54\x68\x65\x20\x71\x75\x69\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20",
                                                                                                                                                              b"\x66\x6F\x78\x20\x6A\x75\x6D\x70\x73\x20\x6F\x76\x65",
                                                                                                                                                                                                                                      b"\x39\x08\x0E\x91\xF8\xD8\x61\x3D\x1E\x44\x06\x43\x79\x9C\x02",
                            ]
        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        inflated_1 = b''
        for header_flag, compressed_data in zip(header_flags, compressed_datas):
            inflated_1 += d.decompress(CompressionArgs(data = compressed_data, flags = header_flag, type = compression_constants.CompressionTypes.RDP_80))
        self.assertEqual(inflated_1.hex(), data.hex())
        self.assertEqual(inflated_1, data)


    @unittest.skip("skip after changing rdp80 cmpression input struct")
    def test_compress_same_packet_twice(self):
        # A RDPGFX_CMDID_CAPSCONFIRM PDU from a real connection
        # copied from the output of:
        # ```
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of text -vvv -o 63 -l 1 --path "tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.bulkData.data.as_wire_bytes"
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of text -vvv -o 63 -l 1 --path "tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.bulkData.__HIDDEN__compression_bytes_for_(field=data)"
        # ```
        history_buffer = b''
        compressed_data = b'\t\xe3\x18\nD\x8cp\xe9\x8d\xd1Dc\x18\x00'
        data = b'\x13\x00\x00\x00\x14\x00\x00\x00\x00\x06\x0a\x00\x04\x00\x00\x00\x00\x00\x00\x00'
        
        compressed_data_with_explanation = test_utils.extract_as_bytes("""
            # token for byte 0: literal 0x13
            # Remainder + encoded bits -> output bits + Remainder:  null + 0 0001 0011 -> 0000 1001 + 1
            09
            # token for byte 1: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  1 + 11000 -> null + 1110 00
        
            # token for byte 2: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  1110 00 + 11000 -> 1110 0011 + 000
            e3
            # token for byte 3: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  000 + 11000 -> 0001 1000 + null
            18
            # token for byte 4: literal 0x14
            # Remainder + encoded bits -> output bits + Remainder:  null + 0 0001 0100 -> 0000 1010 + 0
            0a
            # token for byte 5-7: copy offset 4 length 3+null
            # Remainder + encoded bits -> output bits + Remainder:  0 + 10001 00100 0 -> 0100 0100 + 1000
            44
            # token for byte 8: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  1000 + 11000 -> 1000 1100 + 0
            8c
            # token for byte 9: literal 0x06
            # Remainder + encoded bits -> output bits + Remainder:  0 + 1110000 -> 0111 0000 + null
            70
            # token for byte 10: literal 0x0a
            # Remainder + encoded bits -> output bits + Remainder:  null + 1110100 -> null + 1110 100
            
            # token for byte 11: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  1110 100 + 11000 -> 1110 1001 + 1000
            e9
            # token for byte 12: literal 0x04
            # Remainder + encoded bits -> output bits + Remainder:  1000 + 1101110 -> 1000 1101 + 110
            8d
            # token for byte 13-16: copy offset 8 length 4+0
            # Remainder + encoded bits -> output bits + Remainder:  110 + 10001 01000 10 00 -> 1101 0001 0100 0100 + 0
            d1 44
            # token for byte 17: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  0 + 11000 -> null + 011000
            
            # token for byte 18: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  011000 + 11000 -> 0110 0011 + 000
            63
            # token for byte 19: literal 0x00
            # Remainder + encoded bits -> output bits + Remainder:  000 + 11000 -> 0001 1000 + null
            18
            # remainer padded: null + null -> null
            
            # padding bit count
            00
            """)
        self.assertEqual(compressed_data_with_explanation.hex(), compressed_data.hex())
        
        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        deflated_1 = c.compress(data)
        self.assertEqual(len(deflated_1.data), len(compressed_data)) # the compression from the win10 server chooses a different compressed encoding that has the same length as the compressed encoding from our compressor
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        
        deflated_2 = c.compress(data)
        self.assertEqual(deflated_2.data.hex(), test_utils.extract_as_bytes("""
            # token for byte 0-19: copy offset 20 length 16+4
            # Remainder + encoded bits -> output bits + Remainder:  null + 10001 10100 1110 0100 -> 1000 1101 0011 1001 + 00
            8d 39
            # remainer padded: 00 + null -> 0000 0000
            00
            # padding bit count
            06
            """).hex())
        inflated_2 = d.decompress(deflated_2)
        self.assertEqual(inflated_2, data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))

    @unittest.skip("skip after changing rdp80 cmpression input struct")
    def test_decompress_MSRDP_generated_PDU_with_history(self):
        # A RDPGFX_RESET_GRAPHICS PDU from a real connection
        # copied from the output of:
        # ```
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of text -vvv -o 67 -l 1 --path "tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.bulkData.data.as_wire_bytes"
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i output.win10.rail.no-compression.success.pcap -if pcap -of text -vvv -o 67 -l 1 --path "tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.bulkData.__HIDDEN__compression_bytes_for_(field=data)"
        # ```
        # Note: only the history_buffer and compressed_data are sources of truth because 
        # they are copied from the MS-RDP implementation's output, therefore to test for 
        # interoperability we need to test using the compressed_data value.
        history_buffer = b'\x13\x00\x00\x00\x14\x00\x00\x00\x00\x06\x0a\x00\x04\x00\x00\x00\x00\x00\x00\x00'
        compressed_data = b'\x07E\x02\xa6q\x82\xb6\xf8\xa5\xae1\x15\xa2\x94GEX\xd1\xb6\x91\xa6\xd8\xc4[\xfcE\xd6i\xf0B$Dq5\x84~E(\x92"\xc8\x00'
        data = b'\x0e\x00\x00\x00T\x01\x00\x00V\x05\x00\x00\x00\x03\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00U\x05\x00\x00\xff\x02\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00'
        
        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        compressed_history_buffer_args = c.compress(history_buffer)
        _ = d.decompress(compressed_history_buffer_args)
        
        # import compression_rdp80
        # compression_rdp80.DEBUG = True
        # import compression_mppc
        # compression_mppc.DEBUG = True
        # import compression_utils
        # compression_utils.DEBUG = True
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = {compression_constants.CompressionFlags.COMPRESSED}, type = compression_constants.CompressionTypes.RDP_80))
        # print("compressed_data:     ",binascii.hexlify(compressed_data))
        # print("data 1         :     ",binascii.hexlify(data))
        # print("inflated 1     :     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)

        # reset so that we can test compression of the data blob

        c = compression.CompressionFactory.new_RDP_80()
        d = compression.CompressionFactory.new_RDP_80()
        
        compressed_history_buffer_args = c.compress(history_buffer)
        _ = d.decompress(compressed_history_buffer_args)
        deflated_1 = c.compress(data)
        # the compression from the win10 server chooses a different compressed encoding from 
        # our compressor, so we don't check the compressed value directly, we only check that 
        # it decompresses correctly
        # self.assertEqual(deflated_1.data, compressed_data)
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))



if __name__ == '__main__':
    unittest.main()
