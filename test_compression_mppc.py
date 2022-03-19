import unittest
import binascii

import mccp
import test_utils

import compression
import compression_mppc
import compression_utils

class TestCompressionMppc(unittest.TestCase):
    
    def test_compress_orig_same_packet_twice(self):
        # from: https://datatracker.ietf.org/doc/html/rfc2118#section-4

        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        c = mccp.MCCP()
        
        deflated_1 = c.compress(data)
        inflated_1 = c.decompress(deflated_1)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(deflated_1, test_utils.extract_as_bytes("""66 6f 72 20 77 68 6f 6d 20 74 68 65 20 62 65 6c
                                                                    6c 20 74 6f 6c 6c 73 2c f4 37 20 fa 23 d3 32 97
                                                                    49 a0 00"""))
        self.assertEqual(inflated_1, data)
        
        deflated_2 = c.compress(data)
        inflated_2 = c.decompress(deflated_2)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(deflated_2, test_utils.extract_as_bytes("""fc # F[0:4] = 0b1111 = copy-offset with base 0, CF[0:6] = 0b110011 = copy-offset of 0 + 51
                                                                    fd # FD[2:7] = 0b111101 = length-of-match with base 32
                                                                    30 # D3[3:8] = 0b10011 = length-of-match of 32 + 19
                                                                    """))
        self.assertEqual(inflated_2, data)
        
    
    def test_compress_rdp_40_same_packet_twice(self):
        # from: https://datatracker.ietf.org/doc/html/rfc2118#section-4

        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        c = compression.CompressionFactory.new_RDP_40()
        d = compression.CompressionFactory.new_RDP_40()
        
        deflated_1 = c.compress(data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(deflated_1.data, test_utils.extract_as_bytes("""66 6f 72 20 77 68 6f 6d 20 74 68 65 20 62 65 6c
                                                                    6c 20 74 6f 6c 6c 73 2c f4 37 20 fa 23 d3 32 97
                                                                    49 a0 00"""))
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        
        deflated_2 = c.compress(data)
        inflated_2 = d.decompress(deflated_2)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(deflated_2.data, test_utils.extract_as_bytes("""fc # F[0:4] = 0b1111 = copy-offset with base 0, CF[0:6] = 0b110011 = copy-offset of 0 + 51
                                                                    fd # FD[2:7] = 0b111101 = length-of-match with base 32
                                                                    30 # D3[3:8] = 0b10011 = length-of-match of 32 + 19
                                                                    """))
        self.assertEqual(inflated_2, data)
        
    def test_compress_rdp_50_same_packet_twice(self):
        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        c = compression.CompressionFactory.new_RDP_50()
        d = compression.CompressionFactory.new_RDP_50()
        
        # c._encoder = compression_utils.RecordingEncoder(c._encoder)
        
        deflated_1 = c.compress(data)
        # import pprint ; pprint.pprint(c._encoder.get_recording())
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(deflated_1.data, test_utils.extract_as_bytes("""
                                            66 6f 72 20 77 68 6f 6d 20 74 68 65 20 62 65 6c # for whom the bel
                                            6c 20 74 6f 6c 6c 73 2c                         # l tolls,
                                            # CopyTuple(offset=16, len=15)
                                            # copy-offset 16 with base 0 = 0b11111 && (16 - 0) = 0b010000
                                            # length-of-match 15 base 8 = 0b110 && (15 - 8) = 0b111
                                            # encoded value: 0b 1111 1010 0001 1011 1 = hex:FA1B + carryover 0b1
                                            FA 1B
                                            # bit shifted literal
                                            # carryover 0b1
                                            # literal = ' ' = 0x20 = 0b0010 0000
                                            # encoded = 0b1001 0000 0 = hex:90 + carryover 0b0
                                            90
                                            # CopyTuple(offset=40, len=4)
                                            # carryover 0b0
                                            # copy-offset 40 with base 0 = 0b11111 && (40 - 0) = 0b101000
                                            # length-of-match 4 base 4 = 0b10 && (4 - 4) = 0b00
                                            # encoded value: 0b 0111 1110 1000 1000 = hex:7E88 + carryover None
                                            7E88
                                            # CopyTuple(offset=19, len=3)
                                            # carryover None
                                            # copy-offset 19 with base 0 = 0b11111 && (19 - 0) = 0b010011
                                            # length-of-match 3 base 3 = 0b0 && (3 - 3) = None
                                            # encoded value: 0b 1111 1010 0110 = hex:FA + carryover 0b0110
                                            FA
                                            # bit shifted literal
                                            # carryover 0b0110
                                            # literal = 'e.' = '\x65\x2e' = 0b0110 0101 0010 1110 
                                            # literal = '\xa6' = 0b10 && 0b010 0110
                                            # literal = '\x80' = 0b10 && 0b000 0000
                                            # encoded = 0b0110 0110 0101 0010 1110 1001 0011 0100 0000 00 = hex:6652E934 + carryover 0b000000
                                            66 52 E9 34
                                            # carry over padded with 0's
                                            00
                                            """))
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        
        deflated_2 = c.compress(data)
        inflated_2 = d.decompress(deflated_2)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(deflated_2.data, test_utils.extract_as_bytes("""
                                            # CopyTuple(offset=51, len=51)
                                            # carryover None
                                            # copy-offset 51 with base 0 = 0b11111 && (51 - 0) = 0b110011
                                            # length-of-match 51 base 32 = 0b11110 && (51 - 32) = 0b10011
                                            # encoded value: 0b 1111 1110 0111 1110 1001 1 = hex:FE7E + carryover 0b1001 1
                                            FE 7E
                                            # carry over padded with 0's
                                            98
                                            """))
        self.assertEqual(inflated_2, data)

    def test_MPPC_json_serializable(self):
        # from: https://datatracker.ietf.org/doc/html/rfc2118#section-4

        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        c = compression.CompressionFactory.new_RDP_40()
        d = compression.CompressionFactory.new_RDP_40()
        
        deflated_1 = c.compress(data)
        c_serialized_round_trip = compression_utils.CompressionEngine.from_json(c.to_json())
        # print(c)
        # print(c.to_json())
        # print(c_serialized_round_trip)
        self.assertEqual(c, c_serialized_round_trip)
        
        inflated_1 = d.decompress(deflated_1)
        d_serialized_round_trip = compression_utils.CompressionEngine.from_json(d.to_json())
        # print(d)
        # print(d.to_json())
        # print(d_serialized_round_trip)
        self.assertEqual(d, d_serialized_round_trip)
        

if __name__ == '__main__':
    unittest.main()
