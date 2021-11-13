import unittest
import binascii

import compression
from data_model_v2_rdp import Rdp
from compression_utils import (
    CompressionArgs,
)
import test_utils
    
class TestCompressionRdp60(unittest.TestCase):
    
    @unittest.skip("not needed anymore")
    def test_one_char_at_a_time(self):
        data = b'f'
        compressed_data = test_utils.extract_as_bytes("""
                                # read order: 0b 1101 1111 10 = byte order: 0b 1111 1011 xxxx xx01 = 0xfb + 01 = 'f'
                                fb
                                # carry over bits: 10
                                # read order:  0b 1111 1111 1110 1 = EoS
                                # joined read order: 0b 1011 1111 1111 101
                                # joined byte order: 0b 1111 1101 x101 1111 = 0xfd5f
                                fd5f
                                # 0b1110000111 = 'o'
                                #
                                """)

        c = compression.CompressionFactory.new_RDP_60()
        d = compression.CompressionFactory.new_RDP_60()
        
        inflated_1 = d.decompress(compressed_data)
        # print("data: %s" % data.hex())
        # print("infa: %s" % inflated_1.hex())
        self.assertEqual(inflated_1, data)
        # self.assertEqual(inflated_1.hex(), data.hex())
        
        deflated_1 = c.compress(data)
        self.assertEqual(deflated_1.data.hex(), compressed_data.hex())
        
    def test_compress_same_packet_twice(self):
        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        data = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!"
        compressed_data = b"""\xfb\x1d\x7e\xe4\xda\xc7\x1d\x70\xf8\xa1\x6b\x1f\x7d\xc0\xbe\x6b\xef\xb5\xef\x21\x87\xd0\xc5\xe1\x85\x71\xd4\x10\x16\xe7\xda\xfb\x1d\x7e\xe4\xda\x47\x1f\xb0\xef\xbe\xbd\xff\x2f"""
        
        c = compression.CompressionFactory.new_RDP_60()
        d = compression.CompressionFactory.new_RDP_60()
        
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = {Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED}))
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())
        
        
        deflated_1 = c.compress(data)
        # self.assertEqual(deflated_1.data.hex(), compressed_data.hex())
        # self.assertEqual(deflated_1.data, test_utils.extract_as_bytes("""66 6f 72 20 77 68 6f 6d 20 74 68 65 20 62 65 6c
        #                                                             6c 20 74 6f 6c 6c 73 2c f4 37 20 fa 23 d3 32 97
        #                                                             49 a0 00"""))
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        
        deflated_2 = c.compress(data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertLessEqual(len(deflated_2.data), 5)
        # self.assertEqual(deflated_2.data, test_utils.extract_as_bytes("""fc # F[0:4] = 0b1111 = copy-offset with base 0, CF[0:6] = 0b110011 = copy-offset of 0 + 51
        #                                                             fd # FD[2:7] = 0b111101 = length-of-match with base 32
        #                                                             30 # D3[3:8] = 0b10011 = length-of-match of 32 + 19
        #                                                             """))
        
        inflated_2 = d.decompress(deflated_2)
        self.assertEqual(inflated_2, data)
    

if __name__ == '__main__':
    unittest.main()
