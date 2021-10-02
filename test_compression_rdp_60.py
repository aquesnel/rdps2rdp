import unittest

    
class TestParsing(unittest.TestCase):
    
    def test_compress_same_packet_twice(self):
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
        # print("deflated 2:     ",binascii.hexlify(deflated_2))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(deflated_2, test_utils.extract_as_bytes("""fc # F[0:4] = 0b1111 = copy-offset with base 0, CF[0:6] = 0b110011 = copy-offset of 0 + 51
                                                                    fd # FD[2:7] = 0b111101 = length-of-match with base 32
                                                                    30 # D3[3:8] = 0b10011 = length-of-match of 32 + 19
                                                                    """))
        self.assertEqual(inflated_2, data)
    

if __name__ == '__main__':
    unittest.main()
