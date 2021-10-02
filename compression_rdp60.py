
import array
import binascii
import struct
import sys
import collections
import bisect
import enum

import compression_utils
from compression_utils import (
    SymbolType,
)

DEBUG = False



EncodingConfig = collections.namedtuple('EncodingConfig', ['min_value', 'prefix', 'value_bit_length'])
HuffmanTreeNode = collections.namedtuple('HuffmanTreeNode', ['child_0', 'child_1'])

class HuffmanTreeNode(object):
    def __init__(self, huffman_index = None, child_0=None, child_1=None):
        self._children = [child_0, child_1]
        self._huffman_index = huffman_index
    
    def get_huffman_index(self):
        if not self.is_leaf():
            raise ValueError('Invalid node. A non-leaf node does not have a huffman_index')
        if self._huffman_index is None:
            raise ValueError('Invalid node. This leaf node does not have a huffman_index')
        return self._huffman_index

    def next_huffman_index_from(self, bits_iter):
        tree_node = self
        while not tree_node.is_leaf():
            tree_node = tree_node.get_child(bits_iter.next())
        return tree_node.get_huffman_index()

    def is_leaf(self):
        return (self._children[0] is None) and (self._children[1] is None)
        
    def get_child(self, digit):
        if digit != 0 and digit != 1:
            raise ValueError('Invalid binary digit "%s"' % digit)
        return self._children[digit]
            
    def add_child(self, huffman_index, digits, index = 0):
        if len(digits) <= index:
            if not self.is_leaf():
                raise ValueError('Invalid node. A Node must have children or have a value but not both')
            self._huffman_index = huffman_index
            return
        digit = digits[index]
        if digit != 0 and digit != 1:
            raise ValueError('Invalid binary digit "%s"' % digit)
        if self._children[digit] is None:
            self._children[digit] = HuffmanTreeNode()
        self._children[digit].add_child(huffman_index, digits, index + 1)
        
class Rdp60CompressionHuffanConstants(object):

    @staticmethod
    def build_huffman_tree(codes, lengths):
        root = HuffmanTreeNode()
        
        for code, length, huffman_index in zip(codes, lengths, range(len(codes))):
            digits = []
            for i in range(length):
                digits.append(code & 0x01)
                code >>= 1
            digits = digits[::-1]
            root.add_child(huffman_index, digits)
            
        return root
        
    # from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/0fffd61e-9406-4a85-bc77-c712093bc95e
    HuffLengthLEC = [
0x6, 0x6, 0x6, 0x7, 0x7, 0x7, 0x7, 0x7, # 0
0x7, 0x7, 0x7, 0x8, 0x8, 0x8, 0x8, 0x8, # 8
0x8, 0x8, 0x9, 0x8, 0x9, 0x9, 0x9, 0x9, # 16
0x8, 0x8, 0x9, 0x9, 0x9, 0x9, 0x9, 0x9, # 24
0x8, 0x9, 0x9, 0xa, 0x9, 0x9, 0x9, 0x9, # 32
0x9, 0x9, 0x9, 0xa, 0x9, 0xa, 0xa, 0xa, # 40
0x9, 0x9, 0xa, 0x9, 0xa, 0x9, 0xa, 0x9, # 48
0x9, 0x9, 0xa, 0xa, 0x9, 0xa, 0x9, 0x9, # 56
0x8, 0x9, 0x9, 0x9, 0x9, 0xa, 0xa, 0xa, # 64
0x9, 0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 72
0x9, 0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 80
0xa, 0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 88
0x8, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 96
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 104
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 112
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0x9, # 120
0x7, 0x9, 0x9, 0xa, 0x9, 0xa, 0xa, 0xa, # 128
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 136
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 144
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 152
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 160
0xa, 0xa, 0xa, 0xd, 0xa, 0xa, 0xa, 0xa, # 168
0xa, 0xa, 0xb, 0xa, 0xa, 0xa, 0xa, 0xa, # 176
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 184
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0x9, 0xa, # 192
0xa, 0xa, 0xa, 0xa, 0x9, 0xa, 0xa, 0xa, # 200
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 208
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 216
0x9, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, # 224
0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0x9, 0xa, # 232
0x8, 0x9, 0x9, 0xa, 0x9, 0xa, 0xa, 0xa, # 240
0x9, 0xa, 0xa, 0xa, 0x9, 0x9, 0x8, 0x7, # 248
0xd, 0xd, 0x7, 0x7, 0xa, 0x7, 0x7, 0x6, # 256
0x6, 0x6, 0x6, 0x5, 0x6, 0x6, 0x6, 0x5, # 264
0x6, 0x5, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, # 272
0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, # 280
0x8, 0x5, 0x6, 0x7, 0x7]                # 288

    HuffCodeLEC = [
0x0004, 0x0024, 0x0014, 0x0011, 0x0051, 0x0031, 0x0071, 0x0009, # 0
0x0049, 0x0029, 0x0069, 0x0015, 0x0095, 0x0055, 0x00d5, 0x0035, # 8
0x00b5, 0x0075, 0x001d, 0x00f5, 0x011d, 0x009d, 0x019d, 0x005d, # 16
0x000d, 0x008d, 0x015d, 0x00dd, 0x01dd, 0x003d, 0x013d, 0x00bd, # 24
0x004d, 0x01bd, 0x007d, 0x006b, 0x017d, 0x00fd, 0x01fd, 0x0003, # 32
0x0103, 0x0083, 0x0183, 0x026b, 0x0043, 0x016b, 0x036b, 0x00eb, # 40
0x0143, 0x00c3, 0x02eb, 0x01c3, 0x01eb, 0x0023, 0x03eb, 0x0123, # 48
0x00a3, 0x01a3, 0x001b, 0x021b, 0x0063, 0x011b, 0x0163, 0x00e3, # 56
0x00cd, 0x01e3, 0x0013, 0x0113, 0x0093, 0x031b, 0x009b, 0x029b, # 64
0x0193, 0x0053, 0x019b, 0x039b, 0x005b, 0x025b, 0x015b, 0x035b, # 72
0x0153, 0x00d3, 0x00db, 0x02db, 0x01db, 0x03db, 0x003b, 0x023b, # 80
0x013b, 0x01d3, 0x033b, 0x00bb, 0x02bb, 0x01bb, 0x03bb, 0x007b, # 88
0x002d, 0x027b, 0x017b, 0x037b, 0x00fb, 0x02fb, 0x01fb, 0x03fb, # 96
0x0007, 0x0207, 0x0107, 0x0307, 0x0087, 0x0287, 0x0187, 0x0387, # 104
0x0033, 0x0047, 0x0247, 0x0147, 0x0347, 0x00c7, 0x02c7, 0x01c7, # 112
0x0133, 0x03c7, 0x0027, 0x0227, 0x0127, 0x0327, 0x00a7, 0x00b3, # 120
0x0019, 0x01b3, 0x0073, 0x02a7, 0x0173, 0x01a7, 0x03a7, 0x0067, # 128
0x00f3, 0x0267, 0x0167, 0x0367, 0x00e7, 0x02e7, 0x01e7, 0x03e7, # 136
0x01f3, 0x0017, 0x0217, 0x0117, 0x0317, 0x0097, 0x0297, 0x0197, # 144
0x0397, 0x0057, 0x0257, 0x0157, 0x0357, 0x00d7, 0x02d7, 0x01d7, # 152
0x03d7, 0x0037, 0x0237, 0x0137, 0x0337, 0x00b7, 0x02b7, 0x01b7, # 160
0x03b7, 0x0077, 0x0277, 0x07ff, 0x0177, 0x0377, 0x00f7, 0x02f7, # 168
0x01f7, 0x03f7, 0x03ff, 0x000f, 0x020f, 0x010f, 0x030f, 0x008f, # 176
0x028f, 0x018f, 0x038f, 0x004f, 0x024f, 0x014f, 0x034f, 0x00cf, # 184
0x000b, 0x02cf, 0x01cf, 0x03cf, 0x002f, 0x022f, 0x010b, 0x012f, # 192
0x032f, 0x00af, 0x02af, 0x01af, 0x008b, 0x03af, 0x006f, 0x026f, # 200
0x018b, 0x016f, 0x036f, 0x00ef, 0x02ef, 0x01ef, 0x03ef, 0x001f, # 208
0x021f, 0x011f, 0x031f, 0x009f, 0x029f, 0x019f, 0x039f, 0x005f, # 216
0x004b, 0x025f, 0x015f, 0x035f, 0x00df, 0x02df, 0x01df, 0x03df, # 224
0x003f, 0x023f, 0x013f, 0x033f, 0x00bf, 0x02bf, 0x014b, 0x01bf, # 232
0x00ad, 0x00cb, 0x01cb, 0x03bf, 0x002b, 0x007f, 0x027f, 0x017f, # 240
0x012b, 0x037f, 0x00ff, 0x02ff, 0x00ab, 0x01ab, 0x006d, 0x0059, # 248
0x17ff, 0x0fff, 0x0039, 0x0079, 0x01ff, 0x0005, 0x0045, 0x0034, # 256
0x000c, 0x002c, 0x001c, 0x0000, 0x003c, 0x0002, 0x0022, 0x0010, # 264
0x0012, 0x0008, 0x0032, 0x000a, 0x002a, 0x001a, 0x003a, 0x0006, # 272
0x0026, 0x0016, 0x0036, 0x000e, 0x002e, 0x001e, 0x003e, 0x0001, # 280
0x00ed, 0x0018, 0x0021, 0x0025, 0x0065]                         # 288

    HuffTreeLEC = build_huffman_tree(HuffCodeLEC, HuffLengthLEC)
    
    CopyOffsetBitsLUT,  = [
 0,  0,  0,  0,  1,  1,  2,  2, 
 3,  3,  4,  4,  5,  5,  6,  6, 
 7,  7,  8,  8,  9,  9, 10, 10, 
11, 11, 12, 12, 13, 13, 14, 14
]
    CopyOffsetBaseLUT = [
1, 2, 3, 4, 5, 7, 9, 13,
17, 25, 33, 49, 65, 97, 129, 193, 
257, 385, 513, 769, 1025, 1537, 2049, 3073, 
4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153
]
    
    # copied from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/21aebf8f-b46c-4348-8518-bf444a3d5c16
    HuffLengthL = [
0x4, 	0x2, 	0x3, 	0x4, 	0x3, 	0x4, 	0x4, 	0x5, # 0
0x4, 	0x5, 	0x5, 	0x6, 	0x6, 	0x7, 	0x7, 	0x8, # 8
0x7, 	0x8, 	0x8, 	0x9, 	0x9, 	0x8, 	0x9, 	0x9, # 16
0x9, 	0x9, 	0x9, 	0x9, 	0x9, 	0x9, 	0x9, 	0x9, # 24
]
    HuffCodeL = [
0x0001, 	0x0000, 	0x0002, 	0x0009, 	0x0006, 	0x0005, 	0x000d, 	0x000b, 
0x0003, 	0x001b, 	0x0007, 	0x0017, 	0x0037, 	0x000f, 	0x004f, 	0x006f, 
0x002f, 	0x00ef, 	0x001f, 	0x005f, 	0x015f, 	0x009f, 	0x00df, 	0x01df, 
0x003f, 	0x013f, 	0x00bf, 	0x01bf, 	0x007f, 	0x017f, 	0x00ff, 	0x01ff, 
]
    HuffTreeL = build_huffman_tree(HuffCodeL, HuffLengthL)
    
    LoMBitsLUT = [
0, 0, 0, 0,  0,  0, 0, 0, 
1, 1, 1, 1,  2,  2, 2, 2, 
3, 3, 3, 3,  4,  4, 4, 4, 
6, 6, 8, 8, 14, 14, 
]
    LoMBaseLUT = [
  2,   3,   4,   5,  6,  7,  8,   9, 
 10,  12,  14,  16, 18, 22, 26,  30, 
 34,  42,  50,  58, 66, 82, 98, 114, 
130, 194, 258, 514, 770, 17154, 
]

class Rdp60CompressionEncoder(compression_utils.Encoder):

    def encode(self, bitstream_dest: BitStream, symbol_type: SymbolType, value: Any):
        encoding_tuples = []
        if symbol_type == SymbolType.LITERAL:
            encoding_tuples = self.encode_literal(value)
        elif symbol_type == SymbolType.END_OF_STREAM:
            encoding_tuples = self.encode_end_of_stream()
        elif symbol_type == SymbolType.COPY_OFFSET:
            encoding_tuples = self.encode_copy_offset(value.copy_offset)
            encoding_tuples.extend(self.encode_length_of_match(value.length_of_match))
        elif symbol_type == SymbolType.COPY_OFFSET_CACHE_INDEX:
            encoding_tuples = self.encode_copy_offset_cache(value.copy_offset)
            encoding_tuples.extend(self.encode_length_of_match(value.length_of_match))
        else:
            raise ValueError('Invalid symbol type: %s' % (symbol_type, ))
        
        for packed_bits, bit_length in encoding_tuples:
            bitstream_dest.append_packed_bits(packed_bits, bit_length)

    def encode_LEC_huffman_index(self, LEC_huffman_index):
        return (Rdp60CompressionHuffanConstants.HuffCodeLEC[LEC_huffman_index], Rdp60CompressionHuffanConstants.HuffLengthLEC[LEC_huffman_index])

    def encode_literal(self, literal):
        if literal < 0 or 255 < literal:
            raise ValueError('Invalid literal "%s"' % literal)
        return [self.encode_LEC_huffman_index(literal)]
        
    def encode_end_of_stream(self):
        return [self.encode_LEC_huffman_index(256)]
        
    def encode_copy_offset(self, CopyOffset):
        retval = []
        # encode CopyOffset base
        LUTIndex = bisect.bisect_right(CopyOffset + 1, Rdp60CompressionHuffanConstants.CopyOffsetBaseLUT) - 1 # IndexOfEqualOrSmallerEntry
        retval.append(self.encode_LEC_huffman_index(LUTIndex + 257))
        
        # encode CopyOffset offset
        ExtraBitsLength = Rdp60CompressionHuffanConstants.CopyOffsetBitsLUT[LUTIndex]
        ExtraBits = CopyOffset & ((2 ** ExtraBitsLength) - 1)
        retval.append((ExtraBits, ExtraBitsLength))
    
        return retval

    def encode_copy_offset_cache(self, CopyOffset_cache):
        if CopyOffset_cache < 0 or 3 < CopyOffset_cache:
            raise ValueError('Invalid CopyOffset_cache "%s"' % CopyOffset_cache)
        return [self.encode_LEC_huffman_code(CopyOffset_cache + 289)]

    def encode_length_of_match(self, LengthOfMatch):
        retval = []

        # encode LengthOfMatch base
        LUTIndex = bisect.bisect_right(LengthOfMatch, Rdp60CompressionHuffanConstants.LoMBaseLUT) - 1 # IndexOfEqualOrSmallerEntry
        retval.append((Rdp60CompressionHuffanConstants.HuffCodeL[LUTIndex], Rdp60CompressionHuffanConstants.HuffLengthL[LUTIndex]))
        
        # encode LengthOfMatch offset
        ExtraBitsLength = Rdp60CompressionHuffanConstants.LoMBitsLUT[LUTIndex]
        ExtraBits = (LengthOfMatch - 2) & ((2 ** ExtraBitsLength) - 1)
        retval.append((ExtraBits, ExtraBitsLength))
        
        return retval

class Rdp60CompressionDecoder(compression_utils.Decoder):
    
    def decode_next(self, bits_iter): Tuple[SymbolType, Any]
        return self._decode_next(bits_iter)
    
    def decode_LEC_huffman_code(self, bits_iter):
        return Rdp60CompressionHuffanConstants.HuffTreeLEC.next_huffman_index_from(bits_iter)

    def _decode_next(self, bits_iter):
        huffman_index = self.decode_LEC_huffman_code(bits_iter)
        if 0 <= huffman_index and huffman_index <= 255:
            return (SymbolType.LITERAL, huffman_index)
        elif huffman_index == 256:
            return (SymbolType.END_OF_STREAM, None)
        elif 257 <= huffman_index and huffman_index <= 288:
            return (SymbolType.COPY_OFFSET, (self.decode_copy_offset(huffman_index - 257, bits_iter), self.decode_length_of_match(bits_iter)))
        elif 289 <= huffman_index and huffman_index <= 292:
            return (SymbolType.COPY_OFFSET_CACHE_INDEX, (huffman_index - 289, self.decode_length_of_match(bits_iter)))

    def decode_copy_offset(LUTIndex, bits_iter):
        # decode CopyOffset
        BaseLUT = Rdp60CompressionHuffanConstants.CopyOffsetBaseLUT[LUTIndex]
        BitsLUT = Rdp60CompressionHuffanConstants.CopyOffsetBitsLUT[LUTIndex]
        
        StreamBits = BitStream.next_int(bits_iter, BitsLUT)
        CopyOffset = BaseLUT + StreamBits - 1
        return CopyOffset
        
    def decode_length_of_match(bits_iter):
        # decode LengthOfMatch
        LUTIndex = self.HuffTreeL.next_huffman_index_from(bits_iter)
        BaseLUT = Rdp60CompressionHuffanConstants.LoMBaseLUT[LUTIndex]
        BitsLUT = Rdp60CompressionHuffanConstants.LoMBitsLUT[LUTIndex]
        
        StreamBits = BitStream.next_int(bits_iter, BitsLUT)
        LengthOfMatch = BaseLUT + StreamBits
        return LengthOfMatch
