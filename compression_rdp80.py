import collections
import sorted_collection

import utils
import compression_huffman
import compression_utils
from data_model_v2_rdp import Rdp
import data_model_v2_rdp_egdi
import compression_constants

from compression_utils import (
    SymbolType,
    CopyTuple,
    CopyTupleV2,
    CompressionArgs,
)

DEBUG=False
# DEBUG=True

EncodingToken = collections.namedtuple('EncodingToken', ['prefix', 'prefix_length', 'value_bit_length', 'token_type', 'offset',])
EncodingRange = collections.namedtuple('EncodingRange', ['min_value', 'value_bit_length', 'prefix', 'prefix_length'])

def build_huffman_tree(encoding_tokens):
    root = compression_huffman.HuffmanTreeNode()
    for encoding_token in encoding_tokens:
        root.add_child(encoding_token, encoding_token.prefix, encoding_token.prefix_length)
    return root

class Rdp80CompressionConstants(object):
    # from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/4c26b84a-fa5e-42d0-bcf4-3eee8fac2d3f
    TOKEN_ENCODINGS = [
        EncodingToken(0b0,         1,  8, SymbolType.LITERAL, 0),
        EncodingToken(0b10001,     5,  5, SymbolType.COPY_OFFSET,       0),
        EncodingToken(0b10010,     5,  7, SymbolType.COPY_OFFSET,      32),
        EncodingToken(0b10011,     5,  9, SymbolType.COPY_OFFSET,     160),
        EncodingToken(0b10100,     5, 10, SymbolType.COPY_OFFSET,     672),
        EncodingToken(0b10101,     5, 12, SymbolType.COPY_OFFSET,    1696),
        EncodingToken(0b101100,    6, 14, SymbolType.COPY_OFFSET,    5792),
        EncodingToken(0b101101,    6, 15, SymbolType.COPY_OFFSET,   22176),
        EncodingToken(0b1011100,   7, 18, SymbolType.COPY_OFFSET,   54944),
        EncodingToken(0b1011101,   7, 20, SymbolType.COPY_OFFSET,  317088),
        EncodingToken(0b10111100,  8, 20, SymbolType.COPY_OFFSET, 1365664),
        EncodingToken(0b10111101,  8, 21, SymbolType.COPY_OFFSET, 2414240),
        EncodingToken(0b11000,     5,  0, SymbolType.LITERAL, 0),
        EncodingToken(0b11001,     5,  0, SymbolType.LITERAL, 1),
        EncodingToken(0b110100,    6,  0, SymbolType.LITERAL, 2),
        EncodingToken(0b110101,    6,  0, SymbolType.LITERAL, 3),
        EncodingToken(0b110110,    6,  0, SymbolType.LITERAL, 255), # 0xff
        EncodingToken(0b1101110,   7,  0, SymbolType.LITERAL, 4),
        EncodingToken(0b1101111,   7,  0, SymbolType.LITERAL, 5),
        EncodingToken(0b1110000,   7,  0, SymbolType.LITERAL, 6),
        EncodingToken(0b1110001,   7,  0, SymbolType.LITERAL, 7),
        EncodingToken(0b1110010,   7,  0, SymbolType.LITERAL, 8),
        EncodingToken(0b1110011,   7,  0, SymbolType.LITERAL, 9),
        EncodingToken(0b1110100,   7,  0, SymbolType.LITERAL, 10),
        EncodingToken(0b1110101,   7,  0, SymbolType.LITERAL, 11),
        EncodingToken(0b1110110,   7,  0, SymbolType.LITERAL, 58),  # 0x3a
        EncodingToken(0b1110111,   7,  0, SymbolType.LITERAL, 59),  # 0x3b
        EncodingToken(0b1111000,   7,  0, SymbolType.LITERAL, 60),  # 0x3c
        EncodingToken(0b1111001,   7,  0, SymbolType.LITERAL, 61),  # 0x3d
        EncodingToken(0b1111010,   7,  0, SymbolType.LITERAL, 62),  # 0x3e
        EncodingToken(0b1111011,   7,  0, SymbolType.LITERAL, 63),  # 0x3f
        EncodingToken(0b1111100,   7,  0, SymbolType.LITERAL, 64),  # 0x40
        EncodingToken(0b1111101,   7,  0, SymbolType.LITERAL, 128), # 0x80
        EncodingToken(0b11111100,  8,  0, SymbolType.LITERAL, 12),  # 0x0c
        EncodingToken(0b11111101,  8,  0, SymbolType.LITERAL, 56),  # 0x38
        EncodingToken(0b11111110,  8,  0, SymbolType.LITERAL, 57),  # 0x39
        EncodingToken(0b11111111,  8,  0, SymbolType.LITERAL, 102), # 0x66
    ]

    COPY_OFFSET_ENCODING = sorted_collection.SortedCollection([
            EncodingRange(min_value = encoding_token.offset, 
                    value_bit_length =  encoding_token.value_bit_length, 
                    prefix = encoding_token.prefix, 
                    prefix_length = encoding_token.prefix_length)
            for encoding_token 
                in TOKEN_ENCODINGS 
                if encoding_token.token_type == SymbolType.COPY_OFFSET
        ], key = lambda x: x.min_value)
    LENGTH_ENCODINGS = sorted_collection.SortedCollection([
            EncodingRange(min_value =     3, value_bit_length =  0, prefix = 0b0, prefix_length = 1),
            EncodingRange(min_value =     4, value_bit_length =  2, prefix = 0b10, prefix_length = 2),
            EncodingRange(min_value =     8, value_bit_length =  3, prefix = 0b110, prefix_length = 3),
            EncodingRange(min_value =    16, value_bit_length =  4, prefix = 0b1110, prefix_length = 4),
            EncodingRange(min_value =    32, value_bit_length =  5, prefix = 0b11110, prefix_length = 5),
            EncodingRange(min_value =    64, value_bit_length =  6, prefix = 0b111110, prefix_length = 6),
            EncodingRange(min_value =   128, value_bit_length =  7, prefix = 0b1111110, prefix_length = 7),
            EncodingRange(min_value =   256, value_bit_length =  8, prefix = 0b11111110, prefix_length = 8),
            EncodingRange(min_value =   512, value_bit_length =  9, prefix = 0b111111110, prefix_length = 9),
            EncodingRange(min_value =  1024, value_bit_length = 10, prefix = 0b1111111110, prefix_length = 10),
            EncodingRange(min_value =  2048, value_bit_length = 11, prefix = 0b11111111110, prefix_length = 11),
            EncodingRange(min_value =  4096, value_bit_length = 12, prefix = 0b111111111110, prefix_length = 12),
            EncodingRange(min_value =  8192, value_bit_length = 13, prefix = 0b1111111111110, prefix_length = 13),
            EncodingRange(min_value = 16384, value_bit_length = 14, prefix = 0b11111111111110, prefix_length = 14),
            EncodingRange(min_value = 32768, value_bit_length = 15, prefix = 0b111111111111110, prefix_length = 15),
        ], key = lambda x: x.min_value)
    TOKENS_HUFFMAN_TREE = build_huffman_tree(TOKEN_ENCODINGS)
    LITERALS_MAP = {
        encoding_token.offset: encoding_token
        for encoding_token 
            in TOKEN_ENCODINGS 
            if encoding_token.token_type == SymbolType.LITERAL and encoding_token.prefix_length == 0
    }



class Rdp80_CompressionEncoder(compression_utils.Encoder):

    def __init__(self):
        self._bitstream_dest = compression_utils.BitStream()

    def get_encoded_bytes(self):
        return self._bitstream_dest.tobytes()

    def encode(self, symbol_type, value):
        encoding_tuples = []
        if symbol_type == SymbolType.LITERAL:
            encoding_tuples = self.encode_literal(value)
            if DEBUG: print('encoding literal: %d -> %s' % (value, (chr(value) if value != 0 else '')))
            
        elif symbol_type == SymbolType.COPY_OFFSET:
            if DEBUG: print('encoding copy_tuple: %s' % (value,))
            encoding_tuples = self.encode_copy_offset(value.copy_offset)
            encoding_tuples.extend(self.encode_length_of_match(value.length_of_match))
        elif symbol_type == SymbolType.END_OF_STREAM:
            padding_length = self._bitstream_dest.get_available_bits_in_last_byte()
            encoding_tuples = [
                (0, padding_length), # pad with zeros
                (padding_length, 8), # padding checksum
            ]
            if DEBUG: print('encoding end-of-stream with %d padding bits' % padding_length)
        else:
            raise ValueError('Invalid symbol type: %s' % (symbol_type, ))
        
        for packed_bits, bit_length in encoding_tuples:
            self._bitstream_dest.append_packed_bits(packed_bits, bit_length)

    def encode_literal(self, byte):
        if byte in Rdp80CompressionConstants.LITERALS_MAP:
            encoding_token = Rdp80CompressionConstants.LITERALS_MAP[byte]
            return [(encoding_token.prefix, encoding_token.prefix_length)]
        
        return [(byte & 0xFF, 9)]

    def encode_range_value(self, encoding_range, value):
        value_shifted = value - encoding_range.min_value
        
        retval = [
            (encoding_range.prefix, encoding_range.prefix_length),
            (value_shifted, encoding_range.value_bit_length)
            ]
        if DEBUG: print('encoding range: prefix = %s, value = %s, value_shifted = %s' % (encoding_range.prefix, value, value_shifted))
        
        return retval
        
    def encode_copy_offset(self, CopyOffset):
        encoding_range = Rdp80CompressionConstants.COPY_OFFSET_ENCODING.find_le(CopyOffset)
        return self.encode_range_value(encoding_range, CopyOffset)

    def encode_length_of_match(self, LengthOfMatch):
        encoding_range = Rdp80CompressionConstants.LENGTH_ENCODINGS.find_le(LengthOfMatch)
        return self.encode_range_value(encoding_range, LengthOfMatch)


class Rdp80_CompressionDecoder(compression_utils.Decoder):

    def __init__(self, data):
        self.__iter = self.decode_iter(data)

    def decode_next(self): # Tuple[SymbolType, Any]
        return next(self.__iter)
    
    def decode_iter(self, data): # Tuple[SymbolType, Any]
        # from: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/4c26b84a-fa5e-42d0-bcf4-3eee8fac2d3f
        # """The five high-order bits in the last byte of the compressed segment are reserved."""
        padding_bit_length = data[-1] & 0x07
        if padding_bit_length > 7: # this is now redundant with the mask applied above
            raise ValueError('Invalid padding bit length checksum: %d' % padding_bit_length)
        if DEBUG: print('padding bits removed: %s' % (padding_bit_length,))
        data_without_padding_checksum = memoryview(data)[:-1]
        bits_iter = iter(compression_utils.BitStream(data_without_padding_checksum, padding_bit_length))
        
        while bits_iter.remaining() > 0:
            if DEBUG: print('bits remaining: %s' % (bits_iter.remaining(),))
            encoding_token = Rdp80CompressionConstants.TOKENS_HUFFMAN_TREE.next_value_from(bits_iter)
            if DEBUG: print('decoding token: %s' % (encoding_token,))
            
            value = bits_iter.next_int(encoding_token.value_bit_length) + encoding_token.offset
            if encoding_token.token_type == SymbolType.LITERAL:
                if DEBUG: print('decoding literal: %d -> %s' % (value, (chr(value) if value != 0 else '')))
                yield (SymbolType.LITERAL, value.to_bytes(1,'little'))
                
            elif encoding_token.token_type == SymbolType.COPY_OFFSET:
                copy_offset = value
                if copy_offset == 0:
                    # from: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/4c26b84a-fa5e-42d0-bcf4-3eee8fac2d3f
                    # """
                    # A match distance of zero is a special case, which indicates that an unencoded run of bytes follows. The count of bytes is encoded as a 15-bit value, most significant bit first. After decoding this count, any bits remaining in the current input byte are ignored, and the unencoded run will begin on a whole-byte boundary.
                    # """
                    literals = bytearray()
                    length_of_match = bits_iter.next_int(15)
                    byte_alignment_padding_length = self._bitstream_dest.get_available_bits_in_last_byte()
                    _ = bits_iter.next_int(byte_alignment_padding_length)
                    for i in range(length_of_match):
                        literals.append(bits_iter.next_int(8))
                    if DEBUG: print('decoding literals: %s -> %s' % (utils.as_hex_str(literals), ''.join((chr(value) if value != 0 else '') for value in literals)))
                    yield (SymbolType.LITERAL, literals)
                else:
                    length_of_match = self.decode_length_of_match(bits_iter)
                    copy_tuple = CopyTupleV2(copy_offset, length_of_match, is_relative_offset = True)
                    if DEBUG: print('decoding copy_tuple: copy_tuple = %s' % (str(copy_tuple)))
                    yield (SymbolType.COPY_OFFSET, copy_tuple)
        
        if DEBUG: print('decoding end-of-stream')
        yield (SymbolType.END_OF_STREAM, None)

    def decode_length_of_match(self, bits_iter):
        prefix = 0
        prefix_length = 0
        for encoding_range in Rdp80CompressionConstants.LENGTH_ENCODINGS:
            if prefix_length > encoding_range.prefix_length:
                raise ValueError('Expected the prefix length to be monotonically increasing')
            if DEBUG: print('decode_range_value prefix = %s, prefix_length = %s, encoding_range = %s' % (prefix, prefix_length, encoding_range))
            while prefix_length < encoding_range.prefix_length:
                bit = bits_iter.next()
                prefix <<= 1
                prefix += bit
                prefix_length += 1
            if prefix == encoding_range.prefix:
                if DEBUG: print('decode_range_value found match: prefix = %s, prefix_length = %s, encoding_range = %s' % (prefix, prefix_length, encoding_range))
                return bits_iter.next_int(encoding_range.value_bit_length) + encoding_range.min_value

        raise ValueError('No matching prefix in config. Prefix: %s' % (prefix))


class Rdp80_CompressionEncodingFacotry(compression_utils.EncodingFactory):
    def compression_type(self):
        return compression_constants.CompressionTypes.RDP_80
    
    def make_encoder(self):
        return Rdp80_CompressionEncoder()
    
    def make_decoder(self, compression_args):
        if compression_constants.CompressionFlags.COMPRESSED in compression_args.flags:
            return Rdp80_CompressionDecoder(compression_args.data)
        else:
            return compression_utils.NoOpDecoder(compression_args.data)
    
    