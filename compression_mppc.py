
import array
import binascii
import struct
import sys
import collections
import bisect
import enum
import itertools

import sorted_collection
import compression_utils
from compression_utils import (
    SymbolType,
    CopyTuple,
    CopyTupleV2,
    CopyTupleV3,
)

DEBUG = False
# DEBUG = True

EncodingConfig = collections.namedtuple('CompressionConfig', ['history_size', 'offset_encoding', 'length_encoding'])
EncodingRange = collections.namedtuple('EncodingRange', ['min_value', 'value_bit_length', 'prefix', 'prefix_length'])


class MccpCompressionConfig(object):
    
    RDP_40 = EncodingConfig(
            history_size = 8196,
            # reset_to_begining = True,
            # offset_cache_size = 0,
            offset_encoding = sorted_collection.SortedCollection([
                    EncodingRange(min_value = 0,   value_bit_length =  6, prefix = 0b1111, prefix_length = 4),
                    EncodingRange(min_value = 64,  value_bit_length =  8, prefix = 0b1110, prefix_length = 4),
                    EncodingRange(min_value = 320, value_bit_length = 13, prefix =  0b110, prefix_length = 3),
                ], key = lambda x: x.min_value),
            length_encoding = sorted_collection.SortedCollection([
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
                ], key = lambda x: x.min_value),
        )
    RDP_50 = EncodingConfig(
            history_size = 65536,
            # reset_to_begining = True,
            # offset_cache_size = 0,
            offset_encoding = sorted_collection.SortedCollection([
                    EncodingRange(min_value = 0,    value_bit_length =  6, prefix = 0b11111, prefix_length = 5),
                    EncodingRange(min_value = 64,   value_bit_length =  8, prefix = 0b11110, prefix_length = 5),
                    EncodingRange(min_value = 320,  value_bit_length = 11, prefix =  0b1110, prefix_length = 4),
                    EncodingRange(min_value = 2368, value_bit_length = 16, prefix =   0b110, prefix_length = 3),
                ], key = lambda x: x.min_value),
            length_encoding = sorted_collection.SortedCollection([
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
                ], key = lambda x: x.min_value),
        )

class MccpCompressionEncoder(compression_utils.Encoder):

    def __init__(self, encoding_config):
        self.encoding_config = encoding_config
        self._bitstream_dest = compression_utils.BitStream()

    def get_encoded_bytes(self):
        return self._bitstream_dest.tobytes()

    def encode(self, symbol_type, value):
        encoding_tuples = []
        if symbol_type == SymbolType.LITERAL:
            encoding_tuples = self.encode_literal(value)
            if DEBUG: print('encoding literal: %s' % (chr(value)))
            
        elif symbol_type == SymbolType.COPY_OFFSET:
            if DEBUG: print('encoding copy_tuple: %s' % (value,))
            encoding_tuples = self.encode_copy_offset(value.copy_offset)
            encoding_tuples.extend(self.encode_length_of_match(value.length_of_match))
        elif symbol_type == SymbolType.END_OF_STREAM:
            if DEBUG: print('encoding end-of-stream')
            return
        else:
            raise ValueError('Invalid symbol type: %s' % (symbol_type, ))
        
        for packed_bits, bit_length in encoding_tuples:
            self._bitstream_dest.append_packed_bits(packed_bits, bit_length)

    def encode_literal(self, byte):
        if byte < 0 or 255 < byte:
            raise ValueError('Invalid literal "%s"' % byte)
        
        if byte < 0x80:
            return [(byte, 8)]
        else:
            return [((byte & 0x7F) | 0x0100 , 9)]

    def encode_range_value(self, encoding_range, value):
        value_shifted = value - encoding_range.min_value
        
        retval = [
            (encoding_range.prefix, encoding_range.prefix_length),
            (value_shifted, encoding_range.value_bit_length)
            ]
        if DEBUG: print('encoding range: prefix = %s, value = %s, value_shifted = %s' % (encoding_range.prefix, value, value_shifted))
        
        return retval
        
    def encode_copy_offset(self, CopyOffset):
        encoding_range = self.encoding_config.offset_encoding.find_le(CopyOffset)
        return self.encode_range_value(encoding_range, CopyOffset)

    def encode_length_of_match(self, LengthOfMatch):
        encoding_range = self.encoding_config.length_encoding.find_le(LengthOfMatch)
        return self.encode_range_value(encoding_range, LengthOfMatch)


class MccpCompressionDecoder(compression_utils.Decoder):
    
    def __init__(self, encoding_config, data):
        self.encoding_config = encoding_config
        self._bitstream_src_iter = iter(compression_utils.BitStream(data, append_low_to_high = False))
    
    def decode_next(self): #Tuple[SymbolType, Any]
        bits_iter = self._bitstream_src_iter
        # if DEBUG: print("Processing input byte %d, bit %d, bits: %s" % (byte_offset, self.__getInputBit(), bits))
        # encoding rules from https://www.ietf.org/rfc/rfc2118.txt section 4.2.1
        if DEBUG: print('bits remaining: %s' % bits_iter.remaining())
        if bits_iter.next() == 0: # literal value <= 0x7f with prefix 0b0
            if bits_iter.remaining() < 8: # padding bits at the end of the stream to align to a byte boundary that can be discarded
                return (SymbolType.END_OF_STREAM, None)
            else:
                literal_byte = bits_iter.next_int(7)
                return (SymbolType.LITERAL, literal_byte.to_bytes(1,'little'))

        elif bits_iter.next() == 0: # literal value > 0x7f with prefix 0b10
            literal_byte = bits_iter.next_int(7) + 128
            return (SymbolType.LITERAL, literal_byte.to_bytes(1,'little'))
            
        else:
            # encoded copy tuple with prefix 0b11
            copy_offset = self.decode_range_value(bits_iter, reversed(self.encoding_config.offset_encoding), prefix = 0b11, prefix_length = 2)
            length = self.decode_range_value(bits_iter, self.encoding_config.length_encoding)

            return (SymbolType.COPY_OFFSET, CopyTupleV2(copy_offset, length, is_relative_offset = True))

    def decode_range_value(self, bits_iter, encoding_ranges_iter, prefix = 0, prefix_length = 0):
        for encoding_range in encoding_ranges_iter:
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

class MppcEncodingFacotry(compression_utils.EncodingFacotry):
    def __init__(self, config):
        self._config = config
        
    def make_encoder(self):
        return MccpCompressionEncoder(self._config)
    
    def make_decoder(self, data):
        return MccpCompressionDecoder(self._config, data)
    



class MPPC(compression_utils.CompressionEngine):

    def __init__(self, compression_history_manager, decompression_history_manager, encoder_factory):
        self._encoder_factory = encoder_factory
        self._decompressionHistoryManager = decompression_history_manager
        self._compressionHistoryManager = compression_history_manager

    def resetHistory(self):
        self._decompressionHistoryManager.resetHistory()
        self._compressionHistoryManager.resetHistory()

    def compress(self, data):
        encoder = self._encoder_factory.make_encoder()

        inByteOffset = 0
        for history_match in itertools.chain(self._compressionHistoryManager.append_and_find_matches(data), 
                                            [compression_utils.HistoryMatch(data_absolute_offset=len(data), history_absolute_offset=None, history_relative_offset=None, length=0)]):
            if history_match.data_absolute_offset > inByteOffset:
                non_match_length = history_match.data_absolute_offset - inByteOffset
                for _ in range(non_match_length):
                    encoder.encode(SymbolType.LITERAL, data[inByteOffset])
                    inByteOffset += 1
            if history_match.length > 0:
                encoder.encode(SymbolType.COPY_OFFSET, CopyTupleV3(history_match.history_relative_offset, history_match.length, history_match.history_absolute_offset))
                inByteOffset += history_match.length
        encoder.encode(SymbolType.END_OF_STREAM, None)
                
        return encoder.get_encoded_bytes()
        
    def decompress(self, data):
        # DEBUG = True
        decoder = self._encoder_factory.make_decoder(data)
        # dest = bytearray()
        output_length = 0
        done = False
        while not done:
            type, value = decoder.decode_next()
            if type == SymbolType.END_OF_STREAM:
                if DEBUG: print('decoding end-of-stream')
                done = True
            elif type == SymbolType.LITERAL:
                # if value > b'\xff':
                #     raise ValueError("Byte must be less than or equal to 0xff, got: ", hex(value))
                # dest.append(value)
                self._decompressionHistoryManager.append_bytes(value)
                output_length += len(value)
                if DEBUG: print('decoding literal: %s' % (value,))
                #if DEBUG: print("Push bytes to output: %s = %s, dest = ...%s" % (' '.join([hex(v) for v in value]), bytes(value), self._decompressionHistoryManager.get_bytes(output_length, output_length, relative = True).tobytes()[-10:]))
            elif type == SymbolType.COPY_OFFSET:
                match_data = self._decompressionHistoryManager.get_bytes(value.copy_offset, value.length_of_match, relative = value.is_relative_offset)
                if DEBUG: print("decoding copy_tuple: %s, match_data = [...]%s" % (value, bytes(match_data)[-10:]))
                # dest.extend(match_data)
                self._decompressionHistoryManager.append_bytes(match_data)
                output_length += value.length_of_match
                
            else:
                raise ValueError('unknown SymbolType: %s' % type)
        return self._decompressionHistoryManager.get_bytes(output_length, output_length, relative = True).tobytes()
        # return dest