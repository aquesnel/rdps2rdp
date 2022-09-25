
import array
import binascii
import struct
import sys
import collections
import bisect
import enum
import itertools

import utils
import sorted_collection
import compression_constants
import compression_utils
from compression_utils import (
    SymbolType,
    CopyTuple,
    CopyTupleV2,
    CopyTupleV3,
    CompressionArgs,
)

DEBUG = False
# DEBUG = True

EncodingConfig = collections.namedtuple('CompressionConfig', ['compression_type', 'history_size', 'offset_encoding', 'length_encoding'])
EncodingRange = collections.namedtuple('EncodingRange', ['min_value', 'value_bit_length', 'prefix', 'prefix_length'])


class MppcCompressionConfig(object):
    
    RDP_40 = EncodingConfig(
            compression_type = compression_constants.CompressionTypes.RDP_40,
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
            compression_type = compression_constants.CompressionTypes.RDP_50,
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

class MppcCompressionEncoder(compression_utils.Encoder):

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


class MppcCompressionDecoder(compression_utils.Decoder):
    
    def __init__(self, encoding_config, data):
        self.encoding_config = encoding_config
        self._bitstream_src_iter = iter(compression_utils.BitStream(data, append_low_to_high = False))
    
    def decode_next(self): #Tuple[SymbolType, Any]
        # DEBUG = True
        bits_iter = self._bitstream_src_iter
        # if DEBUG: print("Processing input byte %d, bit %d, bits: %s" % (byte_offset, self.__getInputBit(), bits))
        # encoding rules from https://www.ietf.org/rfc/rfc2118.txt section 4.2.1
        if DEBUG: print('bits remaining: %s' % bits_iter.remaining())
        if bits_iter.remaining() < 8: # padding bits at the end of the stream to align to a byte boundary that can be discarded
            return (SymbolType.END_OF_STREAM, None)
        
        elif bits_iter.next() == 0: # literal value <= 0x7f with prefix 0b0
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
            if DEBUG: print('decode_range_value candidate: prefix_length = %s, prefix = %s, encoding_range = %s' % (prefix, prefix_length, encoding_range))
            while prefix_length < encoding_range.prefix_length:
                bit = bits_iter.next()
                prefix <<= 1
                prefix += bit
                prefix_length += 1
            if prefix == encoding_range.prefix:
                if DEBUG: print('decode_range_value found match: prefix_length = %s, prefix = %s, encoding_range = %s' % (prefix, prefix_length, encoding_range))
                return bits_iter.next_int(encoding_range.value_bit_length) + encoding_range.min_value

        raise ValueError('No matching prefix in config. Prefix: %s' % (prefix))

class MppcEncodingFacotry(compression_utils.EncodingFactory):
    def __init__(self, config):
        self._config = config
        
    def compression_type(self):
        return self._config.compression_type
        
    def make_encoder(self):
        return MppcCompressionEncoder(self._config)
    
    def make_decoder(self, compression_args):
        return MppcCompressionDecoder(self._config, compression_args.data)

def MPPC_field_filter(path):
    if DEBUG: print('MPPC_field_filter: split path = %s' % (path.split('.'),))
    return path.split('.')[-1] not in {'_encoder_factory'}

@utils.json_serializable(field_filter = MPPC_field_filter)
class MPPC(compression_utils.CompressionEngine):
    def __init__(self, compression_type, compression_history_manager, decompression_history_manager, encoder_factory, add_non_compressed_data_to_history, **kwargs):
        super(MPPC, self).__init__(compression_type)
        self._encoder_factory = encoder_factory
        self._decompression_history_manager = decompression_history_manager
        self._compression_history_manager = compression_history_manager
        self._add_non_compressed_data_to_history = add_non_compressed_data_to_history

    # def resetHistory(self):
    #     self._decompression_history_manager.resetHistory()
    #     self._compression_history_manager.resetHistory()

    def compress(self, data):
        encoder = self._encoder_factory.make_encoder()
        flags = {compression_constants.CompressionFlags.COMPRESSED}
        
        if self._compression_history_manager.buffer_space_remaining() < len(data):
            self._compression_history_manager.resetHistory()
            flags.add(compression_constants.CompressionFlags.AT_FRONT)
            flags.add(compression_constants.CompressionFlags.FLUSHED)

        inByteOffset = 0
        for history_match in itertools.chain(self._compression_history_manager.append_and_find_matches(data), 
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
                
        return CompressionArgs(data = encoder.get_encoded_bytes(), flags = flags, type = self._encoder_factory.compression_type())
        
    def decompress(self, compression_args):
        # DEBUG = True
        
        if (compression_constants.CompressionFlags.FLUSHED in compression_args.flags
                or compression_constants.CompressionFlags.AT_FRONT in compression_args.flags):
            self._decompression_history_manager.resetHistory()
        
        if compression_constants.CompressionFlags.COMPRESSED not in compression_args.flags:
            if self._add_non_compressed_data_to_history:
                self._decompression_history_manager.append_bytes(compression_args.data)
            if compression_args.is_debug_enabled(DEBUG): print("decoder the Data is not compressed, returning raw data")
            return compression_args.data
        
        decoder = self._encoder_factory.make_decoder(compression_args)
        
        output_length = 0
        done = False
        while not done:
            decoder_retval = decoder.decode_next()
            if compression_args.is_debug_enabled(DEBUG): print("decoder (%s) returned: %s" % (decoder, decoder_retval,))
            type, value = decoder_retval
            if type == SymbolType.END_OF_STREAM:
                if compression_args.is_debug_enabled(DEBUG): print('decoding (output_len = %d) end-of-stream ' % (output_length, ))
                done = True
            elif type == SymbolType.LITERAL:
                # if value > b'\xff':
                #     raise ValueError("Byte must be less than or equal to 0xff, got: ", hex(value))
                # dest.append(value)
                self._decompression_history_manager.append_bytes(value)
                if compression_args.is_debug_enabled(DEBUG): print('decoding (output_len = %d) literal: %s' % (output_length, value,))
                output_length += len(value)
                #if DEBUG: print("Push bytes to output: %s = %s, dest = ...%s" % (' '.join([hex(v) for v in value]), bytes(value), self._decompression_history_manager.get_bytes(output_length, output_length, relative = True).tobytes()[-10:]))
            elif type == SymbolType.COPY_OFFSET:
                # import binascii
                # if DEBUG: print("history:        ",binascii.hexlify(self._decompression_history_manager._history[-1 * value.copy_offset:self._decompression_history_manager._historyOffset]))
                # match_data = self._decompression_history_manager.get_bytes(value.copy_offset, value.length_of_match, relative = value.is_relative_offset)
                match_data = bytearray(value.length_of_match)
                for i in range(value.length_of_match):
                    if value.is_relative_offset:
                        copy_offset = value.copy_offset
                    else:
                        copy_offset = value.copy_offset + i
                    match_data[i] = self._decompression_history_manager.get_bytes(copy_offset, 1, relative = value.is_relative_offset)[0]
                    self._decompression_history_manager.append_byte(match_data[i])
                    if compression_args.is_debug_enabled(DEBUG): print('decoding (output_len = %d) copy match (count=%d): %s' % (output_length + i, i, match_data[i].to_bytes(1, 'little'),))
                # if DEBUG: print("decoding copy_tuple: %s, match_data = [...]%s" % (value, bytes(match_data)[-10:]))
                # dest.extend(match_data)
                # self._decompression_history_manager.append_bytes(match_data)
                output_length += value.length_of_match
                
            else:
                raise ValueError('unknown SymbolType: %s' % type)
        retval = self._decompression_history_manager.get_bytes(output_length, output_length, relative = True)
        if compression_args.is_debug_enabled(DEBUG): print('decoding final result (len=%d): %s' % (output_length, retval,))
        import utils
        utils.assertEqual(len(retval), output_length)
        retval = retval.tobytes()
        # utils.assertEqual(len(retval), output_length)
        return retval
