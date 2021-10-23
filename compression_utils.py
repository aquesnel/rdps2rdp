import array
import collections
import enum
from typing import Any, Tuple

DEBUG = False
# DEBUG = True

@enum.unique
class SymbolType(enum.Enum):
    LITERAL = 'literal'
    END_OF_STREAM = 'end_of_stream'
    COPY_OFFSET = 'copy_offset'
    COPY_OFFSET_CACHE_INDEX = 'copy_offset_cache_index'

CopyTuple = collections.namedtuple('CopyTuple', ['copy_offset', 'length_of_match'])
HistoryMatch = collections.namedtuple('HistoryMatch', ['data_absolute_offset', 'history_absolute_offset', 'history_relative_offset', 'length'])



class BitStream(object):
    def __init__(self, packed_bits = [], append_low_to_high = False):
        self._bit_offset = 0
        self._bytes = bytearray(packed_bits)
        self._append_low_to_high = append_low_to_high

    class BitStreamIter(object):
        def __init__(self, bit_stream):
            self.bit_stream = bit_stream
            self._iter = self.__priv_iter()
            self._remaining = len(bit_stream)
        
        def __priv_iter(self):
            for b in self.bit_stream._bytes:
                mask = 0x80
                for bit_index in range(7, -1, -1):
                    bit = (b & mask) >> bit_index
                    if DEBUG: print('next_bit bit = %s ' % (bit))
                    yield bit 
                    mask >>= 1
                    self._remaining -= 1
        
        def __next__(self):
            return next(self._iter)
            
        def next(self):
            return self.__next__()
            
        def next_int(self, bit_length):
            retval = 0
            if DEBUG: print('next_int bit_length = %s ' % (bit_length))
            for bit_index in range(bit_length):
                bit = self.next()
                BitStream._verify_bit(bit)
                retval <<= 1
                retval |= bit
            if DEBUG: print('next_int bit_length = %s, value = %s' % (bit_length, retval))
            return retval
            
        def remaining(self):
            return self._remaining
        
    class LowToHightBitStreamIter(object):
        def __init__(self, bit_stream):
            self.bit_stream = bit_stream
            self._iter = self.__priv_iter()
            self._remaining = len(bit_stream)
        
        def __priv_iter(self):
            for b in self.bit_stream._bytes:
                mask = 0x01
                for bit_index in range(8):
                    bit = (b & mask) >> bit_index
                    if DEBUG: print('next_bit bit = %s ' % (bit))
                    yield bit 
                    mask <<= 1
                    self._remaining -= 1
        
        def __next__(self):
            return next(self._iter)
            
        def next(self):
            return self.__next__()
            
        def next_int(self, bit_length):
            retval = 0
            if DEBUG: print('next_int bit_length = %s ' % (bit_length))
            for bit_index in range(bit_length):
                bit = self.next()
                BitStream._verify_bit(bit)
                bit <<= bit_index
                retval |= bit
            if DEBUG: print('next_int bit_length = %s, value = %s' % (bit_length, retval))
            return retval
            
        def remaining(self):
            return self._remaining
        
    def __iter__(self):
        if self._append_low_to_high:
            return BitStream.LowToHightBitStreamIter(self)
        else:
            return BitStream.BitStreamIter(self)
    
    def __len__(self):
        return len(self._bytes) * 8 - (8 - self._bit_offset)
    
    def iter_low_to_high(self):
        return BitStream.LowToHightBitStreamIter(self)
    
    def as_byte_array(self):
        return bytearray(self)
        
    def tobytes(self):
        return bytes(self._bytes)
    
    # @classmethod
    # def next_int(cls, bit_iter, bit_length):
    #     retval = 0
    #     for bit_index in range(bit_length):
    #         bit = bit_iter.next()
    #         self._verify_bit(bit)
    #         retval <<= 1
    #         retval |= bit
    #     return retval
    
    @classmethod
    def _verify_bit(cls, bit):
        if bit != 0 and bit != 1:
            raise ValueError('Invalid binary digit "%s"' % bit)
    
    def append_bit(self, bit):
        self._verify_bit(bit)
        if DEBUG: print('append bit = %s' % (bit))
        self.append_byte(bit, 1)
    
    def append_byte(self, byte, bit_length):
        if bit_length == 0:
            return
        if byte < 0 or 255 < byte:
            raise ValueError('Invalid byte "%s"' % byte)
        if bit_length < 1 or 8 < bit_length:
            raise ValueError('Invalid bit length "%s"' % bit_length)
        if self._bit_offset == 0:
            self._bytes.append(0)
        
        available_bits = 8 - self._bit_offset
        if bit_length <= available_bits:
            # we can fit the whole thing
            if self._append_low_to_high:
                # shift the bits up to be just past the existing bits
                shift = self._bit_offset
            else:
                # shift the bits up to be next to the already packed bits
                shift = available_bits - bit_length
            shifted_bits = byte << shift

            self._bytes[-1] |= shifted_bits
            self._bit_offset += bit_length
            
        else:
            # grab 'available_bits' from the top
            if self._append_low_to_high:
                # shift the bits up to be just past the existing bits
                shifted_bits_1 = (byte << self._bit_offset) & 0xff
                # shift the remaining high bits to start the next byte
                shifted_bits_2 = byte >> available_bits
                
            else:
                # shift the bits down to append the high order bits to be next to the already packed bits
                shift = bit_length - available_bits
                shifted_bits_1 = byte >> shift
                
                shift = 8 - shift
                # mask = (1 << bits_remaining) - 1
                # byte &= mask
                shifted_bits_2 = (byte << shift) & 0xff
                
            self._bytes[-1] |= shifted_bits_1
            self._bytes.append(shifted_bits_2)
            bits_remaining = bit_length - available_bits
            self._bit_offset = bits_remaining
        self._bit_offset %= 8

        if DEBUG: print('bit stream bytes = %s -%d' % (self._bytes.hex(), (8 - self._bit_offset if self._bit_offset > 0 else self._bit_offset)))

    
    def append_packed_bits(self, bytes, bit_length):
        if isinstance(bytes, int):
            # raise ValueError('int byte not supported "%s"' % bytes)
            if bytes < 0:
                raise ValueError('Invalid positive integer "%s"' % bytes)
            if DEBUG: print('appending int as bits. length = %s, int  = %s = %s' % (bit_length, bytes, ("{0:0%db}"%(bit_length)).format(bytes)))
            temp = []
            shift_to_align = bit_length % 8
            if shift_to_align > 0:
                mask = (1 << shift_to_align) - 1
                temp = [bytes & mask]
                bytes >>= shift_to_align
            bits_remaining = bit_length - shift_to_align
            while bits_remaining > 0:
                temp.insert(0, bytes % 0xff)
                bytes >>= 8
                bits_remaining -= 8
            bytes = temp
        import builtins
        if DEBUG: print('appending bit_length = %s, bytes = %s = %s = %s' % (bit_length, bytes, [chr(b) for b in bytes], builtins.bytes(bytes).hex()))
        byte_length = len(bytes)
        bit_length_in_bytes = bit_length // 8
        if byte_length < bit_length_in_bytes or bit_length_in_bytes + 1 < byte_length:
            raise ValueError('Invalid bit_length for bytes. len(bytes) = %s, bit_length = %s' % (len(bytes), bit_length))
        
        i = 0
        while bit_length > 8:
            self.append_byte(bytes[i], 8)
            i += 1
            bit_length -= 8
        if bit_length > 0:
            try:
                self.append_byte(bytes[i], bit_length)
            except Exception:
                raise ValueError('assumed invalid offset. len(bytes) = %s, i = %s, bit_length = %s' % (len(bytes), i, bit_length))

class CompressionEngine(object):
    def resetHistory(self):
        pass

    def compress(self, data):
        raise NotImplementedError()
        return b''

    def decompress(self, data):
        raise NotImplementedError()
        return b''

class EncodingFacotry(object):
    def make_encoder(self):
        return Encoder()
    
    def make_decoder(self, data):
        return Decoder()

class Encoder(object):
    def encode(self, symbol_type: SymbolType, value: Any):
        pass

    def get_encoded_bytes(self):
        return b''

class Decoder(object):
    def decode_next(self): #Tuple[SymbolType, Any]
        pass
    
    # def get_decoded_bytes(self):
    #     return b''

class RecordingEncoder(Encoder):
    def __init__(self, inner_encoder):
        self._inner_encoder = inner_encoder
        self._recording = []
        self._prev = SymbolType.COPY_OFFSET
    
    def get_recording(self):
        return self._recording
    
    def encode(self, bitstream_dest: BitStream, symbol_type: SymbolType, value: Any):
        if symbol_type == SymbolType.LITERAL:
            if self._prev != SymbolType.LITERAL:
                self._recording.append(bytearray())
            self._recording[-1].append(value)
        else:
            self._recording.append(value)
        self._prev = symbol_type
            
        self._inner_encoder.encode(bitstream_dest, symbol_type, value)

class HistoryManager(object):
    def resetHistory(self):
        pass

    def append_bytes(self, bytes):
        for byte in bytes:
            self.append_byte(byte)

    def append_byte(self, byte):
        pass
    
    def get_byte(self, offset, relative=True):
        return self.get_bytes(offset, 1, relative)[0]
        
    def get_bytes(self, offset, length, relative=True):
        return b''
        
    # def get_history_offset(self):
    #     return 0
        
    def append_and_find_matches(self, data):
        self.append_bytes(data)
        # if False:
        #     yield HistoryMatch(data_absolute_offset=0, history_absolute_offset=0, history_relative_offset=0, length=0)
        return iter([])

class BufferOnlyHistoryManager(HistoryManager):
    def __init__(self, size):
        self.__historyLength = size
        self.resetHistory()
    
    def resetHistory(self):
        self.__history = array.array('B')
        self.__history.fromlist([0] * self.__historyLength)
        self.__historyOffset = 0

    def append_bytes(self, data):
        for byte in data:
            self.append_byte(byte)

    def append_byte(self, byte):
        self.__history[self.__historyOffset] = byte
        self.__historyOffset += 1
    
    def get_bytes(self, offset_from_end, length, relative=True):
        if relative:
            offset = self.__historyOffset - offset_from_end
        else:
            offset = offset_from_end
        return memoryview(self.__history)[offset : offset + length]
    
    def append_and_find_matches(self, data):
        raise NotImplementedError()

class RollingHash(object):
    DEFAULT_MODULO = 2**31 - 1 # prime number less than 2*32 so that all of the math is guaranteed to fit in 64-bit registers (prime taken from https://primes.utm.edu/lists/2small/0bit.html  )
    DEFAULT_BASE = 256 # = 2**8 since we are using 8-bit bytes as the character size, so each value is in this base
    #DEFAULT_BASE_MULTIPLICAIVE_INVERSE = 8388608 # = pow(256, -1, 2**31-1) # this is only needed if the rolling window size can be changed, but since this only supports a constant window size it is not needed. see https://youtu.be/w6nuXg0BISo?t=2116    .

    # @classmethod
    # def _calculate_hash(cls, s, multiplier, modulo):
    #     res = 0
    #     for i, c in enumerate(s):
    #         res += ord(c) * multiplier**(len(s) - 1 - i)
    #         res = res % modulo
    #     return res

    def __init__(self, size,
                 multiplier=DEFAULT_BASE,
                 modulo=DEFAULT_MODULO):
        self._base = multiplier
        self._mod_p = modulo
        self._hash = 0
        self._window_content = collections.deque([0] * size, maxlen=size)
        self._magic = (self._base ** (size-1)) % self._mod_p
        self._make_positive_mod_p = self._mod_p * self._base
        # for c in initial_input:
        #     self.roll(c)

    @property
    def window_content(self):
        return ''.join(self._window_content)

    @property
    def hash(self):
        return self._hash

    def roll(self, incomming_byte):
        outgoing_byte = self._window_content.popleft()
        self._window_content.append(incomming_byte)
        
        self._hash = self._hash - outgoing_byte * self._magic + self._make_positive_mod_p
        self._hash = self._hash * self._base + incomming_byte
        self._hash %= self._mod_p
        return self._hash

MatchInfo = collections.namedtuple('MatchInfo', ['history_position', 'input_position', 'length'])

class RabinKarpStringMatcher(object):
    def __init__(self, data = b''):
        self.__min_match_size = 10
        
        self.__historyLength = 8196
        self.__history = array.array('B')
        self.__history.fromlist([0] * self.__historyLength)
        self.__historyOffset = 0
        self.__historyRollingHash = RollingHash(size = self.__min_match_size)
        self.__historyEndPositionByHash = {}
        self.__sortedHistoryEndPositionByHash = {}

    def __pushByteToHistory(self, byte):
        self.__history[self.__historyOffset] = byte
        self.__incrementHistoryOffset()
        hash = self.__historyRollingHash.roll(byte)
        if self.__historyOffset >= self.__min_match_size:
            self.__sortedHistoryEndPositionByHash.setdefault(hash, collections.OrderedDict())[self.__historyOffset] = True
        
        
    def __experimental_findAllInHistory(self):
        retval = []
        sortedHistoryEndPositionsByMatchingInputEndPosition = {}
        if self.__inLength < self.__min_match_size:
            return retval
        input_rolling_hash = RollingHash(size = self.__min_match_size)
        for i in range(self.__min_match_size - 1):
            input_rolling_hash.roll(self.__in[i])
        i = self.__min_match_size
        while i < self.__inLength:
            hash = input_rolling_hash.roll(self.__in[i])
            if hash in self.__historyEndPositionByHash:
                sortedHistoryEndPositionsByMatchingInputEndPosition[i] = self.__sortedHistoryEndPositionByHash[hash]
            i += 1
            
        i = self.__min_match_size
        while i < self.__inLength:
            if i in sortedHistoryEndPositionsByMatchingInputEndPosition:
                match = self.__max_possible_match_len_starting_from(sortedHistoryEndPositionsByMatchingInputPosition, i - self.__min_match_size)
                if match:
                    retval.append(match)
                    i += match.length
            else:        
                i += 1
        return retval
    
    def __max_possible_match_len_starting_from(sortedHistoryEndPositionsByMatchingInputPosition, in_start_pos):
        max_match_len = -1
        max_match_his_start_pos = -1
        for his_pos_end in sortedHistoryEndPositionsByMatchingInputPosition[in_start_pos]:
            his_pos_start = his_pos_end - self.__min_match_size
            check_length_of_match = False
            if max_match_len == -1:
                check_length_of_match = True
            
            else:
                # check if the blocks of the new potential match is longer than the original by a chunk size
                # we use the chunk size as the increment to avoid recomputing the match for small increases in the max_match_length
                in_position = in_start_pos + max_match_len + self.__min_match_size
                history_position = his_pos_start + max_match_len + self.__min_match_size
                if history_position in historyEndPositionsByMatchingInputPosition.get(in_position, []):
                    check_length_of_match = True

            if check_length_of_match:
                in_position = in_start_pos
                history_position = his_pos_start
                # the match is only valid if the history position is before the current input position in the history buffer (ie. it must be a back reference) 
                if history_position < self.__historyOffset - self.__inLength + in_position:
                    while ((in_position < self.__inLength)
                        and (self.__in[in_position] == self.__history[history_position])):
                        in_position += 1
                        history_position += 1
                    
                    diff = in_start_pos - in_position
                    if diff > self.__min_match_size and diff > max_match_len:
                        max_match_len = diff
                        max_match_his_start_pos = his_pos_start
                        if in_position == self.__inLength:
                            # since we started from a fixed input position once we reach the end of the input buffer, then we know that there cannot be a longer match, so we can exit early
                            break
        
        if max_match_len > self.__min_match_size:
            return MatchInfo(max_match_his_start_pos, in_start_pos, max_match_len)
        else:
            return None
            