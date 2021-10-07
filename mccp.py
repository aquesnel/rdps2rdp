#!/usr/bin/python3
#
# Copied from: https://github.com/parc-ccnx-archive/CCNxz/blob/master/mppc.py


# Implemented from RFC2118 and licensed as a code component
#
# Copyright (c) 1997 IETF Trust and the persons identified as authors of the code.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# .  Redistributions of source code must retain the above copyright notice, this list of conditions and the
#    following disclaimer.
#
# .  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#
# .  Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific contributors, may be used
#    to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# Implements the Microsoft Point-to-Point Compression (MPPC) protocol
# RFC 2118
#
# __author__ = 'mmosko'
#
# #######
# History size:
#    8192 bytes
#
# Packet format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         PPP Protocol          |A|B|C|D| Coherency Count       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |        Compressed Data...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# A Bit : history initialize
# B Bit: Set history pointer to front of buffer
# C Bit: Packet is compressed (1)
# D Bit: unused (must be 0)
#
# Coherency counter:
#   monotonically increasing counter with wrap-around to 0
#
# Unlike RFC 2118 we do not include the Protocol field at the start
# of the compressed data, we just begin with the CCNx packet.
#
########
# Because we are not running inside PPP, we will use this packet format:
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |A|B|C|      zeros (13)         |        Coherency Count        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |        Compressed Data...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# N.B.:
#   If the output becomes larger than the input, the program currently
#   crashes with something like:
#       File "./mppc.py", line 159, in __encode7bitLiteral
#         self.__out[byte_offset+1] |= lowerbyte
#     IndexError: array index out of range
#

import array
import binascii
import struct
import sys
import collections
import bisect
import enum

DEBUG = False

EncodingConfig = collections.namedtuple('EncodingConfig', ['min_value', 'prefix', 'value_bit_length'])
CompressionConfig = collections.namedtuple('CompressionConfig', ['history_size', 'offset_encoding', 'length_encoding'])

class MCCP(object):
    # Used as bit patterns in Offset Encoding (RFC Sec 4.2.1)
    __offset_pattern_64  = 0b1111
    __offset_pattern_320 = 0b1110
    __offset_pattern_8191 = 0b110

    __length_pattern_3    = 0b0
    __length_pattern_8    = 0b10
    __length_pattern_16   = 0b110
    __length_pattern_32   = 0b1110
    __length_pattern_64   = 0b11110
    __length_pattern_128  = 0b111110
    __length_pattern_256  = 0b1111110
    __length_pattern_512  = 0b11111110
    __length_pattern_1024 = 0b111111110
    __length_pattern_2048 = 0b1111111110
    __length_pattern_4096 = 0b11111111110
    __length_pattern_8192 = 0b111111111110

    # config = {
    #     'RDP_4': CompressionConfig(
    #         history_size = 8196,
    #         reset_to_begining = True,
    #         offset_cache_size = 0,
    #         offset_encoding = [
    #                 EncodingConfig(min_value = 0,   value_bit_length =  6, prefix = 0b1111),
    #                 EncodingConfig(min_value = 64,  value_bit_length =  8, prefix = 0b1110),
    #                 EncodingConfig(min_value = 320, value_bit_length = 13, prefix =  0b110),
    #             ],
    #         length_encoding = [
    #                 EncodingConfig(min_value =     3, value_bit_length =  0, prefix = 0b0),
    #                 EncodingConfig(min_value =     4, value_bit_length =  2, prefix = 0b10),
    #                 EncodingConfig(min_value =     8, value_bit_length =  3, prefix = 0b110),
    #                 EncodingConfig(min_value =    16, value_bit_length =  4, prefix = 0b1110),
    #                 EncodingConfig(min_value =    32, value_bit_length =  5, prefix = 0b11110),
    #                 EncodingConfig(min_value =    64, value_bit_length =  6, prefix = 0b111110),
    #                 EncodingConfig(min_value =   128, value_bit_length =  7, prefix = 0b1111110),
    #                 EncodingConfig(min_value =   256, value_bit_length =  8, prefix = 0b11111110),
    #                 EncodingConfig(min_value =   512, value_bit_length =  9, prefix = 0b111111110),
    #                 EncodingConfig(min_value =  1024, value_bit_length = 10, prefix = 0b1111111110),
    #                 EncodingConfig(min_value =  2048, value_bit_length = 11, prefix = 0b11111111110),
    #                 EncodingConfig(min_value =  4096, value_bit_length = 12, prefix = 0b111111111110),
    #             ],
    #     ),
    #     'RDP_5': CompressionConfig(
    #         history_size = 65536,
    #         reset_to_begining = True,
    #         offset_cache_size = 0,
    #         offset_encoding = [
    #                 EncodingConfig(min_value = 0,    value_bit_length =  6, prefix = 0b11111),
    #                 EncodingConfig(min_value = 64,   value_bit_length =  8, prefix = 0b11110),
    #                 EncodingConfig(min_value = 320,  value_bit_length = 11, prefix =  0b1110),
    #                 EncodingConfig(min_value = 2368, value_bit_length = 16, prefix =   0b110),
    #             ],
    #         length_encoding = [
    #                 EncodingConfig(min_value =     3, value_bit_length =  0, prefix = 0b0),
    #                 EncodingConfig(min_value =     4, value_bit_length =  2, prefix = 0b10),
    #                 EncodingConfig(min_value =     8, value_bit_length =  3, prefix = 0b110),
    #                 EncodingConfig(min_value =    16, value_bit_length =  4, prefix = 0b1110),
    #                 EncodingConfig(min_value =    32, value_bit_length =  5, prefix = 0b11110),
    #                 EncodingConfig(min_value =    64, value_bit_length =  6, prefix = 0b111110),
    #                 EncodingConfig(min_value =   128, value_bit_length =  7, prefix = 0b1111110),
    #                 EncodingConfig(min_value =   256, value_bit_length =  8, prefix = 0b11111110),
    #                 EncodingConfig(min_value =   512, value_bit_length =  9, prefix = 0b111111110),
    #                 EncodingConfig(min_value =  1024, value_bit_length = 10, prefix = 0b1111111110),
    #                 EncodingConfig(min_value =  2048, value_bit_length = 11, prefix = 0b11111111110),
    #                 EncodingConfig(min_value =  4096, value_bit_length = 12, prefix = 0b111111111110),
    #                 EncodingConfig(min_value =  8192, value_bit_length = 13, prefix = 0b1111111111110),
    #                 EncodingConfig(min_value = 16384, value_bit_length = 14, prefix = 0b11111111111110),
    #                 EncodingConfig(min_value = 32768, value_bit_length = 15, prefix = 0b111111111111110),
    #             ],
    #     ),
    #     'RDP_60': CompressionConfig(
    #         history_size = 65536,
    #         reset_to_begining = False,
    #         offset_cache_size = 4,
    #         offset_encoding = [
    #                 EncodingConfig(min_value = 0,    value_bit_length =  6, prefix = 0b11111),
    #                 EncodingConfig(min_value = 64,   value_bit_length =  8, prefix = 0b11110),
    #                 EncodingConfig(min_value = 320,  value_bit_length = 11, prefix =  0b1110),
    #                 EncodingConfig(min_value = 2368, value_bit_length = 16, prefix =   0b110),
    #             ],
    #         length_encoding = [
    #                 EncodingConfig(min_value =     3, value_bit_length =  0, prefix = 0b0),
    #                 EncodingConfig(min_value =     4, value_bit_length =  2, prefix = 0b10),
    #                 EncodingConfig(min_value =     8, value_bit_length =  3, prefix = 0b110),
    #                 EncodingConfig(min_value =    16, value_bit_length =  4, prefix = 0b1110),
    #                 EncodingConfig(min_value =    32, value_bit_length =  5, prefix = 0b11110),
    #                 EncodingConfig(min_value =    64, value_bit_length =  6, prefix = 0b111110),
    #                 EncodingConfig(min_value =   128, value_bit_length =  7, prefix = 0b1111110),
    #                 EncodingConfig(min_value =   256, value_bit_length =  8, prefix = 0b11111110),
    #                 EncodingConfig(min_value =   512, value_bit_length =  9, prefix = 0b111111110),
    #                 EncodingConfig(min_value =  1024, value_bit_length = 10, prefix = 0b1111111110),
    #                 EncodingConfig(min_value =  2048, value_bit_length = 11, prefix = 0b11111111110),
    #                 EncodingConfig(min_value =  4096, value_bit_length = 12, prefix = 0b111111111110),
    #                 EncodingConfig(min_value =  8192, value_bit_length = 13, prefix = 0b1111111111110),
    #                 EncodingConfig(min_value = 16384, value_bit_length = 14, prefix = 0b11111111111110),
    #                 EncodingConfig(min_value = 32768, value_bit_length = 15, prefix = 0b111111111111110),
    #             ],
    #     ),
    # }

    def __init__(self, data = b''):
        self.__min_match_size = 10
        self.resetHistory()
        self.__resetInOut(data)

    def resetHistory(self):
        self.__historyLength = 8196
        self.__history = array.array('B')
        self.__history.fromlist([0] * self.__historyLength)
        self.__historyOffset = 0
        # self.__historyRollingHash = RollingHash(size = self.__min_match_size)
        # self.__historyEndPositionByHash = {}

    def __resetInOut(self, data):
        self.__in = data
        self.__inByteOffset = 0
        self.__inBitOffset = 0
        self.__inLength = len(self.__in)
        self.__out = array.array('B')
        self.__overflowLength = 20
        self.__outLength = max(len(data), self.__historyLength) + self.__overflowLength
        self.__out.fromlist([0] * self.__outLength)
        self.__outBitOffset = 0

    def __findLongestHistory(self):
        '''
            Begining at __inByteOffset, find the longest substring in the
            history that matches it.
            This is an inefficient implementation as it does a linear scan.
            Because the minimum length encoding is 3, we do not match
            any substrings less than 3 bytes long.
            :return: (offset, length) or None
        '''

        istring = self.__in[self.__inByteOffset:] # copyInToHistory
        # istring = self.__history.tobytes()[self.__inByteOffset:self.__inLength]
        longestLen = 0
        longestOffset = 0

        #hstr = self.__history.tobytes() # copyInToHistory
        hstr = self.__history.tobytes()[:self.__historyOffset]
        for iLen in range(3, 1 + len(istring)):
            idx = hstr.rfind(istring[0:iLen])
            if idx > -1:
                # substrings match, so possible hit
                if iLen > longestLen:
                    longestLen = iLen
                    longestOffset = idx
            else:
                # sustrings no longer match, give up on this historyOffset
                # breaks out of iLen loop
                break

        if longestLen > 0:
            if DEBUG: print("Found longest match (off = {}, len = {})".format(longestOffset, longestLen))
            return (longestOffset, longestLen)
        else:
            return (None, None)

    def __getInputByte(self):
        return self.__inBitOffset // 8

    def __getInputBit(self):
        return self.__inBitOffset % 8

    def __getOutputByte(self):
        return self.__outBitOffset // 8

    def __getOutpuBit(self):
        return self.__outBitOffset % 8
        
    def __incrementHistoryOffset(self, lenth = 1):
        self.__historyOffset = (self.__historyOffset + lenth) % self.__historyLength

    def __appendDataToHistory(self, data):
        if self.__historyOffset + len(data) > self.__historyLength:
            raise ValueError("not supported yet")
        for byte in data:
            self.__pushByteToHistory(byte)
        
    def __pushByteToHistory(self, byte):
        self.__history[self.__historyOffset] = byte
        self.__incrementHistoryOffset()
        # hash = self.__historyRollingHash.roll(byte)
        # if self.__historyOffset >= self.__min_match_size:
        #     self.__sortedHistoryEndPositionByHash.setdefault(hash, collections.OrderedDict())[self.__historyOffset] = True
        
    def __pushByteToOutput(self, byte):
        if byte > 0xff:
            raise ValueError("Byte must be less than or equal to 0xff, got: ", hex(byte))
        if DEBUG: print("Push byte to output: %s" % hex(byte))
        self.__out[self.__getOutputByte()] = byte
        self.__outBitOffset += 8

    def __encode7bitLiteral(self, byte):
        if byte >= 0x80:
            raise ValueError("Byte must be less than 0x80, got: ", hex(byte))

        byte_offset = self.__getOutputByte()
        bit_offset = self.__getOutpuBit()

        if bit_offset == 0:
            self.__out[byte_offset] = byte
        else:
            # example:
            #   memory: ab00.0000.0000.0000
            #   bitoffset = 2
            #   data = defg.hijk
            #
            #   upperbyte = defghi
            #   memory: abde.fghi.0000.0000
            #
            #   lowerbyte = jk00.0000
            #   memory: abde.fghi.jk00.0000

            upperbyte = byte >> bit_offset
            self.__out[byte_offset] |= upperbyte

            mask = (1 << bit_offset) - 1
            shift = 8 - bit_offset
            lowerbyte = (byte & mask) << shift
            self.__out[byte_offset+1] |= lowerbyte

            #if DEBUG: print("wrote {}".format(hex(upperbyte << 8 | lowerbyte)))

        self.__outBitOffset += 8

    def __encodeLiteral(self):
        #python2: byte = ord(self.__in[self.__inByteOffset])
        byte = self.__in[self.__inByteOffset] # copyInToHistory
        # byte = self.__history[self.__inByteOffset]
        self.__inByteOffset += 1

        if byte < 0x80:
            self.__encode7bitLiteral(byte)
        else:
            # We need to write a "1" bit, then write the
            # byte as a 7-bit literal

            byte_offset = self.__getOutputByte()
            bit_offset = self.__getOutpuBit()

            upperbyte = 1 << (7 - bit_offset)
            self.__out[byte_offset] |= upperbyte
            self.__outBitOffset += 1

            self.__encode7bitLiteral(byte & 0x7F)

        self.__pushByteToHistory(byte) # copyInToHistory
        # self.__incrementHistoryOffset()

    def __encodebits(self, bits, bit_length):
        bit_offset = self.__getOutpuBit()

        available_bits = 8 - bit_offset
        if bit_length <= available_bits:
            # we can fit the whole thing, shift the bits
            # up so we pack the top of the byte first
            shift = available_bits - bit_length
            x = bits << shift

            byte_offset = self.__getOutputByte()
            self.__out[byte_offset] |= x
            self.__outBitOffset += bit_length

        else:
            # grab 'available_bits' from the top
            shift = bit_length - available_bits
            x = bits >> shift
            self.__encodebits(x, available_bits)

            bit_length -= available_bits
            mask = (1 << bit_length) - 1
            bits &= mask
            self.__encodebits(bits, bit_length)


    def _encodeTupleOffset(self, offset):
        self.__encodeTupleOffset(offset)
        orig = self.__out
        self.__out = array.array('B')
        self.__out.frombytes(orig.tobytes())
        self.__trimOutputBuffer()
        retval = self.__out
        self.__out = orig
        return retval
        
    def __encodeTupleOffset(self, offset):
        if DEBUG: print("encoding CopyTuple offset: %d" % offset)
        if offset < 64:
            # Encoded as '1111' plus lower 6 bits
            self.__encodebits(MCCP.__offset_pattern_64, 4)
            self.__encodebits(offset, 6)

        elif offset < 320:
            # Encoded as '1110' plus lower 8 bits of (value - 64)
            self.__encodebits(MCCP.__offset_pattern_320, 4)
            self.__encodebits(offset - 64, 8)

        else:
            # Encoded as '110' followed by lower 13 bits of (value - 320)
            self.__encodebits(MCCP.__offset_pattern_8191, 3)
            self.__encodebits(offset - 320, 13)

    def __encodeTupleLength(self, length):
        if DEBUG: print("encoding CopyTuple length: %d" % length)
        if length == 3:
            self.__encodebits(MCCP.__length_pattern_3, 1)
        elif length < 8:
            self.__encodebits(MCCP.__length_pattern_8, 2)
            self.__encodebits(length & 0x0003, 2)
        elif length < 16:
            self.__encodebits(MCCP.__length_pattern_16, 3)
            self.__encodebits(length & 0x0007, 3)
        elif length < 32:
            self.__encodebits(MCCP.__length_pattern_32, 4)
            self.__encodebits(length & 0x000F, 4)
        elif length < 64:
            self.__encodebits(MCCP.__length_pattern_64, 5)
            self.__encodebits(length & 0x001F, 5)
        elif length < 128:
            self.__encodebits(MCCP.__length_pattern_128, 6)
            self.__encodebits(length & 0x003F, 6)
        elif length < 256:
            self.__encodebits(MCCP.__length_pattern_256, 7)
            self.__encodebits(length & 0x007F, 7)
        elif length < 512:
            self.__encodebits(MCCP.__length_pattern_512, 8)
            self.__encodebits(length & 0x00FF, 8)
        elif length < 1024:
            self.__encodebits(MCCP.__length_pattern_1024, 9)
            self.__encodebits(length & 0x01FF, 9)
        elif length < 2048:
            self.__encodebits(MCCP.__length_pattern_2048, 10)
            self.__encodebits(length & 0x03FF, 10)
        elif length < 4096:
            self.__encodebits(MCCP.__length_pattern_4096, 11)
            self.__encodebits(length & 0x07FF, 11)
        else:
            self.__encodebits(MCCP.__length_pattern_8192, 12)
            self.__encodebits(length & 0x0FFF, 12)

    def __encodeCopyTuple(self, offset, length):
        self.__encodeTupleOffset(offset)
        self.__encodeTupleLength(length)

         # copyInToHistory
        endOffset = self.__inByteOffset + length
        while self.__inByteOffset < endOffset:
            # python 2: byte = ord(self.__in[self.__inByteOffset])
            byte = self.__in[self.__inByteOffset] # copyInToHistory
            self.__pushByteToHistory(byte)
            self.__inByteOffset += 1
        # self.__inByteOffset += length
        # self.__incrementHistoryOffset(length)

    def __decodebits(self, bits):
        retval = 0
        for bit in (bits):
            retval = retval << 1
            retval += bit
        return retval

    def __decode(self):
        byte_offset = self.__getInputByte()
        bit_offset = self.__getInputBit()
        
        bits = []
        for byte_index in range(byte_offset, min(byte_offset + 5, len(self.__in))): # there can be at most 40 bits (5 bytes) in an encoded literal or CopyTuple 
            byte = self.__in[byte_index]
            for bit_index in reversed(range(0, 8 - bit_offset)):
                bits.append((byte >> bit_index) & 0x1)
            bit_offset = 0
        if DEBUG: print("Processing input byte %d, bit %d, bits: %s" % (byte_offset, self.__getInputBit(), bits))

        consumed_bits = None
        literal_byte = None
        # encoding rules from https://www.ietf.org/rfc/rfc2118.txt section 4.2.1
        if bits[0] == 0: # literal value <= 0x7f with prefix 0b0
            if len(bits) < 8: # padding bits at the end of the stream to align to a byte boundary that can be discarded
                consumed_bits = len(bits)
            else:
                literal_byte = self.__decodebits(bits[0:8])
                consumed_bits = 8
        elif bits[1] == 0: # literal value > 0x7f with prefix 0b10
            literal_byte = self.__decodebits(bits[1:9]) + 128
            consumed_bits = 9
            
        if consumed_bits is not None:
            if literal_byte is not None:
                self.__pushByteToOutput(literal_byte)
                self.__pushByteToHistory(literal_byte)
        else:
            # ecoded copy tuple
            if bits[2] == 0: # CopyTuple offset with prefix 0b110, 13 bit value with 320 offset
                offset = self.__decodebits(bits[3:16]) + 320
                consumed_bits = 16
            elif bits[3] == 0: # CopyTuple offset with prefix 0b1110, 8 bit value with 64 offset
                offset = self.__decodebits(bits[4:12]) + 64
                consumed_bits = 12
            else: # CopyTuple offset with prefix 0b1111, 6 bit value with 0 offset
                offset = self.__decodebits(bits[4:10])
                consumed_bits = 10
            
            if bits[consumed_bits] == 0: # CopyTuple Length-of-Match with prefix 0b0
                length = 3
                consumed_bits += 1
            elif bits[consumed_bits + 1] == 0: # CopyTuple Length-of-Match with prefix 0b10
                length = self.__decodebits(bits[consumed_bits + 2:consumed_bits + 4]) + 4
                consumed_bits += 4
            elif bits[consumed_bits + 2] == 0: # CopyTuple Length-of-Match with prefix 0b110
                length = self.__decodebits(bits[consumed_bits + 3:consumed_bits + 6]) + 8
                consumed_bits += 6
            elif bits[consumed_bits + 3] == 0: # CopyTuple Length-of-Match with prefix 0b1110
                length = self.__decodebits(bits[consumed_bits + 4:consumed_bits + 8]) + 16
                consumed_bits += 8
            elif bits[consumed_bits + 4] == 0: # CopyTuple Length-of-Match with prefix 0b11110
                length = self.__decodebits(bits[consumed_bits + 5:consumed_bits + 10]) + 32
                consumed_bits += 10
            elif bits[consumed_bits + 5] == 0: # CopyTuple Length-of-Match with prefix 0b111110
                length = self.__decodebits(bits[consumed_bits + 6:consumed_bits + 12]) + 64
                consumed_bits += 12
            elif bits[consumed_bits + 6] == 0: # CopyTuple Length-of-Match with prefix 0b1111110
                length = self.__decodebits(bits[consumed_bits + 7:consumed_bits + 14]) + 128
                consumed_bits += 14
            elif bits[consumed_bits + 7] == 0: # CopyTuple Length-of-Match with prefix 0b11111110
                length = self.__decodebits(bits[consumed_bits + 8:consumed_bits + 16]) + 256
                consumed_bits += 16
            elif bits[consumed_bits + 8] == 0: # CopyTuple Length-of-Match with prefix 0b111111110
                length = self.__decodebits(bits[consumed_bits + 9:consumed_bits + 18]) + 512
                consumed_bits += 18
            elif bits[consumed_bits + 9] == 0: # CopyTuple Length-of-Match with prefix 0b1111111110
                length = self.__decodebits(bits[consumed_bits + 10:consumed_bits + 20]) + 1024
                consumed_bits += 20
            elif bits[consumed_bits + 10] == 0: # CopyTuple Length-of-Match with prefix 0b11111111110
                length = self.__decodebits(bits[consumed_bits + 11:consumed_bits + 22]) + 2048
                consumed_bits += 22
            elif bits[consumed_bits + 11] == 0: # CopyTuple Length-of-Match with prefix 0b111111111110
                length = self.__decodebits(bits[consumed_bits + 12:consumed_bits + 24]) + 4096
                consumed_bits += 24
            else:
                raise ValueError("Programming error")
            
            self.__decodeCopyTuple(offset, length)
        self.__inBitOffset += consumed_bits
        if DEBUG: print("Consumed input bits: %d" % (consumed_bits))

    def __decodeCopyTuple(self, offset, length):
        if DEBUG: print("Processing CopyTuple: offset %d, length %d" % (offset, length))
        beginOffset = self.__historyOffset - offset
        for i in range(length):
            byte = self.__history[beginOffset + i]
            self.__pushByteToOutput(byte)
            self.__pushByteToHistory(byte)

    def __addHeader(self, counter):
        A = 0x1000
        B = 0x0000
        C = 0x0000

        struct.pack_into("!HH", self.__out, 0, A | B | C, counter)
        self.__outBitOffset = 32

    def __trimOutputBuffer(self):
        # Trim down to nearest byte

        # Include +1 because we need the length to include the last byte
        last_byte = self.__getOutputByte() + 1
        last_bit = self.__getOutpuBit()
        if last_bit == 0:
            # If the last bit offset is 0, we have not written to the last byte
            last_byte -= 1

        if DEBUG: print("last_byte = {}.{}, len = {}".format(self.__getOutputByte(), last_bit, len(self.__out)))
        while len(self.__out) > last_byte:
            self.__out.pop()

    @property
    def history(self):
        return self.__history

    def compress(self, data):
        self.__resetInOut(data)
        # self.__appendDataToHistory(data)
        # self.__addHeader(0) # removePppHeader
        while self.__inByteOffset < len(self.__in):
            (longestOffset, longestLen) = self.__findLongestHistory()
#            (longestOffset, longestLen) = (None, None)
            if longestOffset is None:
                self.__encodeLiteral()
            else:
                self.__encodeCopyTuple(self.__historyOffset - longestOffset, longestLen)

        self.__trimOutputBuffer()
        return self.__out.tobytes()
        
    def decompress(self, data):
        self.__resetInOut(data)
        while self.__getInputByte() < len(self.__in):
            self.__decode()
        self.__trimOutputBuffer()
        return self.__out.tobytes()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        True
        False
        if False:
            data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
            comp = MCCP()
            out = comp.compress(data)
        
            print("Input len %d Output len %d, ratio %f" % (len(data), len(out), len(out) / len(data)))
            print("intput:   ",binascii.hexlify(data))
            # print("history:  ",binascii.hexlify(comp.history))
            print("output:   ",binascii.hexlify(out))
        
            # expected = b"10000000666f722077686f6d207468652062656c6c20746f6c6c732cf23720f023c9329749a000" # removePppHeader
            # orig expected = b"666f722077686f6d207468652062656c6c20746f6c6c732cf23720f023c9329749a000" # removePppHeader
            expected = b"666f722077686f6d207468652062656c6c20746f6c6c732cf43720fa23d3329749a000"
            # data =   b'666f722077686f6d207468652062656c6c20746f6c6c732c207468652062656c6c20746f6c6c7320666f7220746865652ea680'
            print("expected: ", expected)
            match = True
            if binascii.hexlify(out) != expected:
                match = False
            print("Result: %s" % match)
            
            decomp = MCCP()
            inflated = decomp.decompress(out)
            
            print("Input len %d Output len %d, ratio %f" % (len(out), len(inflated), len(inflated) / len(out)))
            print("intput:     ",binascii.hexlify(out))
            # print("history:    ",binascii.hexlify(decomp.history))
            print("output:     ",binascii.hexlify(inflated))
            print("expected:   ", binascii.hexlify(data))
            print("output raw:   ",inflated)
            print("expected raw: ", data)
            match = True
            if inflated != data:
                match = False
            print("Result: %s" % match)
        
        if False:
            c = MCCP()
            print("offset 16 = %s" % binascii.hexlify(c._encodeTupleOffset(16)))
        
        if True:
            data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
            c = MCCP()
            deflated_1 = c.compress(data)
            deflated_2 = c.compress(data)
            
            s = MCCP()
            inflated_1 = c.decompress(deflated_1)
            inflated_2 = c.decompress(deflated_2)
            
            print("data 1    :     ",binascii.hexlify(data))
            print("deflated 1:     ",binascii.hexlify(deflated_1))
            print("inflated 1:     ",binascii.hexlify(inflated_1))
            
            print("data 2    :     ",binascii.hexlify(data))
            print("deflated 2:     ",binascii.hexlify(deflated_2))
            print("inflated 2:     ",binascii.hexlify(inflated_2))
            
            match = True
            if inflated_1 != data or inflated_2 != data:
                match = False
            print("Result: %s" % match)
        
    else:
        fh = open(sys.argv[1], "rb")
        data = fh.read(65536)
        comp = MCCP(data)
        out = comp.compress(data)
    
        fhout = open("compressed.mccp", "wb")
        fhout.write(out)
    
        print("Input len %d Output len %d, ratio %f" % (len(data), len(out), len(out) / len(data)))
    
        fhout.close()
        fh.close()
