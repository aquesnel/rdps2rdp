
import contextlib
import enum
import struct
from typing import Any, Sequence, Callable, TypeVar, Generic, Set, Tuple

import utils

FIELD_VALUE_TYPE = TypeVar('FIELD_VALUE_TYPE')
VALUE_RESULT_TYPE = TypeVar('VALUE_RESULT_TYPE')
SERIALIZED_TYPE = TypeVar('SERIALIZED_TYPE')
DESERIALIZED_TYPE = TypeVar('DESERIALIZED_TYPE')

UINT_8  = '<B'
SINT_8  = '<b'
UINT_16_BE = '>H'
UINT_16_LE = '<H'
SINT_16_LE = '<h'
UINT_32_LE = '<I'
UINT_64_LE = '<Q'
PAD = 'x'
STRING_WITH_LENGTH = '%ds'
            
class LengthDependency(object):
    def __init__(self, length_getter: Callable[[Any], int] = len):
        self._length_getter = length_getter
        
    def get_length(self, value: Any) -> int:
        return self._length_getter(value)

class ValueDependency(Generic[VALUE_RESULT_TYPE]):
    def __init__(self, value_getter: Callable[[Any], VALUE_RESULT_TYPE]):
        self._value_getter = value_getter
        
    def get_value(self, value: Any, serde_context = None):
        return self._value_getter(value)
        
class ValueDependencyWithContext(Generic[VALUE_RESULT_TYPE]):
    def __init__(self, value_getter: Callable[[Any, Any], VALUE_RESULT_TYPE]):
        self._value_getter = value_getter
        
    def get_value(self, value: Any, serde_context):
        return self._value_getter(value, serde_context)
        
class ValueDependencyWithSideEffect(Generic[VALUE_RESULT_TYPE]):
    def __init__(self, value_getter: Callable[[Any, Any], VALUE_RESULT_TYPE]):
        self._value_getter = value_getter
        self._call_count = 0
        
    def get_value_with_side_effect(self, value: Any, serde_context):
        if self._call_count > 0:
            raise AssertionError("get_value_with_side_effect can only be called once")
        self._call_count += 1
        return self._value_getter(value, serde_context)

class ValueTransformer(Generic[SERIALIZED_TYPE, DESERIALIZED_TYPE]):
    def __init__(self, to_serialized: Callable[[DESERIALIZED_TYPE], SERIALIZED_TYPE], from_serialized: Callable[[SERIALIZED_TYPE], DESERIALIZED_TYPE]):
        self._to_serialized = to_serialized
        self._from_serialized = from_serialized
        
    def to_serializable_value(self, value: DESERIALIZED_TYPE) -> SERIALIZED_TYPE:
        return self._to_serialized(value)
    
    def from_serializable_value(self, serialized_value: SERIALIZED_TYPE) -> DESERIALIZED_TYPE:
        return self._from_serialized(serialized_value)


class SerializationException(Exception):
    pass

class SerializationContext(object):
    @enum.unique
    class Operation(enum.Enum):
        SERIALIZE = 'Serialize'
        DESERIALIZE = 'Deserialize'

    def __init__(self, operation: Operation):
        self._operation = operation
        self._debug_field_path = []
        self._force_dirty = False
        self._rdp_context = None
        self._print_debug = False
        
    def get_operation(self):
        return self._operation

    def get_allow_partial_parsing(self):
        if self._rdp_context:
            return self._rdp_context.allow_partial_parsing
        else:
            False

    @contextlib.contextmanager
    def field_context(self, field):
        self._debug_field_path.append(field)
        try:
            yield self
        finally:
            self._debug_field_path.pop()
            
    def get_debug_field_path(self):
        return '.'.join([f.name for f in self._debug_field_path])

    @contextlib.contextmanager
    def dirty_context(self, force_is_dirty):
        orig_force_is_dirty = self._force_dirty
        if force_is_dirty is not None:
            self._force_dirty = force_is_dirty
        try:
            yield self
        finally:
            self._force_dirty = orig_force_is_dirty

    def get_force_is_dirty(self):
        return self._force_dirty

    @contextlib.contextmanager
    def rdp_context(self, rdp_context):
        # HACK: inverted import dependency, so we import locally to avoid cycles
        import parser_v2_context
        if rdp_context is not None and not isinstance(rdp_context, parser_v2_context.RdpContext):
            raise ValueError('Expected an RdpContext, but got %s' % (rdp_context.__class__.__name__ if rdp_context else rdp_context))
        orig_rdp_context = self._rdp_context
        self._rdp_context = rdp_context
        try:
            yield self
        finally:
            self._rdp_context = orig_rdp_context

    def get_rdp_context(self):
        return self._rdp_context


    def is_debug_enabled(self, debug_override = False):
        if debug_override:
            return True
        if self._rdp_context is None:
            return False
        return self._rdp_context.parser_config.is_debug_enabled(self.get_debug_field_path())

    def get_compression_enabled(self):
        return self._rdp_context.compression_enabled

class BaseSerializer(Generic[FIELD_VALUE_TYPE]):
    """
    Serialization/deserialization unit for a value. Can be a single unnamed value, or a structure with named values.
    """
    # def get_length(self, value: FIELD_VALUE_TYPE) -> int:
    #     raise NotImplementedError()
    
    def get_serialized_length(self, value: FIELD_VALUE_TYPE) -> int:
        raise NotImplementedError()
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[FIELD_VALUE_TYPE, int]:
        raise NotImplementedError()
    
    def pack_into(self, buffer: bytes, offset: int, value: FIELD_VALUE_TYPE, serde_context: SerializationContext) -> int:
        raise NotImplementedError()

class StaticSerializer(BaseSerializer[FIELD_VALUE_TYPE]):
    def __init__(self, static_value: FIELD_VALUE_TYPE):
        self._static_value = static_value
    
    def get_serialized_length(self, value: FIELD_VALUE_TYPE) -> int:
        return len(self._static_value)
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[FIELD_VALUE_TYPE, int]:
        return self._static_value, self.get_serialized_length(self._static_value)
    
    def pack_into(self, buffer: bytes, offset: int, value: FIELD_VALUE_TYPE, serde_context: SerializationContext) -> int:
        length = len(self._static_value)
        buffer[offset : offset + length] = self._static_value
        return length

class StructEncodedSerializer(BaseSerializer[int]):
    def __init__(self, struct_format: str):
        self._struct = struct.Struct(struct_format)
    
    def get_serialized_length(self, value: int) -> int:
        return self._struct.size
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        value = self._struct.unpack_from(raw_data, offset)
        length = self.get_serialized_length(value)
        if len(value) == 0:
            return None, length
        elif len(value) == 1:
            return value[0], length
        else:
            raise ValueError('unexpected number of values unpacked')
    
    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> int:
        if value is not None:
            self._struct.pack_into(buffer, offset, value)
        return self.get_serialized_length(value)

class VariableLengthIntSerializer(BaseSerializer[int]):
    FORMAT_BY_LENGTH = {
        1: struct.Struct(UINT_8),
        2: struct.Struct(UINT_16_LE),
        4: struct.Struct(UINT_32_LE),
    }
    
    def __init__(self, int_length_dependency: LengthDependency):
        self._int_length_dependency = int_length_dependency
    
    def _get_struct_format(self):
        length = self._int_length_dependency.get_length(None)
        if length not in self.FORMAT_BY_LENGTH:
            raise ValueError('Invalid length value. Expected one of %s, received %d' % (self.FORMAT_BY_LENGTH.keys(), length))
        return self.FORMAT_BY_LENGTH[length]
    
    def get_serialized_length(self, value: int) -> int:
        return self._get_struct_format().size
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        struct_format = self._get_struct_format()
        length = struct_format.size
        value = struct_format.unpack_from(raw_data, offset)
        if len(value) == 0:
            return None, length
        elif len(value) == 1:
            return value[0], length
        else:
            raise ValueError('unexpected number of values unpacked')
    
    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> int:
        struct_format = self._get_struct_format()
        length = struct_format.size
        max_value = 256 ** length
        if value >= max_value:
            raise ValueError('Value is too big for this field. Field length %d (max value: %d), received value %d' % (length, max_value, value))
        if value is not None:
            struct_format.pack_into(buffer, offset, value)
        return length
    
class EncodedStringSerializer(BaseSerializer[str]):
    UTF_16_LE = 'utf-16-le'
    ASCII = 'ascii'
    WINDOWS_1252 = 'cp1252'
    LATIN_1 = 'iso-8859-1'
    SUPPORTED_ENCODINGS = {ASCII, UTF_16_LE, WINDOWS_1252, LATIN_1}
    def __init__(self, encoding, 
            length_dependency = None,
            delimiter_dependency = None,
            include_delimiter_in_length = True):
        self._encoding = encoding
        if self._encoding not in self.SUPPORTED_ENCODINGS:
            raise ValueError('Unsupported Encoding: %s' % self._encoding)
        if length_dependency is None:
            length_dependency = LengthDependency()
        self._length_dependency = length_dependency
        self._delimiter_dependency = delimiter_dependency
        self._include_delimiter_in_length = include_delimiter_in_length
    
    def get_serialized_length(self, value: str) -> int:
        delimiter = ''
        if self._include_delimiter_in_length and self._delimiter_dependency:
            delimiter = self._delimiter_dependency.get_value(None)
        
        if self._encoding == self.UTF_16_LE:
            return 2 * (len(value) + len(delimiter))
        elif self._encoding == self.ASCII:
            return len(value) + len(delimiter)
        else:
            raise ValueError('Unsupported Encoding: %s' % self._encoding)
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[str, int]:
        max_length = self._length_dependency.get_length(raw_data[offset:])
        s = bytes(raw_data[offset : offset+max_length]).decode(self._encoding, errors = 'replace')
        if self._delimiter_dependency:
            delimiter = self._delimiter_dependency.get_value(None)
            end_of_string_index = s.find(delimiter)
            if end_of_string_index >= 0:
                s = s[:end_of_string_index]
        consumed_length = self.get_serialized_length(s)
        return s, consumed_length
    
    def pack_into(self, buffer: bytes, offset: int, value: str, serde_context: SerializationContext) -> int:
        length = self.get_serialized_length(value)
        if self._include_delimiter_in_length and self._delimiter_dependency:
            delimiter = self._delimiter_dependency.get_value(None)
            value += delimiter
        buffer[offset : offset+length] = value.encode(self._encoding)
        return length
        
class FixedLengthEncodedStringSerializer(EncodedStringSerializer):
    def __init__(self, encoding, length,
            delimiter_dependency = ValueDependency(lambda x: '\x00'),
            include_delimiter_in_length = False):
        super().__init__(encoding,
                length_dependency = LengthDependency(lambda x: length),
                delimiter_dependency = delimiter_dependency,
                include_delimiter_in_length = include_delimiter_in_length)
    
    def get_serialized_length(self, value: str) -> int:
        return self._length_dependency.get_length(value)
        
    def pack_into(self, buffer: bytes, offset: int, value: str, serde_context: SerializationContext) -> int:
        length = self.get_serialized_length(value)
        buffer[offset : offset+length] = b'\x00' * length
        super().pack_into(buffer, offset, value, serde_context)
        return length

class DelimitedEncodedStringSerializer(EncodedStringSerializer):
    def __init__(self, encoding, delimiter):
        super().__init__(encoding, delimiter_dependency = ValueDependency(lambda x: delimiter))

    def get_serialized_length(self, value: str) -> int:
        delimiter = self._delimiter_dependency.get_value(None)
        end_of_string_index = value.find(delimiter)
        if end_of_string_index >= 0:
            return end_of_string_index + len(delimiter)
        return len(value) + len(delimiter)

class Utf16leEncodedStringSerializer(EncodedStringSerializer):
    def __init__(self, length_dependency = None, delimiter = '\x00'):
        super().__init__(EncodedStringSerializer.UTF_16_LE,
                length_dependency,
                delimiter_dependency = ValueDependency(lambda x: delimiter) if delimiter is not None else None,
                include_delimiter_in_length = True)
        
class FixedLengthUtf16leEncodedStringSerializer(FixedLengthEncodedStringSerializer):
    def __init__(self, length):
        super().__init__(EncodedStringSerializer.UTF_16_LE, length)

        
class ArraySerializer(BaseSerializer[Sequence[Any]]):
    def __init__(self, item_serializer: BaseSerializer[Any], 
            length_dependency = None,
            item_count_dependency = None):
        self._item_serializer = item_serializer
        if ((length_dependency is None and item_count_dependency is None)
                or (length_dependency is not None and item_count_dependency is not None)):
            raise ValueError('Only one of length_dependency or item_count_dependency must be specified. length_dependency = %s, item_count_dependency = %s' % (
                length_dependency, item_count_dependency))
        
        self._length_dependency = length_dependency
        self._item_count_dependency = item_count_dependency
    
    def get_serialized_length(self, value: Sequence[Any]) -> int:
        return sum(self._item_serializer.get_serialized_length(v) for v in value)
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[Sequence[Any], int]:
        result = []
        consumed = 0
        
        if self._length_dependency:
            length = self._length_dependency.get_length(raw_data)
            has_more_items = lambda: consumed < length
        elif self._item_count_dependency:
            max_items = self._item_count_dependency.get_value(None)
            has_more_items = lambda: len(result) < max_items
            
        while has_more_items():
            item, item_length = self._item_serializer.unpack_from(raw_data, offset + consumed, serde_context)
            result.append(item)
            utils.assertEqual(item_length, self._item_serializer.get_serialized_length(item))
            consumed += item_length

        return result, consumed

    def pack_into(self, buffer: bytes, offset: int, value: Sequence[Any], serde_context: SerializationContext) -> int:
        orig_offset = offset
        for item in value:
            item_length = self._item_serializer.pack_into(buffer, offset, item, serde_context)
            # item_length = self._item_serializer.get_serialized_length(item)
            offset += item_length
        return offset - orig_offset

class BitFieldEncodedSerializer(BaseSerializer[Sequence[int]]):
    def __init__(self, struct_format: str, allowed_bits: Set[int]):
        self._struct_serializer = StructEncodedSerializer(struct_format)
        self._allowed_bits = allowed_bits
    
    def get_serialized_length(self, value: Sequence[int]) -> int:
        return self._struct_serializer.get_serialized_length(value)
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        value, length = self._struct_serializer.unpack_from(raw_data, offset, serde_context)
        result = set()
        for bit_mask in self._allowed_bits:
            if bit_mask & value:
                result.add(bit_mask)
            elif bit_mask == 0:
                result.add(bit_mask)
        utils.assertEqual(length, self.get_serialized_length(result))
        return result, length
    
    def pack_into(self, buffer: bytes, offset: int, value: Sequence[Any], serde_context: SerializationContext) -> int:
        bit_flags = 0
        for bit_mask in value:
            bit_flags |= bit_mask
        return self._struct_serializer.pack_into(buffer, offset, bit_flags, serde_context)

class BitMaskSerializer(BaseSerializer[int]):
    def __init__(self, bit_mask: int, int_serializer: BaseSerializer[int]):
        self._int_serializer = int_serializer
        self._bit_mask = bit_mask
    
    def get_serialized_length(self, value: Sequence[int]) -> int:
        return self._int_serializer.get_serialized_length(value)
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        value, length = self._int_serializer.unpack_from(raw_data, offset, serde_context)
        masked_value = (self._bit_mask & value)
        utils.assertEqual(length, self.get_serialized_length(masked_value))
        return masked_value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: Sequence[Any], serde_context: SerializationContext) -> int:
        masked_value = self._bit_mask & value
        return self._int_serializer.pack_into(buffer, offset, masked_value, serde_context)

class ValueTransformSerializer(BaseSerializer[DESERIALIZED_TYPE]):
    def __init__(self, inner_serializer: BaseSerializer[SERIALIZED_TYPE], transform: ValueTransformer[SERIALIZED_TYPE, DESERIALIZED_TYPE]):
        self._inner_serializer = inner_serializer
        self._transform = transform
    
    def get_serialized_length(self, value: DESERIALIZED_TYPE) -> int:
        return self._inner_serializer.get_serialized_length(self._transform.to_serializable_value(value))
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[DESERIALIZED_TYPE, int]:
        value, length = self._inner_serializer.unpack_from(raw_data, offset, serde_context)
        transformed_value = self._transform.from_serializable_value(value)
        utils.assertEqual(length, self.get_serialized_length(transformed_value))
        return transformed_value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: DESERIALIZED_TYPE, serde_context: SerializationContext) -> int:
        transformed_value = self._transform.to_serializable_value(value)
        return self._inner_serializer.pack_into(buffer, offset, transformed_value, serde_context)

# BASE_DATA_UNIT = TypeVar('BASE_DATA_UNIT')
# class DataUnitSerializer(BaseSerializer[BASE_DATA_UNIT]):
#     def __init__(self, data_unit_factory):
#         self._data_unit_factory = data_unit_factory
    
#     def get_serialized_length(self, value: BASE_DATA_UNIT) -> int:
#         return len(value)
        
#     def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[BASE_DATA_UNIT, int]:
#         data_unit = self._data_unit_factory()
#         length = data_unit.deserialize_value(raw_data, offset)
#         utils.assertEqual(length, self.get_serialized_length(data_unit))
#         return data_unit, length

#     def pack_into(self, buffer: bytes, offset: int, value: BASE_DATA_UNIT, serde_context: SerializationContext) -> int:
#         return value.serialize_value(buffer, offset)

class BerEncodedLengthSerializer(BaseSerializer[int]):
    def __init__(self):
        pass
    
    def get_serialized_length(self, value: int) -> int:
        if value < 0x80:
            return 1
        else:
            length = 1
            while value > 0:
                value >>= 8
                length += 1
            return length
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        payload_length = raw_data[offset]
        length_length = 1
        if (payload_length & 0x80 == 0x80):
            length_length = payload_length & 0x7f
            payload_length = 0
            for j in range(length_length):
                payload_length <<= 8
                payload_length += raw_data[offset + 1 + j]
            length_length += 1
        utils.assertEqual(length_length, self.get_serialized_length(payload_length))
        return payload_length, length_length
    
    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> int:
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
            return 1
        else:
            value_bytes = []
            while value > 0:
                value_bytes.append(value & 0xff)
                value >>= 8
            struct.pack_into(UINT_8, buffer, offset, len(value_bytes) | 0x80)
            i = 1
            for b in reversed(value_bytes):
                struct.pack_into(UINT_8, buffer, offset + i, b)
                i += 1
            return i

class BerEncodedBooleanSerializer(BaseSerializer[bool]):
    def __init__(self):
        pass
    
    def get_serialized_length(self, value: int) -> int:
        return 1
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[bool, int]:
        if raw_data[offset]:
            return True, 1
        else:
            return False, 1

    def pack_into(self, buffer: bytes, offset: int, value: bool, serde_context: SerializationContext) -> int:
        if value:
            i = 0xff
        else:
            i = 0x00
        struct.pack_into(UINT_8, buffer, offset, i)
        return 1

class BerEncodedIntegerSerializer(BaseSerializer[int]):
    def __init__(self, length_dependency):
        self._length_dependency = length_dependency
    
    def get_serialized_length(self, value: int) -> int:
        return len(self._encode(value))
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        length = self._length_dependency.get_length(None)
        offset_end = offset + length
        value = 0
        while offset < offset_end:
            value <<= 8
            value += raw_data[offset]
            offset += 1
        utils.assertEqual(length, self.get_serialized_length(value))
        return value, length

    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> int:
        encoded_value = self._encode(value)
        length = len(encoded_value)
        buffer[offset : offset+length] = encoded_value
        return length
    
    def _encode(self, value) -> bytes:
        byte_list_LE = []
        
        # always consume the first byte of the value even if it is zero
        byte_list_LE.append(value & 0xff)
        value >>= 8
        while value > 0:
            byte_list_LE.append(value & 0xff)
            value >>= 8
        
        offset = 0
        byte_list_BE = list(reversed(byte_list_LE))
        # according to ITU-T X.690 section 8.3.2, the first byte and highest bit of the second byte can't all be 1's
        if (len(byte_list_BE) > 1 
                and (byte_list_BE[0] == 0xff) 
                and (byte_list_BE[1] & 0x80) == 0x80):
            buffer = bytearray(len(byte_list_BE) + 1)
            buffer[offset] = 0x00
            offset += 1
        else:
            buffer = bytearray(len(byte_list_BE))
        
        for b in byte_list_BE:
            buffer[offset] = b
            offset += 1
        return buffer

class PerEncodedLengthSerializer(BaseSerializer[int]):
    RANGE_0_127 = '<range:0..127>'
    RANGE_0_64K = '<range:0..64K>'
    RANGE_VALUE_DEFINED = '<range:value_defined>'
    
    def __init__(self, range):
        self._range = range

    def get_serialized_length(self, value: int) -> int:
        length = None
        if self._range == self.RANGE_0_127:
            length = 1
        if self._range == self.RANGE_0_64K:
            length = 2
        elif self._range == self.RANGE_VALUE_DEFINED:
            if value < 0x80:
                length = 1
            else:
                length = 2
        
        if ((length == 1 and value >= 0x80)
                or (length == 2 and value >= 2**14)):
            raise ValueError('value too large for range %s: %d' % (self._range, value))
        return length

    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
        length = 1
        value = raw_data[offset]
        if (self._range in { self.RANGE_0_64K, self.RANGE_VALUE_DEFINED }
                and value & 0xC0 == 0x80): # see https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_mcs.c#L222
            value &= 0x3f
            value <<= 8
            value += raw_data[offset + 1]
            length += 1
        # utils.assertEqual(length, self.get_serialized_length(value))
        return value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> int:
        length_length = self.get_serialized_length(value, range = self._range)
        print('packing length %s' % length_length)
        if length_length == 1:
            struct.pack_into(UINT_8, buffer, offset, value)
        elif length_length == 2:
            struct.pack_into(UINT_8, buffer, offset + 1, value & 0xff)
            struct.pack_into(UINT_8, buffer, offset, (value >> 8) | 0x80)
        else:
            raise ValueError('Unsupported length %d' % length_length)
        return length_length

class RawLengthSerializer(BaseSerializer[bytes]):
    def __init__(self, length_dependency = None):
        self._length_dependency = length_dependency
        
    def get_serialized_length(self, value: bytes) -> int:
        if self._length_dependency is None:
            return len(value)
        return self._length_dependency.get_length(value)

    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[bytes, int]:
        max_length = self.get_serialized_length(raw_data)
        value = raw_data[offset : offset + max_length]
        # utils.assertEqual(length, self.get_serialized_length(value))
        if self._length_dependency is None:
            if max_length < len(value):
                raise ValueError('RawLengthSerializer unpacked value with max length %d but got value with length %d' % (max_length, len(value)))
        else:
            if max_length != len(value):
                raise ValueError('RawLengthSerializer unpacked value with expected length %d but got value with length %d' % (max_length, len(value)))
        return value, len(value)
    
    def pack_into(self, buffer: bytes, offset: int, value: bytes, serde_context: SerializationContext) -> int:
        length = self.get_serialized_length(value)
        buffer[offset : offset + length] = value[:length]
        return length

class DependentValueSerializer(BaseSerializer):
    def __init__(self, serializer, dependency):
        self._serializer = serializer
        self._dependency = dependency
        
    def get_serialized_length(self, value):
        return self._serializer.get_serialized_length(value)
        
    def unpack_from(self, raw_data, offset, serde_context: SerializationContext) -> Tuple[Any, int]:
        return self._serializer.unpack_from(raw_data, offset, serde_context)
    
    def pack_into(self, buffer, offset, value, serde_context: SerializationContext) -> int:
        dependent_value = self._dependency.get_value(value, serde_context)
        return self._serializer.pack_into(buffer, offset, dependent_value, serde_context)

# class CompressionSerializer(BaseSerializer):
#     def __init__(self, compression_id: ValueDependency, compression_flags: ValueDependency):
#         self._compression_id = compression_id
#         self._compression_flags = compression_flags
        
#     def get_serialized_length(self, value):
#         raise NotImplementedError("TODO")
#         return self._serializer.get_serialized_length(value)
        
#     def unpack_from(self, raw_data, offset, serde_context: SerializationContext) -> Tuple[Any, int]:
#         engine = serde_context.get_rdp_context().get_compression_engine(*self._compression_id.get_value())
#         inflated = engine.decompress(CompressionArgs(data = memoryview(raw_data)[offset:], flags = self._compression_flags.get_value()))
#         return inflated, (len(raw_data) - offset)
    
#     def pack_into(self, buffer, offset, value, serde_context: SerializationContext) -> int:
#         engine = serde_context.get_rdp_context().get_compression_engine(*self._compression_id.get_value())
#         deflated = engine.compress(value)
#         length = len(deflated)
#         buffer[offset : offset + length] = deflated.data
        
#         raise NotImplementedError("TODO: return the compression flags")
#         return length


