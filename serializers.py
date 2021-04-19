
import struct
from typing import Any, Sequence, Callable, TypeVar, Generic, Set

FIELD_VALUE_TYPE = TypeVar('FIELD_VALUE_TYPE')

UINT_8  = '<B'
UINT_16_BE = '>H'
UINT_16_LE = '<H'
UINT_32_LE = '<I'
PAD = 'x'
STRING_WITH_LENGTH = '%ds'
            
class LengthDependency(object):
    def __init__(self, length_getter = len):
        self._length_getter = length_getter
        
    def get_length(self, value):
        return self._length_getter(value)

class ValueDependency(object):
    def __init__(self, value_getter):
        self._value_getter = value_getter
        
    def get_value(self, value):
        return self._value_getter(value)

class BaseSerializer(Generic[FIELD_VALUE_TYPE]):
    """
    Serialization/deserialization unit for a value. Can be a single unnamed value, or a structure with named values.
    """
    def get_length(self, value: FIELD_VALUE_TYPE) -> int:
        raise NotImplementedError()
        
    def unpack_from(self, raw_data: bytes, offset: int) -> FIELD_VALUE_TYPE:
        raise NotImplementedError()
    
    def pack_into(self, buffer: bytes, offset: int, value: FIELD_VALUE_TYPE) -> None:
        raise NotImplementedError()

class StaticSerializer(BaseSerializer[FIELD_VALUE_TYPE]):
    def __init__(self, static_value: FIELD_VALUE_TYPE):
        self._static_value = static_value
    
    def get_length(self, value: FIELD_VALUE_TYPE) -> int:
        return len(self._static_value)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> FIELD_VALUE_TYPE:
        return self._static_value
    
    def pack_into(self, buffer: bytes, offset: int, value: FIELD_VALUE_TYPE) -> None:
        buffer[offset : offset + len(self._static_value)] = self._static_value

class StructEncodedSerializer(BaseSerializer[int]):
    def __init__(self, struct_format: str):
        self._struct = struct.Struct(struct_format)
    
    def get_length(self, value: int) -> int:
        return self._struct.size
        
    def unpack_from(self, raw_data: bytes, offset: int) -> int:
        value = self._struct.unpack_from(raw_data, offset)
        if len(value) == 0:
            return None
        elif len(value) == 1:
            return value[0]
        else:
            raise ValueError('unexpected number of values unpacked')
    
    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        if value is not None:
            self._struct.pack_into(buffer, offset, value)

class EncodedStringSerializer(BaseSerializer[str]):
    def __init__(self, encoding, 
            length_dependency = LengthDependency(),
            delimiter_dependency = ValueDependency(lambda x: '\x00')):
        self._encoding = encoding
        self._length_dependency = length_dependency
        self._delimiter_dependency = delimiter_dependency
    
    def get_length(self, value: str) -> int:
        return self._length_dependency.get_length(value)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> str:
        length = self._length_dependency.get_length(raw_data[offset:])
        s = raw_data[offset : offset+length].decode(self._encoding)
        delimiter = self._delimiter_dependency.get_value(None)
        end_of_string_index = s.find(delimiter)
        if end_of_string_index >= 0:
            s = s[:end_of_string_index]
        return s
    
    def pack_into(self, buffer: bytes, offset: int, value: str) -> None:
        length = self.get_length(value)
        buffer[offset : offset+length] = value.encode(self._encoding)
        
class FixedLengthEncodedStringSerializer(EncodedStringSerializer):
    def __init__(self, encoding, length):
        super().__init__(encoding, LengthDependency(lambda x: length))

    def get_length(self, value: str) -> int:
        return self._length_dependency.get_length(None)
        
    def pack_into(self, buffer: bytes, offset: int, value: str) -> None:
        length = self.get_length()
        buffer[offset : offset+length] = b'\x00' * length
        super().pack_into(buffer, offset, value)

class DelimitedEncodedStringSerializer(EncodedStringSerializer):
    def __init__(self, encoding, delimiter):
        super().__init__(encoding, delimiter_dependency = ValueDependency(lambda x: delimiter))

    def get_length(self, value: str) -> int:
        delimiter = self._delimiter_dependency.get_value(None)
        end_of_string_index = value.find(delimiter)
        if end_of_string_index >= 0:
            return end_of_string_index + len(delimiter)
        return len(value) + len(delimiter)

class Utf16leEncodedStringSerializer(EncodedStringSerializer):
    UTF_16_LE = 'utf-16-le'
    def __init__(self, length_dependency):
        super().__init__(self.UTF_16_LE, length_dependency)
    
    def get_length(self, value: str) -> int:
        return 2 * len(value)
        
class FixedLengthUtf16leEncodedStringSerializer(FixedLengthEncodedStringSerializer):
    def __init__(self, length):
        super().__init__(Utf16leEncodedStringSerializer.UTF_16_LE, length)

    def get_length(self, value: str) -> int:
        return self._length_dependency.get_length(None)
        
        
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
    
    def get_length(self, value: Sequence[Any]) -> int:
        return sum(self._item_serializer.get_length(v) for v in value)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> Sequence[Any]:
        result = []
        consumed = 0
        
        if self._length_dependency:
            length = self._length_dependency.get_length(raw_data)
            has_more_items = lambda: consumed < length
        elif self._item_count_dependency:
            max_items = self._item_count_dependency.get_value(None)
            has_more_items = lambda: len(result) < max_items
            
        while has_more_items():
            item = self._item_serializer.unpack_from(raw_data, offset + consumed)
            result.append(item)
            consumed += self._item_serializer.get_length(item)

        return result

    def pack_into(self, buffer: bytes, offset: int, value: Sequence[Any]) -> None:
        for item in value:
            self._item_serializer.pack_into(buffer, offset, item)
            item_length = self._item_serializer.get_length(item)
            offset += item_length

class BitFieldEncodedSerializer(BaseSerializer[Sequence[int]]):
    def __init__(self, struct_format: str, allowed_bits: Set[int]):
        self._struct_serializer = StructEncodedSerializer(struct_format)
        self._allowed_bits = allowed_bits
    
    def get_length(self, value: Sequence[int]) -> int:
        return self._struct_serializer.get_length(value)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> int:
        value = self._struct_serializer.unpack_from(raw_data, offset)
        result = []
        for bit_mask in self._allowed_bits:
            if bit_mask & value:
                result.append(bit_mask)
            elif bit_mask == 0:
                result.append(bit_mask)
        return result
    
    def pack_into(self, buffer: bytes, offset: int, value: Sequence[Any]) -> None:
        bit_flags = 0
        for bit_mask in value:
            bit_flags |= bit_mask
        self._struct_serializer.pack_into(buffer, offset, bit_flags)

BASE_DATA_UNIT = TypeVar('BASE_DATA_UNIT')
class DataUnitSerializer(BaseSerializer[BASE_DATA_UNIT]):
    def __init__(self, data_unit_factory):
        self._data_unit_factory = data_unit_factory
    
    def get_length(self, value: BASE_DATA_UNIT) -> int:
        return len(value)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> BASE_DATA_UNIT:
        data_unit = self._data_unit_factory()
        data_unit.deserialize_value(raw_data, offset)
        return data_unit

    def pack_into(self, buffer: bytes, offset: int, value: BASE_DATA_UNIT) -> None:
        value.serialize_value(buffer, offset)

class BerEncodedLengthSerializer(BaseSerializer[int]):
    def __init__(self):
        pass
    
    def get_length(self, value: int) -> int:
        if value < 0x80:
            return 1
        else:
            length = 1
            while value > 0:
                value >>= 8
                length += 1
            return length
        
    def unpack_from(self, raw_data: bytes, offset: int) -> int:
        payload_length = raw_data[offset]
        if (payload_length & 0x80 == 0x80):
            length_length = payload_length & 0x7f
            payload_length = 0
            for j in range(length_length):
                payload_length <<= 8
                payload_length += raw_data[offset + 1 + j]
        return payload_length
    
    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
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

class BerEncodedBooleanSerializer(BaseSerializer[bool]):
    def __init__(self):
        pass
    
    def get_length(self, value: int) -> int:
        return 1
        
    def unpack_from(self, raw_data: bytes, offset: int) -> bool:
        if raw_data[offset]:
            return True
        else:
            return False

    def pack_into(self, buffer: bytes, offset: int, value: bool) -> None:
        if value:
            i = 0xff
        else:
            i = 0x00
        struct.pack_into(UINT_8, buffer, offset, i)

class BerEncodedIntegerSerializer(BaseSerializer[int]):
    def __init__(self, length_dependency):
        self._length_dependency = length_dependency
    
    def get_length(self, value: int) -> int:
        return len(self._encode(value))
        
    def unpack_from(self, raw_data: bytes, offset: int) -> int:
        length = self._length_dependency.get_length(None)
        offset_end = offset + length
        value = 0
        while offset < offset_end:
            value <<= 8
            value += raw_data[offset]
            offset += 1
        return value

    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        encoded_value = self._encode(value)
        length = len(encoded_value)
        buffer[offset : offset+length] = encoded_value
    
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
    def __init__(self):
        pass
    
    def get_length(self, value: int) -> int:
        if value < 0x80:
            return 1
        else:
            return 2
        
    def unpack_from(self, raw_data: bytes, offset: int) -> int:
        payload_length = raw_data[offset]
        if payload_length & 0xC0 == 0x80: # see https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_mcs.c#L222
            payload_length &= 0x3f
            payload_length <<= 8
            payload_length += raw_data[offset + 1]
        return payload_length
    
    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
        elif value < 2**14:
            struct.pack_into(UINT_8, buffer, offset +1 , value & 0xff)
            struct.pack_into(UINT_8, buffer, offset, (value >> 8) | 0x80)
        else:
            raise ValueError('value too large: %d' % value)

class RawLengthSerializer(BaseSerializer[bytes]):
    def __init__(self, length_dependency = LengthDependency()):
        self._length_dependency = length_dependency
        
    def get_length(self, value: bytes) -> int:
        return self._length_dependency.get_length(value)

    def unpack_from(self, raw_data: bytes, offset: int) -> bytes:
        return raw_data[offset : offset + self.get_length(raw_data)]
    
    def pack_into(self, buffer: bytes, offset: int, value: bytes) -> None:
        buffer[offset : offset + self.get_length(value)] = value[:self.get_length(value)]



# class CompositeSerializer(BaseSerializer[FIELD_VALUE_TYPE]):
#     """
#     Serialization/deserialization unit for mapping between ordered unamed values, and named unordered values.
#     """
#     TODO: rename as DataUnitFactory?
#     def __init__(self, name_serializer_pairs: Sequence[NamedSerializer]):
#         self._name_serializer_pairs = name_serializer_pairs

#     # def _get_names_inorder(self):
#     #     return (p.name for p in self._name_serializer_pairs)

#     # def _get_serializers_inorder(self):
#     #     return (p.serializer for p in self._name_serializer_pairs)

#     def get_length(self, value: NamedValues) -> int:
#         values = value.get_values()
#         total_length = 0
#         for p in self._name_serializer_pairs:
#             total_length += p.serializer.get_length(values[p.name])
#         return total_length
        
#     def unpack_from(self, raw_data: bytes, offset: int) -> NamedValues:
#         result = {}
#         for pair in self._name_serializer_pairs:
#             value = pair.serializer.unpack_from(raw_data, offset)
#             result[pair.name] = value
#             offset += pair.serializer.get_length(value)
#         return NamedValues(*result)
    
#     def pack_into(self, buffer: bytes, offset: int, value: NamedValues)  -> None:
#         values = value.get_values()
#         for p in self._name_serializer_pairs:
#             v = values[p.name]
#             p.serializer.pack_into(buffer, offset, v)
#             offset += p.serializer.get_length(v)
            

class DependentValueSerializer(BaseSerializer):
    def __init__(self, serializer, dependency):
        self._serializer = serializer
        self._dependency = dependency
        
    def get_length(self, value):
        return self._serializer.get_length(value)
        
    def unpack_from(self, raw_data, offset):
        return self._serializer.unpack_from(raw_data, offset)
    
    def pack_into(self, buffer, offset, value):
        dependent_value = self._dependency.get_value(value)
        self._serializer.pack_into(buffer, offset, dependent_value)

# class NonSerializingReferenceSerializer(BaseSerializer):
#     def __init__(self, name, value_getter):
#         self.name = name
#         self._value_getter = value_getter
        
#     def get_referenced_value(self):
#         return self._value_getter()
    
#     def get_length(self, value):
#         return 0

#     def unpack_from(self, raw_data, offset):
#         return None
    
#     def pack_into(self, buffer, offset, value):
#         pass

# class ReinterpretedSerializer(BaseSerializer):
#     def __init__(self, name, original_field, new_field):
#         self.name = name
#         self._original_field = original_field
#         self._new_field = new_field
#         self._remaining_field = RawLengthSerializer(
#                 name + "_remaining", 
#                 LengthDependency(lambda x: self._original_field.get_length(x) - self._new_field.get_length(x)))
        
#     def get_original_field(self):
#         return self._original_field
    
#     def get_remaining_field(self):
#         return self._original_field
    
#     def clear_remaining_field(self):
#         self._remaining_field = RawLengthSerializer(
#                 self._remaining_field.name, 
#                 LengthDependency(lambda x: 0))
    
#     def get_length(self, value):
#         return self._new_field.get_length(value)

#     def unpack_from(self, raw_data, offset):
#         return self._new_field.unpack_from(raw_data, offset)
    
#     def pack_into(self, buffer, offset, value):
#         self._new_field.pack_into(buffer, offset, value)
#         raise ValueError("TODO: how do I pack the original remaining value if it has not been reinterpreted?")
#         # length = self._new_field.get_length(value)
#         # self._remaining_field.pack_into(buffer, offset + length, value)

# class Marshaller(Generic[FIELD_VALUE_TYPE]):
#     # def __init__(self, composer: Callable[Mapping[str, Any], FIELD_VALUE_TYPE], decomposer: Callable[FIELD_VALUE_TYPE, Mapping[str, Any]]):
#     def __init__(self):
#         self.compose = NamedValues
#         self.decompose = NamedValues.get_values



# class StructuredDataUnitSerializer(BaseSerializer):
#     def __init__(self, name, data_unit_factory):
#         self.name = name
#         self._data_unit_factory = data_unit_factory

#     def get_length(self, value):
#         return len(value)
        
#     def unpack_from(self, data, offset):
#         return self._data_unit_factory(data[offset:])
    
#     def pack_into(self, buffer, offset, value):
#         wire_bytes = value.as_wire_bytes()
#         buffer[offset : offset + len(wire_bytes)] = wire_bytes
