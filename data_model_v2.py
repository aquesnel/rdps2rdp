"""
Class diagram:
http://www.plantuml.com/plantuml/uml/jLF1RXen4BtxAqPxgHILg6al5LAZL4Mzj8SeX5DLhGoUWDjTUsNF1j68VwynXjdYPKKFuSRupNlptipUUPAEsheITluB5mGJIN9cDC6B09ZeKA6L96WzUYYk2z364qe5zWcA7p-B05fOGr8RTBlQiwnQzA4QEGu5KDhHPcJGxvvgsJJQB66Ej4OqO9r2XmfQ8sjKuD5fMUa_wFnR271f5EnVMfEWNSors9xENYvMkb8NEk3sQIALymg_QamCNxhsM3UEfUcDtplaAK93tLYl2QSCVdbDsrqTJlu8bgIj2UW3_C5QEYGbHFSVZ4QtS7pwfrfS5JtvYBmKm7q9z2DFDoRwicDzPXD7DmLNn_0Wrz_HB6bLmESfEBak6xcfh5Gb9rVUYB09ABA1nf30MVFJuHZIDN-wXVc6ufapBro5ESzhRlUg1yDZk9_Ceb2ZsaYTkX9DfXu8uY-oX9lqROtgahdBv_UHtpgzr4PMtUaTrb8RXOwBszvWPzhGnyXFpMygQTDWnrwGkAIhYgl9-WRMoBrvfg7vt29Z2-o6F1cv6mZlyaE-nxCsjyEQUukPvNxTctUzmjpsNz8feJooN7pWW0VIpa_uyVxR8-kfK2_Ry92qECF4dAz1G4eiyywOqq-ZtzlWznK0WvyOqwIfMObT9PKxDAgjgxy0
"""

import struct
from functools import lru_cache as memoized
import functools
import collections
import pprint

import serializers
from serializers import (
    BaseSerializer,
    
    StaticSerializer,
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    BerEncodedLengthSerializer,
    BerEncodedBooleanSerializer,
    BerEncodedIntegerSerializer,
    
    PerEncodedLengthSerializer,
    Utf16leEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    ArraySerializer,
    DataUnitSerializer,
    RawLengthSerializer,
    LengthDependency,
    DependentValueSerializer,
    ValueDependency,
    )

from typing import Any, Sequence, Callable, TypeVar, Generic, Union


# FIELD_VALUE_TYPE = TypeVar('FIELD_VALUE_TYPE')


def lazy_get_field(self, name: str):
    return functools.partial(self.__getattr__, name)

def no_op(x):
    pass

def is_int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False
        
def traverse_object_graph(value, path):
    for field_name in path.split("."):
        if is_int(field_name):
            try:
                # print('getting field name with numerical value %s' % field_name)
                value = value[int(field_name)]
                continue
            except IndexError:
                pass
        value = getattr(value, field_name)
    return value

def as_hex_str(b):
    return " ".join("{:02x}".format(x) for x in b)

# class NamedValues(object):
#     """
#     A mapping Value container that uses "." instead of "[]" for accessing values
#     """
#     def __init__(self, **kwargs):
#         # if 'get_values' in kwargs:
#         #     raise ValueError('"get_values" is an illegal value name')
#         # self.__dict__.update(kwargs)
        
#         # self._names = kwargs.keys()
#         for name, value in kwargs.items():
#             if name in self.__dict__:
#                 raise ValueError('"%s" is an illegal value name because it will overwrite an existing value' % (name))
#             setattr(self, name, value)
    
#     # def get_names(self):
#     #     return self.__slots__
        
#     # def get_values_inorder(self):
#     #     retval = []
#     #     for name in self.__slots__:
#     #         retval.append(getattr(self, name))
#     #     return retval
    
#     @staticmethod
#     def get_values(self):
#         return self.__dict__
    
#     # def __setattr__(self, name, value):
#     #     if name not in self.VALUE_NAMES_ORDER:
#     #         raise ValueError('''setting attribute "%s" is not supported because it is not on of %s's fields: %s''' % (name, type(self).__name__, self.VALUE_NAMES_ORDER))
#     #     super(NamedValues, self).__setattr__(name, value)


NamedField = collections.namedtuple('NamedField', ['name', 'serializer'])

class SerializationException(Exception):
    pass

class BaseField(object):
    """
    Container that associates a serializer with it's value.
    """
    def __init__(self, name):
        self.name = name
    
    def get_value(self) -> Any:
        raise NotImplementedError()
    
    def set_value(self, value: Any):
        raise NotImplementedError()
    
    def get_length(self):
        raise NotImplementedError()

    def deserialize_value(self, raw_data: bytes, offset: int) -> int:
        try:
            return self._deserialize_value(raw_data, offset)
        except Exception as e:
            raise SerializationException(
                'Error deserializing "%s" from raw_data length %d, offset %d' % (
                    self.name, len(raw_data), offset)) from e
    
    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        raise NotImplementedError()
    
    def serialize_value(self, buffer: bytes, offset: int) -> None:
        try:
            return self._serialize_value(buffer, offset)
        except Exception as e:
            raise SerializationException(
                'Error serializing "%s" into buffer length %d, offset %d' % (
                    self.name, len(buffer), offset)) from e

    def _serialize_value(self, buffer: bytes, offset: int) -> None:
        raise NotImplementedError()
        
class PrimitiveField(BaseField):
    def __init__(self, name, serializer):
        self.name = name
        self.serializer = serializer
        self.value = None
        self.raw_value = None
        self.is_value_dirty = False

    def __str__(self):
        return '<PrimitiveField(name=%s, serializer=%s)>' % (
            self.name, self.serializer)

    def get_value(self) -> Any:
        if self.is_value_dirty:
            return self.value
        if self.raw_value is None:
            raise ValueError('Field has not been deserialized yet')
        return self.value

    def set_value(self, value: Any):
        self.is_value_dirty = True
        self.value = value

    def get_length(self):
        return self.serializer.get_length(self.get_value())
        
    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        value = self.serializer.unpack_from(raw_data, offset)
        self.value = value
        self.is_value_dirty = False
        length = self.serializer.get_length(value)
        self.raw_value = memoryview(raw_data)[offset : offset+length]
        return length
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        if self.is_value_dirty:
            self.serializer.pack_into(buffer, offset, self.value)
            length = self.serializer.get_length(self.value)
        else:
            length = len(self.raw_value)
            buffer[offset : offset+length] = self.raw_value
        return length

# class DataUnitField(PrimitiveField):
#     def __init__(self, name, data_unit):
#         super().__init__(name, DataUnitSerializer(lambda: data_unit.__class__()))

class DataUnitField(BaseField):
    def __init__(self, name, data_unit):
        self.name = name
        self.data_unit = data_unit
    
    def __str__(self):
        return '<DataUnitField(name=%s, data_unit class=%s)>' % (
            self.name, self.data_unit.__class__)
            
    def get_value(self) -> Any:
        return self.data_unit

    def set_value(self, value: Any):
        self.data_unit = value

    def get_length(self):
        return self.data_unit.get_length()
        
    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        return self.data_unit.deserialize_value(raw_data, offset)
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        return self.data_unit.serialize_value(buffer, offset)

class RemainingRawField(BaseField):
    def __init__(self, name, orig_raw_value, length):
        self.name = name
        self.orig_raw_value = orig_raw_value
        self.remaining = memoryview(orig_raw_value)[length:]

    def get_value(self) -> Any:
        return self.remaining

    def set_value(self, value: Any):
        raise NotImplementedError('RemainingRawField does not support being set')

    def get_length(self):
        return 0

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        return 0
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        return 0
        
class ReferenceField(BaseField):
    def __init__(self, name, obj, referenced_value_path):
        self.name = name
        self._obj = obj
        self._referenced_value_path = referenced_value_path

    def __str__(self):
        return '<ReferenceField(name=%s, referenced_value_path=%s)>' % (
            self.name, self._referenced_value_path)

    def get_value(self) -> Any:
        raise NotImplementedError('ReferenceField does not support get')

    def set_value(self, value: Any):
        raise NotImplementedError('ReferenceField does not support set')

    def get_referenced_value(self) -> Any:
        return traverse_object_graph(self._obj, self._referenced_value_path)

    def get_length(self):
        return 0

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        return 0
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        return 0

class OptionalField(BaseField):
    def __init__(self, optional_field):
        self._optional_field = optional_field
        self._value_is_present = False

    @property
    def name(self):
        return self._optional_field.name

    def get_value(self) -> Any:
        if self._value_is_present:
            return self._optional_field.get_value()
        else:
            return None

    def set_value(self, value: Any):
        self._value_is_present = True
        self._optional_field.set_value(value)

    def get_length(self):
        if self._value_is_present:
            return self._optional_field.get_length()
        else:
            return 0

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        length = 0
        try:
            length = self._optional_field._deserialize_value(raw_data, offset)
            self._value_is_present = True
        except struct.error:
            pass    
        return length
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        if self._value_is_present:
            return self._optional_field.serialize_value(buffer, offset)
        else:
            return 0

class ConditionallyPresentField(BaseField):
    def __init__(self, is_present_condition, optional_field):
        self._optional_field = optional_field
        self._is_present_condition = is_present_condition

    @property
    def name(self):
        return self._optional_field.name

    def get_value(self) -> Any:
        if self._is_present_condition():
            return self._optional_field.get_value()
        else:
            return None

    def set_value(self, value: Any):
        self._optional_field.set_value(value)

    def get_length(self):
        if self._is_present_condition():
            return self._optional_field.get_length()
        else:
            return 0

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        length = 0
        try:
            length = self._optional_field._deserialize_value(raw_data, offset)
        except struct.error:
            pass    
        return length
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        if self._is_present_condition():
            return self._optional_field.serialize_value(buffer, offset)
        else:
            return 0

class BaseDataUnit(object):
    def __init__(self, fields):
        super(BaseDataUnit, self).__setattr__('_fields_by_name', {})
        # self. = {}
        self._fields = fields
        for f in fields:
            self._fields_by_name[f.name] = f

    def __getattr__(self, name: str) -> Any:
        if name in self._fields_by_name:
            f = self._fields_by_name[name]
            if isinstance(f, ReferenceField):
                return f.get_referenced_value()
            return f.get_value()
        else:
            raise AttributeError(name)
        
    def __setattr__(self, name: str, value: Any):
        if name not in self._fields_by_name:
            super(BaseDataUnit, self).__setattr__(name, value)
        else:
            f = self._fields_by_name[name]
            f.set_value(value)

    def __len__(self):
        return self.get_length()
        
    def get_length(self):
        length = 0
        for f in self._fields:
            length += f.get_length()
        return length

    def __str__(self):
        return pprint.pformat(self._as_dict_for_pprint())
        
    def _as_dict_for_pprint(self):
        result = {
            '__python_type__': self.__class__
        }
        for f in self._fields:
            if isinstance(f, ReferenceField):
                v = str(f)
            else:
                v = f.get_value()
            if not isinstance(v, list):
                v_list = [v]
            else:
                v_list = v[:]
            for i, v in enumerate(v_list):
                if isinstance(v, BaseDataUnit):
                    v = v._as_dict_for_pprint()
                elif isinstance(v, (bytes, bytearray, memoryview)):
                    length = len(v)
                    if length < 10:
                        s = "b'%s'" % as_hex_str(v)
                    else:
                        s = "b'%s...%s'" % (as_hex_str(v[:4]), as_hex_str(v[-4:]))
                    v = '<bytes(len %d): %s>' % (length, s)
                v_list[i] = v
            if len(v_list) == 1:
                v = v_list[0]
            else:
                v = v_list
            
            result[f.name] = v
        return result

    def deserialize_value(self, raw_data: bytes, orig_offset: int = 0) -> int:
        offset = orig_offset
        for f in self._fields:
            length = f.deserialize_value(raw_data, offset)
            offset += length
        return offset - orig_offset

    def serialize_value(self, buffer: bytes, orig_offset: int = 0) -> None:
        offset = orig_offset
        for f in self._fields:
            length = f.serialize_value(buffer, offset)
            offset += length
        return offset - orig_offset

    def as_wire_bytes(self):
        buffer = bytearray(self.get_length())
        self.serialize_value(memoryview(buffer))
        return buffer

    def alias_field(self, new_name, path):
        if new_name in self._fields_by_name:
            raise ValueError('the field "%s" already exists and therefor cannot be an alias' % (new_name))
        new_field = ReferenceField(new_name, self, path)
        self._fields_by_name[new_field.name] = new_field
        self._fields.append(new_field)


    def reinterpret_field(self, name_to_reinterpret, new_field):
        use_remainder = False
        if name_to_reinterpret.endswith('.remaining'):
            use_remainder = True
            name_to_reinterpret = name_to_reinterpret[:-1 * len('.remaining')]
        
        if name_to_reinterpret not in self._fields_by_name:
            raise AttributeError(name_to_reinterpret)
            # raise ValueError('field "%s" does not exist' % (name_to_reinterpret))
        
        for i, f in enumerate(self._fields):
            if f.name == name_to_reinterpret:
                if use_remainder and isinstance(f, RemainingRawField):
                    # if not isinstance(f, RemainingRawField):
                    #     raise ValueError('field "%s" must be of type RemainingRawField' % (f.name))
                    orig_raw_value = f.orig_raw_value
                    orig_remaining = f.get_value()
                    length = new_field.deserialize_value(orig_remaining, 0)
                    remaining_field = RemainingRawField(f.name, orig_raw_value, len(orig_remaining) + length)
                else:
                    orig_raw_value = bytearray()
                    length = f.serialize_value(orig_raw_value, 0)
                    orig_raw_value = orig_raw_value[:length]
                    
                    length = new_field.deserialize_value(orig_raw_value, 0)
                    remaining_field = RemainingRawField(f.name, orig_raw_value, length)
                
                if new_field.name == remaining_field.name:
                    if len(remaining_field.get_value()) > 0:
                        raise ValueError('Cannot overwrite field "%s" because not all of the bytes were consumed during the re-interpretation as %s. Existing length %d, consumed length %d' % (
                            remaining_field.name, new_field, len(remaining_field.get_value()) + length, length))
                else:
                    self._fields_by_name[remaining_field.name] = remaining_field
                    self._fields.insert(i+1, remaining_field)

                self._fields_by_name[new_field.name] = new_field
                self._fields[i] = new_field
                break


class RawDataUnit(BaseDataUnit):
    def __init__(self):
        super().__init__([
            PrimitiveField('payload', RawLengthSerializer()),
        ])

# raw_data = bytes()
# pdu = RawDataUnit_v2() # make payload a proxy object which has the reinterpret_as which references back to the parent pdu, and which otherwise delegates to the field value
# pdu.deserialize_from(raw_data)
# pdu.reinterpret_field('payload', 'tpkt', Tpkt_DataUnit()) # make payload a non-serialized field with the special 'remaining' sub value, maybe make the parsed payload value unreadable but still have the raw_data still accessible. Also add the new field to the parent object
# pdu.tpkt.get_tpkt_version()
# pdu.tpkt.reinterpret_field('payload', 'x224', X224_DataUnit())
# pdu.tpkt.x224.get_x224_type()
# pdu.tpkt.reinterpret_field('payload.remainder', 'rdp_sec_header', RdpSecHeader_DataUnit())
# pdu.tpkt.rdp_sec_header.get_type()
# pdu.tpkt.reinterpret_field('payload.remainder', 'rdp_pdu_header', RdpPduHeader_DataUnit()) # consume bytes from remainder, and rest the remainder to the new smaller size
# pdu.tpkt.rdp_pdu_header.get_type()
# pdu.tpkt.rdp_pdu_header.type = 1
# pdu.as_wire_bytes()

# class BaseDataUnit(object):
#     def __init__(self, raw_data, fields):
#         self._fields = fields
#         self._field_values = {}
#         self._fields_dirty = False
#         self._raw_data = raw_data # we need to populate _raw_data in case there is a DynamicField in fields when we calculate the length
#         self._raw_data = raw_data[:self.get_length()]
        
#     def __getattr__(self, name):
#         if len(self._field_values) == 0:
#             self._unpack()
#         if name in self._field_values:
#             return self._get_value(name)
#         else:
#             raise AttributeError(name)
        
#     def __setattr__(self, name, value):
#         if name in {'_field_values', '_fields', '_fields_dirty', '_raw_data'}:
#             super(BaseDataUnit, self).__setattr__(name, value)
#             return
#         if len(self._field_values) == 0:
#             self._unpack()
#         if name in self._field_values:
#             self._field_values[name] = value
#             self._fields_dirty = True
#         else:
#             super(BaseDataUnit, self).__setattr__(name, value)
    
#     # problem:
#     # how to reference length for a field that is split?
#     #  > create a field which is a split field and a reference field, then split the field and add a ref in the parent to the new child and replace the 
#     # how to keep field names short while still having a single clear place to lookup field names?
#     #  > use aliasing of fields
#     def reinterpret_field(self, name_to_reinterpret, new_name, cls):
#     # def reinterpret_field(self, name_to_reinterpret, new_field):
#         if len(self._field_values) == 0:
#             self._unpack()
#         offset = 0
#         for i, f in enumerate(self._fields):
#             value = self._get_value(f.name)
#             length = f.get_length(value)
#             if f.name == name_to_reinterpret:
#                 raise ValueError("TODO: how do I support reinterpreting the remaining value of this reinterpreted field?")
#                 # can I reinterpret an alias?
#                 # fields are only used for serialization and deserialization. once deserialized all of the 
#                 # values are the object representation only. Maybe I should make this more explicit by renaming 
#                 # field to "serializationSpec"/UnMarshaller and then having a seperate object which handles 
#                 # marshalling which only does serialization
#                 # Maybe I change the field definition to hold a sede and a value.
#                 #
#                 # problem: reinterpretation means doing multiple things that are seperate:
#                 # * use a new deserializer on the old raw bytes
#                 # * split the old raw bytes into the new object and the remaining bytes (eg. split off a header)
#                 #   * consuming all of the bytes is easy and does not have the problem of remaining bytes
#                 # * replace the old value with the new value
#                 # * install a serializer for the new value
#                 # * store the remaining bytes for future use (eg. payload that will next be reinterpreted)
#                 # 
#                 # problem: can I make deserialization lazy?
                
                
#                 # attemp 2:
#                 # reinterperted_field = ReinterpretedSerializer(name_to_reinterpret, f, new_field)
#                 # self._fields[i] = reinterperted_field
#                 # new_value = reinterperted_field.unpack_from(memoryview(self._raw_data[offset : offset + length]), 0)
#                 # self._field_values[name_to_reinterpret] = new_value
#                 # raise ValueError('TODO: this is broken because the ReinterpretedSerializer dosen't expose it's remaining_field via a property for object graph traversal. This can be fixed with a structured field (maybe? but maybe not since it dosen't make sense to reference a field via a name and expect to get a value from it. Maybe I can change this by having Unbound and Bound fields.))
#                 # self.alias_field(name_to_reinterpret + "_remaining", name_to_reinterpret + "." + )

#                 # Orig:
#                 new_value = cls(memoryview(self._raw_data[offset : offset + length]))
#                 # raise ValueError('TODO: fixup the replaced field so it can add the structured field')
#                 self._field_values[new_name] = new_value
#                 self._fields[i] = StructuredDataUnitSerializer(new_name, cls)
#                 remaining_length = length - new_value.get_length()
#                 if remaining_length < 0:
#                     raise ValueError("new field is bigger than old field")
#                 else:
#                     self._fields.insert(i + 1, 
#                             RawLengthSerializer(name_to_reinterpret, LengthDependency(lambda x: remaining_length)))
#                 break
#             else:
#                 offset += length
    
#     def alias_field(self, new_name, path):
#         self._fields.append(NonSerializingReferenceSerializer(new_name, lambda: traverse_object_graph(self, path)))
    
#     def __len__(self):
#         return self.get_length()
        
#     def get_length(self):
#         if len(self._field_values) == 0:
#             self._unpack()
#         length = 0
#         for f in self._fields:
#             length += f.get_length(self._get_value(f.name))
#         return length
        
#     def _unpack(self):
#         self._field_values = {}
#         offset = 0
#         for f in self._fields:
#             value = f.unpack_from(self._raw_data, offset)
#             self._field_values[f.name] = value
#             offset += f.get_length(value)
    
#     def _get_value(self, name):
#         value = self._field_values[name]
#         if value is not None:
#             return value
#         for f in self._fields:
#             if name == f.name and hasattr(f, 'get_referenced_value'):
#                 return f.get_referenced_value()
#         return None
            
    
#     def is_dirty(self):
#         if self._fields_dirty:
#             return True
#         elif len(self._field_values) == 0:
#             return False
#         else:
#             for v in self._field_values.values():
#                 if hasattr(v, 'is_dirty') and v.is_dirty():
#                     return True
#             return False
        
#     def as_wire_bytes(self):
#         if not self.is_dirty():
#             return self._raw_data
#         elif len(self._field_values) == 0:
#             return self._raw_data
#         else:
#             buffer = bytearray(self.get_length())
#             offset = 0
#             for f in self._fields:
#                 value = self._get_value(f.name)
#                 f.pack_into(buffer, offset, value)
#                 offset += f.get_length(value)
#             return memoryview(buffer)

# class RawDataUnit(BaseDataUnit):
#     def __init__(self, raw_data):
#         super(RawDataUnit, self).__init__(raw_data, fields = [
#             RawLengthSerializer('payload'),
#         ])

class Ber(object):
    # ITU-T X.690
    BOOLEAN = 'boolean' # bool 0 = False, ff = True
    INTEGER = 'integer' # big endian integer
    ENUM = 'enumeration' # an int
    OCTET_STRING = 'OctetString'
    TYPES = {
        0x01: BOOLEAN, 
        0x02: INTEGER, 
        0x04: OCTET_STRING,
        0x0a: ENUM,
        0x30: 'sequenceOf',
    }

class BerEncodedDataUnit(BaseDataUnit):
    def __init__(self, interpret_payload_as: Union[BaseSerializer[Any], BaseDataUnit] = None):
        super(BerEncodedDataUnit, self).__init__(fields = [
            PrimitiveField('type', StructEncodedSerializer(UINT_8)),
            PrimitiveField('length', 
                DependentValueSerializer(
                    BerEncodedLengthSerializer(),
                    ValueDependency(lambda x: self._fields_by_name['payload'].get_length()))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.length)))
        ])
        self._interpret_payload_as = interpret_payload_as
        # print('auto re-interprert forced %s in __init__' % (self._interpret_payload_as is not None) )
        
    def deserialize_value(self, raw_data: bytes, offset: int = 0) -> int:
        result = super(BerEncodedDataUnit, self).deserialize_value(raw_data, offset)
        # auto re-interprert the payload based on the embedded type
        reinterpert_as = None
        ber_type = Ber.TYPES.get(self.type, 'Unknown')
        # print('auto re-interprert forced %s' % (self._interpret_payload_as is not None) )
        if self._interpret_payload_as is not None:
            if ber_type == Ber.OCTET_STRING:
                reinterpert_as = self._interpret_payload_as
            else:
                raise ValueError('BerEncodedDataUnit type must be OctectString when given a "%s" for interpreting the payload, but the type is "%s"' % (
                    self._interpret_payload_as.__class__, ber_type))
        elif ber_type == Ber.BOOLEAN:
            reinterpert_as = BerEncodedBooleanSerializer()
        elif ber_type in {Ber.INTEGER, Ber.ENUM}:
            reinterpert_as = BerEncodedIntegerSerializer(
                LengthDependency(lambda x: self.length))
        
        if reinterpert_as is not None:
            # print('auto re-interprert "payload" as %s' % (reinterpert_as.__class__) )
            if isinstance(reinterpert_as, BaseDataUnit):
                new_field = DataUnitField('payload', reinterpert_as)
            else:
                new_field = PrimitiveField('payload', reinterpert_as)
            self.reinterpret_field('payload', new_field)
        return result
        
class PerEncodedDataUnit(BaseDataUnit):
    def __init__(self, interpret_payload_as: Union[BaseSerializer[Any], BaseDataUnit] = None):
        super(PerEncodedDataUnit, self).__init__(fields = [
            PrimitiveField('length', 
                DependentValueSerializer(
                    PerEncodedLengthSerializer(),
                    ValueDependency(lambda x: self._fields_by_name['payload'].get_length()))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.length)))
        ])
        self._interpret_payload_as = interpret_payload_as
    
    def deserialize_value(self, raw_data: bytes, offset: int = 0) -> int:
        result = super(PerEncodedDataUnit, self).deserialize_value(raw_data, offset)
        # auto re-interprert the payload based on the given DataUnit
        if self._interpret_payload_as is not None:
            if isinstance(self._interpret_payload_as, BaseDataUnit):
                new_field = DataUnitField('payload', self._interpret_payload_as)
            else:
                new_field = PrimitiveField('payload', self._interpret_payload_as)
            self.reinterpret_field('payload', new_field)
        return result


class Tpkt(object):
    FAST_PATH_NAME = 'FastPath'
    SLOW_PATH_NAME = 'SlowPath'
    SLOW_PATH = 3
    TPKT_VERSIONS = {
        SLOW_PATH: SLOW_PATH_NAME,
    }

class TpktDataUnit(BaseDataUnit):
    def __init__(self):
        super(TpktDataUnit, self).__init__(fields = [
            PrimitiveField('version', StructEncodedSerializer(UINT_8)),
            PrimitiveField('_', StructEncodedSerializer(PAD)),
            PrimitiveField('length',
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_16_BE),
                    ValueDependency(lambda x: len(self)))),
            PrimitiveField('tpktUserData',
                RawLengthSerializer(LengthDependency(lambda x: self.length - 4))),
        ])

    def get_tpkt_version_name(self):
        return Tpkt.TPKT_VERSIONS.get(self.version, Tpkt.FAST_PATH_NAME)
    
class X224(object):
    TPDU_DATA = 'Data'
    TPDU_CONNECTION_REQUEST = 'Connection Request'
    TPDU_CONNECTION_CONFIRM = 'Connection Confirm'
    TPDU_TYPE = {
        0xE0: TPDU_CONNECTION_REQUEST,
        0xD0: TPDU_CONNECTION_CONFIRM,
        0xF0: TPDU_DATA
    }
    
class X224HeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(X224HeaderDataUnit, self).__init__(fields = [
            PrimitiveField('length', StructEncodedSerializer(UINT_8)),
            PrimitiveField('x224_type', StructEncodedSerializer(UINT_8)),
            PrimitiveField('x224_EOT', StaticSerializer(b'\x08')),
            PrimitiveField('x224UserData', RawLengthSerializer()),
        ])

    def get_x224_type_name(self):
        return X224.TPDU_TYPE.get(self.x224_type, 'unknown (%d)' % self.x224_type)


class Mcs(object):
    SEND_DATA_CLIENT = 'send data request'
    SEND_DATA_SERVER = 'send data indication'
    CONNECT = 'Connect'
    ERECT_DOMAIN = 'Erect Domain'
    ATTACH_USER_REQUEST = 'Attach user request'
    ATTACH_USER_CONFIRM = 'Attach user confirm'
    CHANNEL_JOIN_REQUEST = 'channel join request'
    CHANNEL_JOIN_CONFIRM = 'channel join confirm'
    MCS_TYPE = {
        0x7f: CONNECT,
        0x04: ERECT_DOMAIN,
        0x28: ATTACH_USER_REQUEST,
        0x2c: ATTACH_USER_CONFIRM, # only uses high 6 bits
        0x38: CHANNEL_JOIN_REQUEST,
        0x3c: CHANNEL_JOIN_CONFIRM, # only uses high 6 bits
        0x64: SEND_DATA_CLIENT,
        0x68: SEND_DATA_SERVER,
    }
    
    CONNECT_INITIAL = 'Connect Initial'
    CONNECT_RESPONSE = 'Connect Response'
    MCS_CONNECT_TYPE = {
        0x65: CONNECT_INITIAL,
        0x66: CONNECT_RESPONSE,
    }
    
class McsHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsHeaderDataUnit, self).__init__(fields = [
            PrimitiveField('mcs_type', StructEncodedSerializer(UINT_8)),
            PrimitiveField('payload', RawLengthSerializer()),
        ])
    
    def get_mcs_type_name(self):
        mcs_type = Mcs.MCS_TYPE.get(self.mcs_type, None)
        if mcs_type is None:
            mcs_type = Mcs.MCS_TYPE[self.mcs_type & 0xfc] # for high 6 bits
        return mcs_type

class McsConnectHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectHeaderDataUnit, self).__init__(fields = [
            PrimitiveField('mcs_connect_type', StructEncodedSerializer(UINT_8)),
        ])
        
    def get_mcs_connect_type(self):
        return Mcs.MCS_CONNECT_TYPE.get(self.mcs_connect_type, None)


class McsConnectInitialDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectInitialDataUnit, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    BerEncodedLengthSerializer(),
                    ValueDependency(lambda x: len(self)))),
            DataUnitField('callingDomainSelector', BerEncodedDataUnit()),
            DataUnitField('calledDomainSelector', BerEncodedDataUnit()),
            DataUnitField('upwardFlag', BerEncodedDataUnit()),
            DataUnitField('targetParameters', BerEncodedDataUnit()),
            DataUnitField('minimumParameters', BerEncodedDataUnit()),
            DataUnitField('maximumParameters', BerEncodedDataUnit()),
            DataUnitField('userData', 
                BerEncodedDataUnit(McsGccConnectionDataUnit())),
        ])


class McsConnectResponseDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectResponseDataUnit, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    BerEncodedLengthSerializer(),
                    ValueDependency(lambda x: len(self)))),
            DataUnitField('result', BerEncodedDataUnit()),
            DataUnitField('calledConnectId', BerEncodedDataUnit()),
            DataUnitField('domainParameters', BerEncodedDataUnit()),
            DataUnitField('userData', 
                BerEncodedDataUnit(McsGccConnectionDataUnit())),
        ])

class McsGccConnectionDataUnit(BaseDataUnit):
    def __init__(self): 
        super(McsGccConnectionDataUnit, self).__init__(fields = [
            PrimitiveField('gcc_header', RawLengthSerializer(LengthDependency(lambda x: 21))),
            DataUnitField('gcc_userData', 
                PerEncodedDataUnit(
                    ArraySerializer(
                        DataUnitSerializer(RdpUserDataBlock),
                        LengthDependency()))),
        ])
        
class McsSendDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsSendDataUnit, self).__init__(fields = [
            PrimitiveField('mcs_data_parameters', RawLengthSerializer(LengthDependency(lambda x: 6))),
            DataUnitField('mcs_data', PerEncodedDataUnit()),
        ])
        
    # @property
    # def payload(self):
        
    #     payload = None
    #     if self.mcs_type in (Mcs.CONNECT_INITIAL):
    #         payload_length, i = parse_ber_length(self._raw_data, 2)
    #         # payload = self._raw_data[i:i + payload_length]
            
    #         callingDomainSelector, i = parse_ber(self._raw_data, i)
    #         calledDomainSelector, i = parse_ber(self._raw_data, i)
    #         upwardFlag, i = parse_ber(self._raw_data, i)
    #         targetParameters, i = parse_ber(self._raw_data, i)
    #         minimumParameters, i = parse_ber(self._raw_data, i)
    #         maximumParameters, i = parse_ber(self._raw_data, i)
    #         connectionInitial_userData, i = parse_ber(self._raw_data, i)
            
    #         # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
    #         #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
    #         # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
    #         gccConnectionData_userData = connectionInitial_userData[23:]
    #         payload = gccConnectionData_userData
        
    #     elif self.mcs_type in (Mcs.CONNECT_RESPONSE):
    #         payload_length, i = parse_ber_length(self._raw_data, 2)
    #         # payload = self._raw_data[i:i + payload_length]
            
    #         result, i = parse_ber(self._raw_data, i)
    #         calledConnectId, i = parse_ber(self._raw_data, i)
    #         domainParameters, i = parse_ber(self._raw_data, i)
    #         connectionResponse_userData, i = parse_ber(self._raw_data, i)
            
    #         # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
    #         #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
    #         # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
    #         gccConnectionData_userData = connectionResponse_userData[23:]
    #         payload = gccConnectionData_userData
            
    #     elif self.mcs_type in (Mcs.SEND_DATA_CLIENT, Mcs.SEND_DATA_SERVER):
    #         # type = self._raw_data[0]
    #         # initiator = self._raw_data[1] << 8 + self._raw_data[2] + 1001
    #         # channel_id = self._raw_data[3] << 8 + self._raw_data[4]
    #         # segmentation = self._raw_data[5]
            
    #         payload_length, i = parse_per_length(self._raw_data, 6)
    #         payload = self._raw_data[i:i + payload_length]

    #     elif self.mcs_type in (
    #             Mcs.ATTACH_USER_REQUEST, 
    #             Mcs.ATTACH_USER_CONFIRM, 
    #             Mcs.ERECT_DOMAIN,
    #             Mcs.CHANNEL_JOIN_REQUEST,
    #             Mcs.CHANNEL_JOIN_CONFIRM,
    #             ):
    #         payload = self._raw_data

    #     return payload



class Rdp_TS_SECURITY_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SECURITY_HEADER, self).__init__(fields = [
            PrimitiveField('flags', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('flagsHi', StructEncodedSerializer(UINT_16_LE)),
        ])

    def sec_packet_type(self):
        return Rdp.Security.SEC_PACKET_TYPE.get(self.flags & Rdp.Security.SEC_PACKET_MASK, 'unknown')

    def is_SEC_ENCRYPT(self):
        return self.flags & 0x0008 == 0x0008

class RdpShareControlHeader(object):
    PDUTYPE_DEMANDACTIVEPDU = 'Demand Active'
    PDUTYPE_CONFIRMACTIVEPDU = 'Confirm Active'
    PDUTYPE_DEACTIVATEALLPDU = 'Deactivate'
    PDUTYPE_DATAPDU = 'Data'
    PDUTYPE_SERVER_REDIR_PKT = 'Redirect'
    PDU_TYPE = {
        0x1: PDUTYPE_DEMANDACTIVEPDU,
        0x3: PDUTYPE_CONFIRMACTIVEPDU,
        0x6: PDUTYPE_DEACTIVATEALLPDU,
        0x7: PDUTYPE_DATAPDU,
        0xA: PDUTYPE_SERVER_REDIR_PKT,
    }
    

class Rdp_TS_SHARECONTROLHEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SHARECONTROLHEADER, self).__init__(fields = [
            PrimitiveField('totalLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pduType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pduSource', StructEncodedSerializer(UINT_16_LE)),
        ])

    def pdu_type(self):
        pdu_code = self.pduType & 0x0f
        return RdpShareControlHeader.PDU_TYPE.get(pdu_code, 'unknown %s' % bytes.hex(bytes([pdu_code])))

    def channel_id(self):
        return self.pduSource

class Rdp(object):
    class UserData(object):
        SC_CORE = 'serverCoreData'
        SC_SECURITY = 'serverSecurityData'
        SC_NET = 'serverNetworkData'
        
        CS_CORE = 'clientCoreData'
        CS_SECURITY = 'clientSecurityData'
        CS_NET = 'clientNetworkData'
        
        USER_DATA_TYPES = {
            0xC001: CS_CORE,
            0xC002: CS_SECURITY,
            0xC003: CS_NET,
            
            0x0C01: SC_CORE,
            0x0C02: SC_SECURITY,
            0x0C03: SC_NET,
        }

    class Protocols(object):
        PROTOCOL_RDP = 'PROTOCOL_RDP'
        PROTOCOL_SSL = 'PROTOCOL_SSL'
        PROTOCOL_HYBRID = 'PROTOCOL_HYBRID'
        PROTOCOL_RDSTLS = 'PROTOCOL_RDSTLS'
        PROTOCOL_HYBRID_EX = 'PROTOCOL_HYBRID_EX'
        
        PROTOCOL_TYPES = {
            0x00000000: PROTOCOL_RDP,
            0x00000001: PROTOCOL_SSL,
            0x00000002: PROTOCOL_HYBRID,
            0x00000004: PROTOCOL_RDSTLS,
            0x00000008: PROTOCOL_HYBRID_EX,
        }
        
    class Security(object):
        SEC_HDR_BASIC = 'Basic'
        SEC_HDR_NON_FIPS = 'Non-FIPS'
        SEC_HEADER_TYPE = {
            1: SEC_HDR_BASIC,
            2: SEC_HDR_NON_FIPS,
            3: 'FIPS',
        }
        
        SEC_PKT_EXCHANGE = 'Client Security Exchange'
        SEC_PKT_INFO = 'Client Info'
        SEC_PKT_LICENSE = 'License'
        SEC_PACKET_TYPE = {
            0x0001: SEC_PKT_EXCHANGE,
            0x0040: SEC_PKT_INFO,
            0x0080: SEC_PKT_LICENSE,
        }
        SEC_PACKET_MASK = 0
        for key in SEC_PACKET_TYPE.keys():
            SEC_PACKET_MASK |= key
    
        ENCRYPTION_METHOD_NONE = 'ENCRYPTION_METHOD_NONE'
        ENCRYPTION_METHOD_40BIT = 'ENCRYPTION_METHOD_40BIT'
        ENCRYPTION_METHOD_128BIT = 'ENCRYPTION_METHOD_128BIT'
        ENCRYPTION_METHOD_56BIT = 'ENCRYPTION_METHOD_56BIT'
        ENCRYPTION_METHOD_FIPS = 'ENCRYPTION_METHOD_FIPS'
        
        SEC_ENCRYPTION_METHOD = {
            0x00000000: ENCRYPTION_METHOD_NONE,
            0x00000001: ENCRYPTION_METHOD_40BIT,
            0x00000002: ENCRYPTION_METHOD_128BIT,
            0x00000008: ENCRYPTION_METHOD_56BIT,
            0x00000010: ENCRYPTION_METHOD_FIPS,
        }
    
        SEC_ENCRYPTION_NONE = 'None'
        SEC_ENCRYPTION_LOW = 'Low'
        SEC_ENCRYPTION_CLIENT_COMPATIBLE = 'CLIENT_COMPATIBLE'
        SEC_ENCRYPTION_FIPS = 'FIPS'
        SEC_ENCRYPTION_LEVEL = {
            0: SEC_ENCRYPTION_NONE,
            1: SEC_ENCRYPTION_LOW,
            2: SEC_ENCRYPTION_CLIENT_COMPATIBLE,
            3: 'High',
            4: SEC_ENCRYPTION_FIPS,
        }
        
        # @property
        # def sec_header_type(self, rdp_context):
        #     if self.rdp_context.encryption_level == RdpSecurity.SEC_ENCRYPTION_FIPS:
        #         raise ValueError('not yet supported')
        #     elif self.is_SEC_ENCRYPT:
        #         return RdpSecurity.SEC_HDR_NON_FIPS
        #     elif self.rdp_context.encryption_level == RdpSecurity.SEC_ENCRYPTION_NONE:
        #         return RdpSecurity.SEC_HDR_BASIC
        #     elif (self.rdp_context.encrypted_client_random is None and 
        #             self.rdp_context.encryption_level == RdpSecurity.SEC_ENCRYPTION_LOW):
        #         return RdpSecurity.SEC_HDR_BASIC
        #     else:
        #         return RdpSecurity.SEC_HDR_NON_FIPS

class RdpUserDataBlock(BaseDataUnit):
    def __init__(self):
        super(RdpUserDataBlock, self).__init__(fields = [
            DataUnitField('header', 
                Rdp_TS_UD_HEADER(ValueDependency(lambda x: len(self)))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.header.length - len(self.header)))),
        ])
    
class Rdp_TS_UD_HEADER(BaseDataUnit):
    def __init__(self, length_value_dependency):
        super(Rdp_TS_UD_HEADER, self).__init__(fields = [
            PrimitiveField('type', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('length', 
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_16_LE),
                    length_value_dependency)),
        ])
        
    def get_type_name(self):
        return Rdp.UserData.USER_DATA_TYPES.get(self.type, 'unknown')

class Rdp_TS_UD_CS_CORE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_CS_CORE, self).__init__(fields = [
            PrimitiveField('version', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('desktopWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('desktopHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('colorDepth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('SASSequence', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('keyboardLayout', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('clientBuild', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('clientName', FixedLengthUtf16leEncodedStringSerializer(32)),
            PrimitiveField('keyboardType', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('keyboardSubType', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('keyboardFunctionKey', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('imeFileName', FixedLengthUtf16leEncodedStringSerializer(64)),
            OptionalField(
                PrimitiveField('postBeta2ColorDepth', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('clientProductId', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('serialNumber', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('highColorDepth', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('supportedColorDepths', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('earlyCapabilityFlags', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('clientDigProductId', FixedLengthUtf16leEncodedStringSerializer(64))),
            OptionalField(
                PrimitiveField('connectionType', StructEncodedSerializer(UINT_8))),
            OptionalField(
                PrimitiveField('pad1octet ', StructEncodedSerializer(PAD))),
            OptionalField(
                PrimitiveField('serverSelectedProtocol', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopPhysicalWidth', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopPhysicalHeight', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopOrientation', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('desktopScaleFactor', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('deviceScaleFactor', StructEncodedSerializer(UINT_32_LE))),
        ])

class Rdp_TS_UD_SC_CORE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_CORE, self).__init__(fields = [
            PrimitiveField('version', StructEncodedSerializer(UINT_32_LE)),
            OptionalField(
                PrimitiveField('clientRequestedProtocols', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('earlyCapabilityFlags', StructEncodedSerializer(UINT_32_LE))),
        ])
    
    def get_clientRequestedProtocols_name(self):
        return Rdp.Protocols.PROTOCOL_TYPES.get(self.clientRequestedProtocols, 'unknown')
    
class Rdp_TS_UD_SC_NET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_NET, self).__init__(fields = [
            PrimitiveField('MCSChannelId', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('channelCount', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('channelIdArray',
                ArraySerializer(
                        StructEncodedSerializer(UINT_16_LE),
                        LengthDependency(lambda x: self.channelCount * StructEncodedSerializer(UINT_16_LE).get_length(None)))),
            OptionalField(
                PrimitiveField('Pad', StructEncodedSerializer(PAD*2))),
        ])
        
class Rdp_TS_UD_SC_SEC1(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_SEC1, self).__init__(fields = [
            PrimitiveField('encryptionMethod', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('encryptionLevel', StructEncodedSerializer(UINT_32_LE)),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverRandomLen', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverCertLen', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverRandom', 
                    RawLengthSerializer(LengthDependency(lambda x: self.serverRandomLen)))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverCertificate', 
                    RawLengthSerializer(LengthDependency(lambda x: self.serverCertLen)))),
        ])
    
    def get_encryptionMethod_name(self):
        return Rdp.Security.SEC_ENCRYPTION_METHOD.get(self.encryptionMethod, 'unknown %d' % self.encryptionMethod)

    def get_encryptionLevel_name(self):
        return Rdp.Security.SEC_ENCRYPTION_LEVEL.get(self.encryptionLevel, 'unknown %d' % self.encryptionLevel)
