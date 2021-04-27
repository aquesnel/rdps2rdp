"""
Class diagram:
http://www.plantuml.com/plantuml/uml/jLF1RXen4BtxAqPxgHILg6al5LAZL4Mzj8SeX5DLhGoUWDjTUsNF1j68VwynXjdYPKKFuSRupNlptipUUPAEsheITluB5mGJIN9cDC6B09ZeKA6L96WzUYYk2z364qe5zWcA7p-B05fOGr8RTBlQiwnQzA4QEGu5KDhHPcJGxvvgsJJQB66Ej4OqO9r2XmfQ8sjKuD5fMUa_wFnR271f5EnVMfEWNSors9xENYvMkb8NEk3sQIALymg_QamCNxhsM3UEfUcDtplaAK93tLYl2QSCVdbDsrqTJlu8bgIj2UW3_C5QEYGbHFSVZ4QtS7pwfrfS5JtvYBmKm7q9z2DFDoRwicDzPXD7DmLNn_0Wrz_HB6bLmESfEBak6xcfh5Gb9rVUYB09ABA1nf30MVFJuHZIDN-wXVc6ufapBro5ESzhRlUg1yDZk9_Ceb2ZsaYTkX9DfXu8uY-oX9lqROtgahdBv_UHtpgzr4PMtUaTrb8RXOwBszvWPzhGnyXFpMygQTDWnrwGkAIhYgl9-WRMoBrvfg7vt29Z2-o6F1cv6mZlyaE-nxCsjyEQUukPvNxTctUzmjpsNz8feJooN7pWW0VIpa_uyVxR8-kfK2_Ry92qECF4dAz1G4eiyywOqq-ZtzlWznK0WvyOqwIfMObT9PKxDAgjgxy0
"""

import struct
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
    EncodedStringSerializer,
    FixedLengthEncodedStringSerializer,
    Utf16leEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    ArraySerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    ValueTransformSerializer,
    
    DataUnitSerializer,
    RawLengthSerializer,
    LengthDependency,
    DependentValueSerializer,
    ValueDependency,
    )

from typing import Any, Sequence, Callable, TypeVar, Generic, Union


# FIELD_VALUE_TYPE = TypeVar('FIELD_VALUE_TYPE')


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
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        try:
            return self._serialize_value(buffer, offset)
        except Exception as e:
            raise SerializationException(
                'Error serializing "%s" into buffer length %d, offset %d' % (
                    self.name, len(buffer), offset)) from e

    def _serialize_value(self, buffer: bytes, offset: int) -> int:
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
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
        if self.is_value_dirty:
            self.serializer.pack_into(buffer, offset, self.value)
            length = self.serializer.get_length(self.value)
        else:
            length = len(self.raw_value)
            buffer[offset : offset+length] = self.raw_value
        return length

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
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
        return self.data_unit.serialize_value(buffer, offset)

class RemainingRawField(BaseField):
    def __init__(self, name, orig_raw_value, offset):
        self.name = name
        self.orig_raw_value = orig_raw_value
        self.offset = offset
        self.remaining = memoryview(orig_raw_value)[offset:]

    def get_value(self) -> Any:
        return self.remaining

    def set_value(self, value: Any):
        raise NotImplementedError('RemainingRawField does not support being set')

    def get_length(self):
        return len(self.remaining)

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        raise NotImplementedError('RemainingRawField does not support being deserialized')
    
    def serialize_value(self, buffer: bytes, offset: int) -> int:
        length = self.get_length()
        buffer[offset: offset+length] = self.remaining
        return length
        
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

    def get_referenced_path(self) -> str:
        return self._referenced_value_path
        
    def get_length(self):
        return 0

    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        return 0
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
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
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
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
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
        if self._is_present_condition():
            return self._optional_field.serialize_value(buffer, offset)
        else:
            return 0

class UnionField(BaseField):
    def __init__(self, fields):
        self.name = 'UnionField'
        self._fields = fields
    
    def __str__(self):
        return '<UnionField(fields=%s)>' % (
            [f.name for f in self._fields])
    
    def get_length(self):
        length = None
        for f in self._fields:
            if length is None:
                length = f.get_length()
            else:
                if length != f.get_length():
                    raise ValueError('The length of all fields in the UnionField is not all the same')
        return length
    
    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        for f in self._fields:
            length = f.deserialize_value(raw_data, offset)
        return length
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
        length = 0
        for f in self._fields:
            length = f.get_length()
            shared_data = memoryview(bytearray(length))
            f.serialize_value(shared_data, 0)
            for i in range(length):
                buffer[offset+i] |= shared_data[i]
        return length
        
    def get_union_fields(self):
        return (UnionWrapperField(f) for f in self._fields)

class UnionWrapperField(BaseField):
    def __init__(self, field):
        self._field = field

    @property
    def name(self):
        return self._field.name
        
    def get_length(self):
        return 0

    def get_value(self) -> Any:
        return self._field.get_value()
        
    def set_value(self, value: Any):
        self._field.set_value(value)
        
    def _deserialize_value(self, raw_data: bytes, offset: int) -> int:
        return 0
    
    def _serialize_value(self, buffer: bytes, offset: int) -> int:
        return 0

class BaseDataUnit(object):
    def __init__(self, fields):
        super(BaseDataUnit, self).__setattr__('_fields_by_name', {})
        self._fields = []
        for f in fields:
            self._fields.append(f)
            if isinstance(f, UnionField):
                for uf in f.get_union_fields():
                    self._fields.append(uf)
        for f in self._fields:
            if not isinstance(f, UnionField):
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
        return pprint.pformat(self._as_dict_for_pprint(), width=160)

    def _as_dict_for_pprint(self):
        # HACK for pprint sorting dict in custom order
        # https://stackoverflow.com/a/32188121/561476 for custom ordering
        # https://stackoverflow.com/a/4902870/561476 for simplified code as namedtuple
        ItemKey = collections.namedtuple('ItemKey', ['position', 'name'])
        ItemKey.__repr__ = lambda x: x.name

        result = {}
        result[ItemKey(-1, '__python_type__')] = self.__class__        
        for field_index, f in enumerate(self._fields):
            if isinstance(f, ReferenceField) or isinstance(f, UnionField):
                v = str(f)
            else:
                v = f.get_value()
            if not isinstance(v, list):
                v_list = [v]
            else:
                v_list = v[:]
            for value_index, v in enumerate(v_list):
                if isinstance(v, BaseDataUnit):
                    v = v._as_dict_for_pprint()
                elif isinstance(v, (bytes, bytearray, memoryview)):
                    length = len(v)
                    if length < 10:
                        s = "b'%s'" % as_hex_str(v)
                    else:
                        s = "b'%s...%s'" % (as_hex_str(v[:4]), as_hex_str(v[-4:]))
                    v = '<bytes(len %d): %s>' % (length, s)
                v_list[value_index] = v
            if len(v_list) == 1:
                v = v_list[0]
            else:
                v = v_list
            
            result[ItemKey(field_index, f.name)] = v
        return result

    def deserialize_value(self, raw_data: bytes, orig_offset: int = 0) -> int:
        offset = orig_offset
        for f in self._fields:
            length = f.deserialize_value(raw_data, offset)
            offset += length
        return offset - orig_offset

    def serialize_value(self, buffer: bytes, orig_offset: int = 0) -> int:
        offset = orig_offset
        for f in self._fields:
            length = f.serialize_value(buffer, offset)
            offset += length
        return offset - orig_offset

    def as_wire_bytes(self):
        buffer = bytearray(self.get_length())
        length = self.serialize_value(memoryview(buffer))
        if length != len(buffer):
            raise ValueError('Unexpected serialized length: expected %d, got %d' % (len(buffer), length))
        return buffer

    def alias_field(self, new_name, path):
        if new_name in self._fields_by_name:
            raise ValueError('the field "%s" already exists and therefor cannot be an alias' % (new_name))
        new_field = ReferenceField(new_name, self, path)
        self._fields_by_name[new_field.name] = new_field
        self._fields.append(new_field)


    def reinterpret_field(self, name_to_reinterpret, new_field, allow_overwrite = False):
        use_remainder = False
        if '.' in name_to_reinterpret and not name_to_reinterpret.endswith('.remaining'):
            raise ValueError('Invalid reinterpert suffix: %s' % (name_to_reinterpret))
        if name_to_reinterpret.endswith('.remaining'):
            use_remainder = True
            name_to_reinterpret = name_to_reinterpret[:-1 * len('.remaining')]
        
        if name_to_reinterpret not in self._fields_by_name:
            raise AttributeError('field "%s" does not exist' % (name_to_reinterpret))
        if not allow_overwrite and new_field.name in self._fields_by_name:
            raise AttributeError('field "%s" already exist' % (new_field.name))
        
        for i, f in enumerate(self._fields):
            if f.name == name_to_reinterpret:
                if isinstance(f, ReferenceField):
                    raise ValueError('reinterpreting reference fields is not supported. Reinterpret the field by using the original path: %s' % (f.get_referenced_path()))
                if use_remainder and isinstance(f, RemainingRawField):
                    # if not isinstance(f, RemainingRawField):
                    #     raise ValueError('field "%s" must be of type RemainingRawField' % (f.name))
                    orig_raw_value = f.orig_raw_value
                    orig_remaining = f.get_value()
                    length = new_field.deserialize_value(orig_remaining, 0)
                    remaining_field = RemainingRawField(f.name, orig_raw_value, f.offset + length)
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
            self.reinterpret_field('payload', new_field, allow_overwrite = True)
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
            self.reinterpret_field('payload', new_field, allow_overwrite = True)
        return result


