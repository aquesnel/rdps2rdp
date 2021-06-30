"""
Class diagram:
http://www.plantuml.com/plantuml/uml/jLF1RXen4BtxAqPxgHILg6al5LAZL4Mzj8SeX5DLhGoUWDjTUsNF1j68VwynXjdYPKKFuSRupNlptipUUPAEsheITluB5mGJIN9cDC6B09ZeKA6L96WzUYYk2z364qe5zWcA7p-B05fOGr8RTBlQiwnQzA4QEGu5KDhHPcJGxvvgsJJQB66Ej4OqO9r2XmfQ8sjKuD5fMUa_wFnR271f5EnVMfEWNSors9xENYvMkb8NEk3sQIALymg_QamCNxhsM3UEfUcDtplaAK93tLYl2QSCVdbDsrqTJlu8bgIj2UW3_C5QEYGbHFSVZ4QtS7pwfrfS5JtvYBmKm7q9z2DFDoRwicDzPXD7DmLNn_0Wrz_HB6bLmESfEBak6xcfh5Gb9rVUYB09ABA1nf30MVFJuHZIDN-wXVc6ufapBro5ESzhRlUg1yDZk9_Ceb2ZsaYTkX9DfXu8uY-oX9lqROtgahdBv_UHtpgzr4PMtUaTrb8RXOwBszvWPzhGnyXFpMygQTDWnrwGkAIhYgl9-WRMoBrvfg7vt29Z2-o6F1cv6mZlyaE-nxCsjyEQUukPvNxTctUzmjpsNz8feJooN7pWW0VIpa_uyVxR8-kfK2_Ry92qECF4dAz1G4eiyywOqq-ZtzlWznK0WvyOqwIfMObT9PKxDAgjgxy0
"""

import struct
import functools
import collections
import collections.abc
import pprint
import contextlib
import copy

import utils
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
    
    RawLengthSerializer,
    LengthDependency,
    DependentValueSerializer,
    ValueDependency,
)

from typing import Any, Sequence, Callable, TypeVar, Generic, Union, Dict


# FIELD_VALUE_TYPE = TypeVar('FIELD_VALUE_TYPE')


def is_int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False
        
def traverse_object_graph(value, path):
    # try:
        for field_name in path.split("."):
            # if is_int(field_name):
            #     try:
            #         # print('getting field name with numerical value %s' % field_name)
            #         value = value[int(field_name)]
            #         continue
            #     except IndexError:
            #         pass
            value = getattr(value, field_name)
        return value
    # except AttributeError as e:
    #     raise AttributeError('Getting "%s" from %s' % (path, value), e)
    #     raise e


def lookup_name_in(names_by_value):
    def lookup_name_in_inner(value):
        if isinstance(value, list):
            result = ['%s (%s)' % (names_by_value.get(v, '<unknown>'), v) for v in value]
        elif isinstance(value, set):
            result = {'%s (%s)' % (names_by_value.get(v, '<unknown>'), v) for v in value}
        else:
            result = '%s (%s)' % (names_by_value.get(value, '<unknown>'), value)
        return result
    return lookup_name_in_inner


def add_constants_names_mapping(constants_prefix, mapping_name=None):
    if not mapping_name:
        mapping_name = constants_prefix + '_NAMES'
    def class_decorator(cls):
        mapping = {}
        for k,v in cls.__dict__.items():
            if k.startswith(constants_prefix):
                mapping[v] = k
        setattr(cls, mapping_name, mapping)
        return cls
    return class_decorator

class SerializationException(Exception):
    pass

class SerializationContext(object):
    def __init__(self):
        self._debug_field_path = []
        self._force_dirty = False
        
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


class BaseField(object):
    """
    Container that associates a serializer with it's value.
    """
    def __init__(self, name):
        self.name = name

    def get_human_readable_value(self):
        return self.get_value()

    # def get_alias_hint(self):
    #     return None

    def get_pdu_types(self, rdp_context):
        return []

    def get_value(self) -> Any:
        raise NotImplementedError()
    
    def set_value(self, value: Any):
        raise NotImplementedError()
    
    def get_length(self):
        raise NotImplementedError()

    def is_dirty(self) -> bool:
        raise NotImplementedError()
    
    def deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        with serde_context.field_context(self) as _:
            try:
                return self._deserialize_value(raw_data, offset, serde_context)
            except Exception as e:
                raise SerializationException(
                    'Error deserializing "%s" from raw_data length %d, offset %d' % (
                        self.name, len(raw_data), offset)) from e
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        raise NotImplementedError()
    
    def serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        with serde_context.field_context(self) as _:
            try:
                return self._serialize_value(buffer, offset, serde_context)
            except Exception as e:
                raise SerializationException(
                    'Error serializing "%s" into buffer length %d, offset %d' % (
                        self.name, len(buffer), offset)) from e

    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        raise NotImplementedError()
        
class PrimitiveField(BaseField):
    def __init__(self, name, serializer, to_human_readable = lambda x: x):
        super().__init__(name)
        self.serializer = serializer
        self._to_human_readable = to_human_readable
        self.value = None
        self.raw_value = None
        self.is_value_dirty = False
        self._deserialize_value_snapshot = None

    def __str__(self):
        return '<PrimitiveField(name=%s, serializer=%s)>' % (
            self.name, self.serializer)

    def get_human_readable_value(self):
        return self._to_human_readable(self.get_value())

    def get_value(self) -> Any:
        if self.is_dirty():
            return self.value
        if self.raw_value is None:
            raise ValueError('Field has not been deserialized yet')
        return self.value

    def set_value(self, value: Any):
        self.is_value_dirty = True
        self.value = value

    def get_length(self):
        if self.is_dirty():
            return self.serializer.get_serialized_length(self.get_value())
        else:
            return len(self.raw_value)
        
    def is_dirty(self) -> bool:
        # if self._deserialize_value_snapshot:
        #     print('is_dirty by snapshot (%s): %s vs %s' % (self.value != self._deserialize_value_snapshot, self.value, self._deserialize_value_snapshot))
        return (self.is_value_dirty 
                or (self._deserialize_value_snapshot is not None
                    and self.value != self._deserialize_value_snapshot))

    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        value, length = self.serializer.unpack_from(raw_data, offset)
        self.value = value
        if isinstance(value, collections.abc.Iterable) and not isinstance(value, memoryview):
            self._deserialize_value_snapshot = copy.copy(value)
        self.is_value_dirty = False
        # utils.assertEqual(length, self.serializer.get_serialized_length(value))
        # length = self.serializer.get_serialized_length(value)
        self.raw_value = memoryview(raw_data)[offset : offset+length]
        return length
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        # print('Serializing: is_dirty? %s for %s' % (self.is_dirty(), serde_context.get_debug_field_path()))
        if self.is_dirty() or serde_context.get_force_is_dirty():
            length = self.serializer.pack_into(buffer, offset, self.value)
        else:
            length = len(self.raw_value)
            utils.assertLessEqual(offset+length, len(buffer))
            buffer[offset : offset+length] = self.raw_value
        return length

class DataUnitField(BaseField):
    def __init__(self, name, data_unit):
        self.name = name
        self.data_unit = data_unit
    
    def __str__(self):
        return '<DataUnitField(name=%s, data_unit class=%s)>' % (
            self.name, self.data_unit.__class__)

    def get_pdu_types(self, rdp_context):
        return self.data_unit.get_pdu_types(rdp_context)

    def get_value(self) -> Any:
        return self.data_unit

    def set_value(self, value: Any):
        self.data_unit = value

    def get_length(self):
        return self.data_unit.get_length()
        
    def is_dirty(self) -> bool:
        return self.data_unit.is_dirty()
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        return self.data_unit.deserialize_value(raw_data, offset, serde_context)
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        return self.data_unit.serialize_value(buffer, offset, serde_context)

class RemainingRawField(BaseField):
    def __init__(self, name, orig_raw_value, offset):
        self.name = name
        self.orig_raw_value = orig_raw_value
        self.offset = offset
        self.remaining = memoryview(orig_raw_value)[offset:]

    def __str__(self):
        return '<RemainingRawField(orig_len=%d, offset=%d)>' % (
            len(self.orig_raw_value), self.offset)

    def get_value(self) -> Any:
        return self.remaining

    def set_value(self, value: Any):
        raise NotImplementedError('RemainingRawField does not support being set')

    def get_length(self):
        return len(self.remaining)

    def is_dirty(self) -> bool:
        return False
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        raise NotImplementedError('RemainingRawField does not support being deserialized')
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
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

    def get_human_readable_value(self):
        return str(self)

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

    def is_dirty(self) -> bool:
        return False
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        return 0
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        return 0

class OptionalField(BaseField):
    def __init__(self, optional_field):
        self._optional_field = optional_field
        self._value_is_present = False

    def __str__(self):
        return '<OptionalField(is_present=%s, field=%s)>' % (
            self._value_is_present, self._optional_field)

    @property
    def name(self):
        return self._optional_field.name

    def get_human_readable_value(self):
        if self._value_is_present:
            return self._optional_field.get_human_readable_value()
        else:
            return None

    def get_pdu_types(self, rdp_context):
        if self._value_is_present:
            return self._optional_field.get_pdu_types(rdp_context)
        else:
            return []

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

    def is_dirty(self) -> bool:
        if self._value_is_present:
            return self._optional_field.is_dirty()
        else:
            return False
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        length = 0
        try:
            length = self._optional_field._deserialize_value(raw_data, offset, serde_context)
            self._value_is_present = True
        except struct.error:
            pass    
        return length
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        if self._value_is_present:
            return self._optional_field.serialize_value(buffer, offset, serde_context)
        else:
            return 0

class ConditionallyPresentField(BaseField):
    def __init__(self, is_present_condition, optional_field):
        self._optional_field = optional_field
        self._is_present_condition = is_present_condition

    def __str__(self):
        return '<ConditionallyPresentField(is_present=%s, field=%s)>' % (
            self._is_present_condition(), self._optional_field)

    @property
    def name(self):
        return self._optional_field.name
        
    def get_human_readable_value(self):
        if self._is_present_condition():
            return self._optional_field.get_human_readable_value()
        else:
            return None

    def get_pdu_types(self, rdp_context):
        if self._is_present_condition():
            return self._optional_field.get_pdu_types(rdp_context)
        else:
            return []
            
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

    def is_dirty(self) -> bool:
        if self._is_present_condition():
            return self._optional_field.is_dirty()
        else:
            return False
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        if self._is_present_condition():
            return self._optional_field._deserialize_value(raw_data, offset, serde_context)
        else:
            return 0
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        if self._is_present_condition():
            return self._optional_field.serialize_value(buffer, offset, serde_context)
        else:
            return 0

class UnionField(BaseField):
    def __init__(self, fields):
        self.name = 'UnionField'
        self._fields = fields
    
    def __str__(self):
        return '<UnionField(fields=%s)>' % (
            [f.name for f in self._fields])
    
    def get_human_readable_value(self):
        return str(self)

    def get_pdu_types(self, rdp_context):
        retval = []
        for f in self._fields:
            retval.extend(f.get_pdu_types(rdp_context))
        return retval

    def get_length(self):
        length = None
        for f in self._fields:
            if length is None:
                length = f.get_length()
            else:
                if length != f.get_length():
                    raise ValueError('The length of all fields in the UnionField is not all the same')
        return length
    
    def is_dirty(self) -> bool:
        for f in self._fields:
            if f.is_dirty():
                return True
        return False
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        for f in self._fields:
            length = f.deserialize_value(raw_data, offset, serde_context)
        return length
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        length = 0
        force_is_dirty = None
        for f in self._fields:
            if f.is_dirty():
                force_is_dirty = True
                break

        with serde_context.dirty_context(force_is_dirty):
            for f in self._fields:
                length = f.get_length()
                shared_data = memoryview(bytearray(length))
                f.serialize_value(shared_data, 0, serde_context)
                # import utils ; print('field %s serialized to %s' % (f.name, utils.as_hex_str(bytes(shared_data))))
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
        
    def get_human_readable_value(self):
        return self._field.get_human_readable_value()

    def get_pdu_types(self, rdp_context):
        return self._field.get_pdu_types(rdp_context)
        
    def get_length(self):
        return 0

    def get_value(self) -> Any:
        return self._field.get_value()
        
    def set_value(self, value: Any):
        self._field.set_value(value)
        
    def is_dirty(self) -> bool:
        return self._field.is_dirty()
    
    def _deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        return 0
    
    def _serialize_value(self, buffer: bytes, offset: int, serde_context: SerializationContext) -> int:
        return 0

AutoReinterpretConfig = collections.namedtuple('AutoReinterpretConfig', ['alias_hint', 'factory'])
AUTO_REINTERPRET_TYPE_ID = TypeVar('AUTO_REINTERPRET_TYPE_ID')

class AutoReinterpretBase(object):
    def auto_reinterpret(self, data_unit):
        raise NotImplementedError()

class AutoReinterpret(AutoReinterpretBase):
    def __init__(self, 
            field_to_reinterpret_name: str,
            type_getter: ValueDependency[AUTO_REINTERPRET_TYPE_ID], 
            config_by_type: Dict[AUTO_REINTERPRET_TYPE_ID, AutoReinterpretConfig]):
        self.field_to_reinterpret_name = field_to_reinterpret_name
        self.type_getter = type_getter
        self.config_by_type = config_by_type

    # def get_alias_hint(self, data_unit):
    #     type = self.type_getter.get_value(data_unit)
    #     if type in self.config_by_type:
    #         reinterpret_config = self.config_by_type[type]
    #         return reinterpret_config.alias_hint
    #     return None

    def auto_reinterpret(self, data_unit):
        type = self.type_getter.get_value(data_unit)
        if type in self.config_by_type:
            reinterpret_config = self.config_by_type[type]
            data_unit.reinterpret_field(
                    self.field_to_reinterpret_name, 
                    DataUnitField(
                        self.field_to_reinterpret_name, 
                        reinterpret_config.factory()), 
                    allow_overwrite = True)

class ArrayAutoReinterpret(AutoReinterpretBase):
    def __init__(self, 
            array_field_to_reinterpret_name: str,
            item_field_to_reinterpret_name: str,
            type_getter: ValueDependency[AUTO_REINTERPRET_TYPE_ID], 
            type_mapping: Dict[AUTO_REINTERPRET_TYPE_ID, AutoReinterpretConfig]):
        self.array_field_to_reinterpret_name = array_field_to_reinterpret_name
        self.item_field_to_reinterpret_name = item_field_to_reinterpret_name
        self.type_getter = type_getter
        self.type_mapping = type_mapping

    def auto_reinterpret(self, data_unit):
        array_value = traverse_object_graph(data_unit, self.array_field_to_reinterpret_name)
        
        if isinstance(array_value, ArrayDataUnit):
            array_value = array_value.fields_as_array()
        if not isinstance(array_value, list):
            raise ValueError('array field must be a list')
            
        for i, item in enumerate(array_value):
            item_type = self.type_getter.get_value(item)
            if item_type in self.type_mapping:
                item_reinterpret_config = self.type_mapping[item_type]
                item.reinterpret_field(
                        self.item_field_to_reinterpret_name, 
                        DataUnitField(
                            self.item_field_to_reinterpret_name, 
                            item_reinterpret_config.factory()), 
                        allow_overwrite = True)
                # data_unit.alias_field(item_reinterpret_config.name, '%s.%d.%s' % (self.array_field_to_reinterpret_name, i, self.item_field_to_reinterpret_name))
                data_unit.alias_field(item_reinterpret_config.name, '%s.%d' % (self.array_field_to_reinterpret_name, i))

class BaseDataUnit(object):
    def __init__(self, fields, auto_reinterpret_configs = None, use_class_as_pdu_name = False):
        super(BaseDataUnit, self).__setattr__('_fields_by_name', {})
        if auto_reinterpret_configs is None:
            auto_reinterpret_configs = []
        self._auto_reinterpret_configs = auto_reinterpret_configs
        self._use_class_as_pdu_name = use_class_as_pdu_name
        self._fields = []
        for f in fields:
            self._fields.append(f)
            if isinstance(f, UnionField):
                for uf in f.get_union_fields():
                    self._fields.append(uf)
        for f in self._fields:
            if not isinstance(f, UnionField):
                self._fields_by_name[f.name] = f
        self._raw_value = None
        

    def __getattr__(self, name: str) -> Any:
        if name in self._fields_by_name:
            f = self._fields_by_name[name]
            if isinstance(f, ReferenceField):
                return f.get_referenced_value()
            return f.get_value()
        else:
            raise AttributeError('Class <%s> does not have a field named: %s' % (self.__class__.__name__, name))
        
    def __setattr__(self, name: str, value: Any):
        if name not in self._fields_by_name:
            super(BaseDataUnit, self).__setattr__(name, value)
        else:
            f = self._fields_by_name[name]
            f.set_value(value)

    def has_path(self, path):
        try:
            traverse_object_graph(self, path)
            return True
        except Exception:
            return False

    def get_length(self):
        total_length = 0
        for f in self._fields:
            length = f.get_length()
            total_length += length
            # print('field %s has length %d' % (f.name, length))
        return total_length

    def is_dirty(self) -> bool:
        for f in self._fields:
            if f.is_dirty():
                return True
        return False
    
    def __str__(self):
        return pprint.pformat(self._as_dict_for_pprint(), width=160)

    def get_pdu_name(self, rdp_context):
        types = self.get_pdu_types(rdp_context)
        if types:
            return ' '.join(types)
        else:
            return 'Unknown'
        
    def get_pdu_types(self, rdp_context):
        retval = []
        if self._use_class_as_pdu_name:
            retval.append(str(self.__class__))
        for f in self._fields:
            retval.extend(f.get_pdu_types(rdp_context))
        return retval
        
    def _as_dict_for_pprint(self):
        # HACK for pprint sorting dict in custom order
        # https://stackoverflow.com/a/32188121/561476 for custom ordering
        # https://stackoverflow.com/a/4902870/561476 for simplified code as namedtuple
        ItemKey = collections.namedtuple('ItemKey', ['position', 'name'])
        ItemKey.__repr__ = lambda x: x.name

        result = {}
        result[ItemKey(-1, '__python_type__')] = self.__class__        
        for field_index, f in enumerate(self._fields):
            v = f.get_human_readable_value()
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
                        s = "b'%s'" % utils.as_hex_str(v)
                    else:
                        s = "b'%s...%s'" % (utils.as_hex_str(v[:4]), utils.as_hex_str(v[-4:]))
                    v = '<bytes(len %d): %s>' % (length, s)
                v_list[value_index] = v
            if len(v_list) == 1:
                v = v_list[0]
            else:
                v = v_list
            
            result[ItemKey(field_index, f.name)] = v
        return result
        
    def with_value(self, raw_data: bytes):
        self.deserialize_value(memoryview(raw_data), 0, SerializationContext())
        return self

    def deserialize_value(self, raw_data: bytes, orig_offset: int, serde_context: SerializationContext) -> int:
        offset = orig_offset
        for f in self._fields:
            length = f.deserialize_value(raw_data, offset, serde_context)
            offset += length
        self._raw_value = memoryview(raw_data[orig_offset:offset])
        for config in self._auto_reinterpret_configs:
            config.auto_reinterpret(self)
        return offset - orig_offset

    def serialize_value(self, buffer: bytes, orig_offset: int, serde_context: SerializationContext) -> int:
        if not self.is_dirty():
            length = len(self._raw_value)
            buffer[orig_offset : orig_offset+length] = self._raw_value
            return length
        # print('Serializing: DataUnit is reserializing fields for %s' % serde_context.get_debug_field_path())
        offset = orig_offset
        for f in self._fields:
            length = f.serialize_value(buffer, offset, serde_context)
            offset += length
        return offset - orig_offset

    def as_wire_bytes(self):
        buffer = bytearray(self.get_length())
        length = self.serialize_value(memoryview(buffer), 0, SerializationContext())
        if length != len(buffer):
            raise ValueError('Unexpected serialized length: expected %d, got %d' % (len(buffer), length))
        return buffer

    # def get_alias_hint(self):
    #     return None
        
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
        serde_context = SerializationContext()
        for i, f in enumerate(self._fields):
            if f.name == name_to_reinterpret:
                if isinstance(f, ReferenceField):
                    raise ValueError('reinterpreting reference fields is not supported. Reinterpret the field by using the original path: %s' % (f.get_referenced_path()))
                if use_remainder and isinstance(f, RemainingRawField):
                    orig_raw_value = f.orig_raw_value
                    orig_remaining = f.get_value()
                    length = new_field.deserialize_value(orig_remaining, 0, serde_context)
                    remaining_field = RemainingRawField(f.name, orig_raw_value, f.offset + length)
                else:
                    orig_raw_value = bytearray(f.get_length())
                    length = f.serialize_value(orig_raw_value, 0, serde_context)
                    orig_raw_value = orig_raw_value[:length]
                    
                    length = new_field.deserialize_value(orig_raw_value, 0, serde_context)
                    remaining_field = RemainingRawField(f.name, orig_raw_value, length)
                
                if new_field.name == remaining_field.name:
                    if len(remaining_field.get_value()) > 0:
                        pass
                        raise ValueError(
                            ('Cannot overwrite field "%s" because not all of the bytes were consumed during '
                                + 'the re-interpretation as %s. Existing length %d, consumed length %d. '
                                + 'Original bytes: %s, reinterprested_field: %s') % (
                            remaining_field.name, 
                            new_field, 
                            len(remaining_field.get_value()) + length, 
                            length,
                            utils.as_hex_str(orig_raw_value),
                            new_field.get_human_readable_value()))
                else:
                    self._fields_by_name[remaining_field.name] = remaining_field
                    self._fields.insert(i+1, remaining_field)

                self._fields_by_name[new_field.name] = new_field
                self._fields[i] = new_field
                break


class RawDataUnit(BaseDataUnit):
    def __init__(self):
        super().__init__(fields = [
            PrimitiveField('payload', RawLengthSerializer()),
        ])
       
    @staticmethod 
    def parse(data):
        pdu = RawDataUnit()
        pdu.deserialize_value(memoryview(data))
        return pdu

class ArrayDataUnit(BaseDataUnit):
    def __init__(self, 
            data_unit_factory,
            alias_hinter = None,
            length_dependency = None,
            item_count_dependency = None):
        super().__init__(fields = [])
        self._data_unit_factory = data_unit_factory
        self._length_dependency = length_dependency
        self._item_count_dependency = item_count_dependency
        self._alias_hinter = alias_hinter

        if ((length_dependency is None and item_count_dependency is None)
                or (length_dependency is not None and item_count_dependency is not None)):
            raise ValueError('Only one of length_dependency or item_count_dependency must be specified. length_dependency = %s, item_count_dependency = %s' % (
                length_dependency, item_count_dependency))

    def __len__(self):
        return len(self.fields_as_array())
    
    def __iter__(self):
        return iter(self.fields_as_array())

    def __getitem__(self, subscript):
        if isinstance(subscript, slice):
            # do your handling for a slice object:
            return self.fields_as_array()[subscript.start : subscript.stop : subscript.step]
        else:
            # Do your handling for a plain index
            return self.fields_as_array()[subscript]

    def fields_as_array(self):
        return [f.get_value() for f in self._fields if isinstance(f, DataUnitField)]

    def deserialize_value(self, raw_data: bytes, orig_offset: int, serde_context: SerializationContext) -> int:
        consumed = 0
        items_parsed = 0
        
        if len(self._fields) > 0:
            raise ValueError('Unsupported: ArrayDataUnit is being deserialized twice')
        
        if self._length_dependency:
            length = self._length_dependency.get_length(raw_data)
            has_more_items = lambda: consumed < length
        elif self._item_count_dependency:
            max_items = self._item_count_dependency.get_value(None)
            has_more_items = lambda: items_parsed < max_items
            
        i = 0
        while has_more_items():
            item = self._data_unit_factory()
            item_length = item.deserialize_value(raw_data, orig_offset + consumed, serde_context)
            utils.assertEqual(item_length, item.get_length())
            field_name = '%d' % i
            field_item = DataUnitField(field_name, item)
            self._fields_by_name[field_name] = field_item
            self._fields.append(field_item)
            if self._alias_hinter:
                alias = self._alias_hinter.get_value(item)
                if alias:
                    self.alias_field(alias, field_name)
            consumed += item_length
            items_parsed += 1
            i += 1

        self._raw_value = memoryview(raw_data[orig_offset: orig_offset+consumed])
        return consumed

    def get_pdu_types(self, rdp_context):
        retval = ["["]
        for f in self.self._fields:
            field_pdu_types = f.get_pdu_types(rdp_context)
            if len(field_pdu_types) > 0:
                retval.extend(field_pdu_types)
                retval.append(",")
        if len(retval) == 1:
            return []
        retval = retval[:-2]
        retval.append("]")
        return retval

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
        
    def deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        result = super(BerEncodedDataUnit, self).deserialize_value(raw_data, offset, serde_context)
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
    def __init__(self, length_range, interpret_payload_as: Union[BaseSerializer[Any], BaseDataUnit] = None):
        super(PerEncodedDataUnit, self).__init__(fields = [
            PrimitiveField('length', 
                DependentValueSerializer(
                    PerEncodedLengthSerializer(length_range),
                    ValueDependency(lambda x: self._fields_by_name['payload'].get_length()))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.length)))
        ])
        self._interpret_payload_as = interpret_payload_as
    
    def deserialize_value(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> int:
        result = super(PerEncodedDataUnit, self).deserialize_value(raw_data, offset, serde_context)
        # auto re-interprert the payload based on the given DataUnit
        if self._interpret_payload_as is not None:
            if isinstance(self._interpret_payload_as, BaseDataUnit):
                new_field = DataUnitField('payload', self._interpret_payload_as)
            else:
                new_field = PrimitiveField('payload', self._interpret_payload_as)
            self.reinterpret_field('payload', new_field, allow_overwrite = True)
        return result


