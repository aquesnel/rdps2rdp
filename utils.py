import collections.abc
import enum
import functools
import inspect
import json
import unittest

DEBUG = False
# DEBUG = True

def as_hex_str(b):
    return " ".join("{:02x}".format(x) for x in b)

if True:
    test_case = unittest.TestCase()
    assertEqual = test_case.assertEqual
    assertLessEqual = test_case.assertLessEqual
else:
    def noop(*argv, **argkw):
        pass
    assertEqual = noop
    assertLessEqual = noop
    
def log(value, do_print = False, name = ''):
    if do_print: print('%s%s%s' % (name, ': ' if name else '', value))
    return value

def to_dict(self, is_recursive = True, path = '$', field_filter = lambda x: True):
    d = {}
    for k,v in self.__dict__.items():
        path_k = '%s.%s' % (path, k)
        if DEBUG: print('to_dict: path_k = %s' % path_k)
        if callable(v):
            continue
        elif not field_filter(path_k):
            continue
        
        if is_recursive:
            if isinstance(v, str):
                pass
            elif isinstance(v, collections.abc.Mapping):
                temp = {}
                for k1, v1 in v.items():
                    if hasattr(v1, 'to_dict'):
                        v1 = v1.to_dict(path = '%s.%s' % (path_k, k1))
                    temp[k1] = v1
                v = temp
            elif isinstance(v, collections.abc.Iterable):
                v = [(e.to_dict(path = '%s.%s' % (path_k, i)) if hasattr(e, 'to_dict') else e) for i, e in enumerate(v)]
            elif hasattr(v, 'to_dict'):
                v = v.to_dict(path = path_k)
        d[k] = v
    return d

def to_json_value(v):
    return to_json_dict(v)

def to_json_dict(d):
    if isinstance(d, collections.abc.Mapping):
        temp = {}
        for k,v in d.items():
            if hasattr(k, 'to_json_key'):
                k = k.to_json_key()
            elif isinstance(k, enum.Enum):
                k = k.name
            temp[k] = to_json_dict(v)
        d = temp
    elif isinstance(d, enum.Enum):
        d = d.name
    elif isinstance(d, str):
        pass
    elif isinstance(d, collections.abc.Iterable):
        d = [to_json_dict(e) for e in d]
    return d

def from_json_value(value_cls, d, default = None):
    if d is None and default is not None:
        d = default
    elif isinstance(d, value_cls):
        pass
    elif isinstance(d, collections.abc.Mapping):
        d = value_cls.from_json(d)
    elif isinstance(d, str):
        if DEBUG: print('from_json_dict: d = %s' % d)
        if issubclass(value_cls, enum.Enum):
            if d in (None, 'None'):
                d = None
            else:
                d = value_cls[d]

    return d
    
def from_json_list(value_cls, d):
    return from_json_dict(None, value_cls, d)

def from_json_dict(key_cls, value_cls, d):
    if isinstance(d, collections.abc.Mapping):
        temp = {}
        for k,v in d.items():
            if issubclass(key_cls, enum.Enum):
                if k in (None, 'None'):
                    k = None
                else:
                    k = key_cls[k]
            elif not isinstance(k, key_cls) and hasattr(key_cls, 'from_json_key'):
                k = key_cls.from_json_key(k)
            if not isinstance(v, value_cls) and hasattr(value_cls, 'from_json'):
                v = value_cls.from_json(v)
            temp[k] = v
        d = temp
    elif isinstance(d, str):
        if DEBUG: print('from_json_dict: d = %s' % d)
        if issubclass(value_cls, enum.Enum):
            if d in (None, 'None'):
                d = None
            else:
                d = value_cls[d]
    elif isinstance(d, collections.abc.Iterable):
        temp = []
        for v in d:
            if not isinstance(v, value_cls) and hasattr(value_cls, 'from_json'):
                v = value_cls.from_json(v)
            temp.append(v)
        d = temp
    return d

def to_json(self):
    d = to_json_dict(self.to_dict())
    return json.dumps(d)

@classmethod
def get_field_from_json_dict(cls, field_name, json_dict, default = None, factory = None):
    if factory is None:
        factory = cls
    
    # un-mangle the naming convention of private fields to match the init parameters if there is a matching parameter
    init_sig = inspect.signature(factory)
    if field_name in init_sig.parameters:
        pass
    elif field_name.startswith('_') and field_name[1:] in init_sig.parameters:
        if DEBUG: print('Removing leading underscore from field name to match the factory parameter: %s' % field_name)
        field_name = field_name[1:]
    else:
        raise ValueError('Unknown field name: %s' % field_name)
        
    if field_name in json_dict:
        return json_dict[field_name]
    
    if ('_%s' % field_name) in json_dict:
        if DEBUG: print('Adding leading underscore from field name to match the json_dict: %s' % field_name)
        return json_dict['_%s' % field_name]
    
    # mangle the naming convention of private fields to match the key name in json
    mangled_field_name = '_%s__%s' % (cls.__name__, field_name)
    if mangled_field_name in json_dict:
        return json_dict[mangled_field_name]
    else:
        if DEBUG: print('Field name not found in json_dict: %s' % field_name)
        return default

@classmethod
def from_json_cls(cls, json_str, factory = None):
    if isinstance(json_str, collections.abc.Mapping):
        d = json_str
    else:
        d = json.loads(json_str)
    
    if factory is None:
        factory = cls
    
    # un-mangle the naming convention of private fields to match the init parameters if there is a matching parameter
    init_sig = inspect.signature(factory)
    for name in list(d.keys()):
        if name in init_sig.parameters:
            continue
        elif name.startswith('_') and name[1:] in init_sig.parameters:
            d[name[1:]] = d[name]
            del d[name]
        # mangle the naming convention of private fields to match the key name in json
        mangle_prefix = '_%s__' % (cls.__name__)
        if name.startswith(mangle_prefix) and name[len(mangle_prefix):] in init_sig.parameters:
            d[name[len(mangle_prefix):]] = d[name]
            del d[name]
    
    return factory(**d)

def repr_from_dict(self, field_filter = lambda x: True):
    if not hasattr(self, 'to_dict'):
        raise ValueError('repr_from_json: class %s does not have the method to_dict()' % (self.__class__.__name__))
    return '%s(%s)' % (self.__class__.__name__, self.to_dict(is_recursive = False, field_filter = field_filter))

def eq_from_dict(self, other, field_filter = lambda x: True):
    # return self.__dict__ == other.__dict__
    
    return (
        {k:v for k,v in self.__dict__.items() if field_filter(k)}
        ==
        {k:v for k,v in other.__dict__.items() if field_filter(k)}
        )

def json_serializable(factory = None, field_filter = lambda x: True):
    def class_decorator(cls):
        if hasattr(cls, 'to_dict'):
            to_dict_local = getattr(cls, 'to_dict')
        else:
            to_dict_local = to_dict
        setattr(cls, 'to_dict', functools.partialmethod(to_dict_local, field_filter = field_filter))
        
        setattr(cls, 'from_json', functools.partialmethod(from_json_cls, factory = factory))
        setattr(cls, 'get_field_from_json', functools.partialmethod(get_field_from_json_dict, factory = factory))
        setattr(cls, 'to_json', to_json)
        setattr(cls, '__repr__', functools.partialmethod(repr_from_dict, field_filter = field_filter))
        # setattr(cls, '__str__', repr_from_dict)
        setattr(cls, '__eq__', functools.partialmethod(eq_from_dict, field_filter = field_filter))
        return cls
    return class_decorator
