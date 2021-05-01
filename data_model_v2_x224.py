from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
        
    add_constants_names_mapping,
    lookup_name_in,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    StaticSerializer,
    
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    ValueDependency,
    LengthDependency,
)

@add_constants_names_mapping('TPDU_', 'TPDU_NAMES')
class X224(object):
    END_OF_TYPE = b'\x08'
    
    TPDU_DATA = 0xF0
    TPDU_CONNECTION_REQUEST = 0xE0
    TPDU_CONNECTION_CONFIRM = 0xD0
    
class X224HeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(X224HeaderDataUnit, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_8),
                    ValueDependency(lambda x: len(self) - self._fields_by_name['length'].get_length(self.length)))),
            PrimitiveField('type', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(X224.TPDU_NAMES)),
            PrimitiveField('payload',
                RawLengthSerializer(LengthDependency(lambda x: self.length - self._fields_by_name['type'].get_length()))),
        ])

class X224ConnectionDataUnit(BaseDataUnit):
    def __init__(self):
        super(X224ConnectionDataUnit, self).__init__(fields = [
            PrimitiveField('destination', StructEncodedSerializer(UINT_16_BE)),
            PrimitiveField('source', StructEncodedSerializer(UINT_16_BE)),
            PrimitiveField('class', StructEncodedSerializer(UINT_8)),
            PrimitiveField('x224UserData', RawLengthSerializer()),
        ])

class X224DataHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(X224DataHeaderDataUnit, self).__init__(fields = [
            PrimitiveField('x224_EOT', StaticSerializer(X224.END_OF_TYPE)),
        ])
