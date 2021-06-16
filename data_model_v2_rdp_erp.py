import functools

from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
    ArrayAutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    ArraySerializer,
    DataUnitSerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    
    StructEncodedSerializer,
    VariableLengthIntSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    EncodedStringSerializer,
    DelimitedEncodedStringSerializer,
    
    ValueTransformSerializer,
    ValueTransformer,
    
    ValueDependency,
    LengthDependency,
)
from data_model_v2_rdp import (
    Rdp,
)

class Rdp_TS_RAIL_PDU_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_PDU_HEADER, self).__init__(fields = [
            PrimitiveField('orderType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_ORDER_NAMES)),
            PrimitiveField('orderLength', StructEncodedSerializer(UINT_16_LE)),
        ])
        
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self._fields_by_name['orderType'].get_human_readable_value())
        retval.extend(super(Rdp_TS_RAIL_PDU_HEADER, self).get_pdu_types(rdp_context))
        return retval

class Rdp_TS_RAIL_ORDER_EXEC(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_EXEC, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES)),
            PrimitiveField('ExeOrFileLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('WorkingDirLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ArgumentsLen', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ExeOrFile', EncodedStringSerializer(EncodedStringSerializer.UTF_16_LE, length_dependency = LengthDependency(lambda x: self.ExeOrFileLength))),
            PrimitiveField('WorkingDir', EncodedStringSerializer(EncodedStringSerializer.UTF_16_LE, length_dependency = LengthDependency(lambda x: self.WorkingDirLength))),
            PrimitiveField('Arguments', EncodedStringSerializer(EncodedStringSerializer.UTF_16_LE, length_dependency = LengthDependency(lambda x: self.ArgumentsLen))),
        ])