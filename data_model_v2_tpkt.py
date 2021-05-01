from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    ValueDependency,
    LengthDependency,
)

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
            # PrimitiveField('version', StructEncodedSerializer(UINT_8)), # moved to Rdp_TS_FP_INPUT_HEADER.action
            PrimitiveField('_', StructEncodedSerializer(PAD)),
            PrimitiveField('length',
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_16_BE),
                    ValueDependency(lambda x: len(self)))),
            PrimitiveField('tpktUserData',
                RawLengthSerializer(LengthDependency(lambda x: self.length - 4))),
        ])
