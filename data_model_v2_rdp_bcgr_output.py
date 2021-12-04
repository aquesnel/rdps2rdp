
from serializers import (
    BaseSerializer,
    RawLengthSerializer,
    DependentValueSerializer,
    ValueTransformSerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    EncodedStringSerializer,
    FixedLengthEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    Utf16leEncodedStringSerializer,
    
    ValueTransformer,
    ValueDependency,
    ValueDependencyWithSideEffect,
    LengthDependency,
    
    SerializationContext,
)

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    RawDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    PolymophicField,
    CompressedField,
    
    AutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
    PduLayerSummary,
)
from data_model_v2_rdp import Rdp


class Rdp_TS_POINTERATTRIBUTE(BaseDataUnit):
    def __init__(self, field_size: LengthDependency):
        super(Rdp_TS_POINTERATTRIBUTE, self).__init__(fields = [
            PrimitiveField('xorBpp', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('colorPtrAttr', 
                Rdp_TS_COLORPOINTERATTRIBUTE(
                    LengthDependency(lambda x: (field_size.get_length(None) 
                            - self.as_field_objects().xorBpp.get_length())))),
        ])
    
class Rdp_TS_COLORPOINTERATTRIBUTE(BaseDataUnit):
    def __init__(self, field_size: LengthDependency):
        super(Rdp_TS_COLORPOINTERATTRIBUTE, self).__init__(fields = [
            PrimitiveField('cacheIndex', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('hotSpot', Rdp_TS_POINT16()),
            PrimitiveField('width', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('height', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthAndMask', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthXorMask', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('xorMaskData', RawLengthSerializer(LengthDependency(lambda x: self.lengthXorMask))),
            PrimitiveField('andMaskData', RawLengthSerializer(LengthDependency(lambda x: self.lengthAndMask))),
            ConditionallyPresentField(
                lambda: 0 < (field_size.get_length(None) 
                        - self.as_field_objects().cacheIndex.get_length()
                        - self.as_field_objects().hotSpot.get_length()
                        - self.as_field_objects().width.get_length()
                        - self.as_field_objects().height.get_length()
                        - self.as_field_objects().lengthAndMask.get_length()
                        - self.as_field_objects().lengthXorMask.get_length()
                        - self.as_field_objects().xorMaskData.get_length()
                        - self.as_field_objects().andMaskData.get_length()
                        ),
                PrimitiveField('pad', StructEncodedSerializer(PAD))),
        ])

class Rdp_TS_POINT16(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_POINT16, self).__init__(fields = [
            PrimitiveField('xPos', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('yPos', StructEncodedSerializer(UINT_16_LE)),
        ])
        
class Rdp_TS_CACHEDPOINTERATTRIBUTE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_CACHEDPOINTERATTRIBUTE, self).__init__(fields = [
            PrimitiveField('cacheIndex', StructEncodedSerializer(UINT_16_LE)),
        ])
