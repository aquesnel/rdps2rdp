from typing import Tuple

from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
    ArrayAutoReinterpret,
    AutoReinterpretItem,
    
    add_constants_names_mapping,
    lookup_name_in,
)
from serializers import (
    BaseSerializer,
    RawLengthSerializer,
    DependentValueSerializer,
    ValueTransformSerializer,
    ArraySerializer,
    DataUnitSerializer,
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
    LengthDependency,
)

from data_model_v2_rdp import Rdp


class Rdp_TS_FP_INPUT_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_INPUT_HEADER, self).__init__(fields = [
            UnionField([
                PrimitiveField('action', BitMaskSerializer(Rdp.FastPath.FASTPATH_INPUT_ACTIONS_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_INPUT_ACTION_NAMES)),
                PrimitiveField('numEvents', 
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.FastPath.FASTPATH_INPUT_NUM_EVENTS_MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 2,
                            from_serialized = lambda x: x >> 2))),
                PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.FastPath.FASTPATH_INPUT_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_INPUT_FLAG_NAMES)),
            ]),
        ])

class TS_FP_LengthSerializer(BaseSerializer[int]):
    # TS_FP_INPUT_PDU.length1 and TS_FP_INPUT_PDU.length2 fields
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
    def __init__(self):
        pass
    
    def get_serialized_length(self, value: int) -> int:
        if value < 0x80:
            return 1
        else:
            return 2
        
    def unpack_from(self, raw_data: bytes, offset: int) -> Tuple[int, int]:
        length = 1
        value = raw_data[offset]
        # if value > 0x7fff:
        #     raise ValueError('value too large: %d' % value)
        if value & 0x80 == 0x80:
            value &= 0x7f
            value <<= 8
            value += raw_data[offset + 1]
            length += 1
        return value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
        elif value <= 0x7fff:
            struct.pack_into(UINT_16_BE, buffer, offset, value | 0x8000)
        else:
            raise ValueError('value too large: %d' % value)

class Rdp_TS_FP_INPUT_PDU_length_only(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_INPUT_PDU_length_only, self).__init__(fields = [
            PrimitiveField('length', TS_FP_LengthSerializer()),
            ])

            
class Rdp_TS_FP_INPUT_PDU(BaseDataUnit):
    def __init__(self, is_fips_present = False, is_data_signature_present = False, is_num_events_present = False):
        super(Rdp_TS_FP_INPUT_PDU, self).__init__(fields = [
            PrimitiveField('length', TS_FP_LengthSerializer()),
            ConditionallyPresentField(
                lambda:  is_fips_present,
                PrimitiveField('fipsInformation', RawLengthSerializer(LengthDependency(lambda x: 4)))),
            ConditionallyPresentField(
                lambda:  is_data_signature_present,
                PrimitiveField('dataSignature', RawLengthSerializer(LengthDependency(lambda x: 8)))),
            ConditionallyPresentField(
                lambda:  is_num_events_present,
                PrimitiveField('numEvents', StructEncodedSerializer(UINT_8))),
            PrimitiveField('fpInputEvents', 
                RawLengthSerializer(
                    LengthDependency(
                        lambda x: (self.length
                                    - 1 # Rdp_TS_FP_INPUT_HEADER.get_length()
                                    - self._fields_by_name['length'].get_length()
                                    - self._fields_by_name['fipsInformation'].get_length()
                                    - self._fields_by_name['dataSignature'].get_length()
                                    - self._fields_by_name['numEvents'].get_length())))),
        ])
