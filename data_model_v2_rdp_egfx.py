
from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    
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
from serializers import (
    BaseSerializer,
    RawLengthSerializer,
    DependentValueSerializer,
    ValueTransformSerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    
    StructEncodedSerializer,
    SINT_8,
    UINT_8, 
    SINT_16_LE,
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


class Rdp_RDPGFX_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_PDU, self).__init__(fields = [
            DataUnitField('type_header', Rdp_RDPGFX_PDU_header()),
            ConditionallyPresentField(
                lambda: self.type_header.pdu_type == Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_COMMANDS,
                DataUnitField('commands', Rdp_RDPGFX_commands_PDU())),
            ConditionallyPresentField(
                lambda: self.type_header.pdu_type == Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_SEGMENTS,
                DataUnitField('segments', Rdp_RDP_SEGMENTED_DATA(ValueDependency(lambda x: self.type_header.RDP_SEGMENTED_DATA_descriptor)))),
        ])
        
class Rdp_RDPGFX_PDU_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_PDU_header, self).__init__(fields = [
            UnionField([
                # Note: since the RDP_SEGMENTED_DATA.descriptor and the 
                # first byte of RDPGFX_HEADER.cmdId do not overlap, we can use 
                # this first byte to determine which type of PDU this is.
                # Also, since the RDPGFX_HEADER.cmdId values are all less 
                # than 255, the high byte of the RDPGFX_HEADER.cmdId can be 
                # ignored
                PrimitiveField('pdu_type', 
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.GraphicsPipelineExtention.PduType.MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x if x else 0,
                            from_serialized = lambda x: x if x == Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_SEGMENTS else Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_COMMANDS)),
                    to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_NAMES)),
                ConditionallyPresentField(
                    lambda: self.pdu_type == Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_SEGMENTS,
                    PrimitiveField('RDP_SEGMENTED_DATA_descriptor', 
                        StructEncodedSerializer(UINT_8),
                        to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_NAMES))),
                ConditionallyPresentField(
                    lambda: self.pdu_type == Rdp.GraphicsPipelineExtention.PduType.PDU_TYPE_COMMANDS,
                    PrimitiveField('header_cmdId_low', 
                        StructEncodedSerializer(UINT_8),
                        to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.Commands.RDPGFX_CMDID_NAMES))),
            ]),
        ])

class Rdp_RDP_SEGMENTED_DATA(BaseDataUnit):
    # def __init__(self, descriptor): # replace s/self.descriptor/descriptor.get_value(None)/
    def __init__(self):
        super(Rdp_RDP_SEGMENTED_DATA, self).__init__(fields = [
            # the descriptor field has moved to Rdp_RDPGFX_PDU_header.RDP_SEGMENTED_DATA_descriptor
            PrimitiveField('descriptor', StructEncodedSerializer(UINT_8),
                to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_NAMES)),
            ConditionallyPresentField(
                lambda: self.descriptor == Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_MULTIPART,
                PrimitiveField('segmentCount', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: self.descriptor == Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_MULTIPART,
                PrimitiveField('uncompressedSize', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(  
                lambda: self.descriptor == Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_SINGLE,
                DataUnitField('bulkData', Rdp_RDP8_BULK_ENCODED_DATA(LengthDependency()))),
            ConditionallyPresentField(  
                lambda: self.descriptor == Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_MULTIPART,
                DataUnitField('segmentArray', 
                    ArrayDataUnit(Rdp_RDP_DATA_SEGMENT,
                        item_count_dependency = ValueDependency(lambda x: self.segmentCount)))),
        ])

class Rdp_RDP_DATA_SEGMENT(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_DATA_SEGMENT, self).__init__(fields = [
            PrimitiveField('size', StructEncodedSerializer(UINT_32_LE)), # compressed size
            DataUnitField('bulkData', 
                Rdp_RDP8_BULK_ENCODED_DATA(LengthDependency(lambda x: self.size))),
        ])
        
class Rdp_RDP8_BULK_ENCODED_DATA(BaseDataUnit):
    def __init__(self, data_length_dependency):
        super(Rdp_RDP8_BULK_ENCODED_DATA, self).__init__(fields = [
            UnionField([
                PrimitiveField('header_CompressionType', 
                    BitMaskSerializer(Rdp.GraphicsPipelineExtention.Compression.COMPRESSION_TYPE_MASK, StructEncodedSerializer(UINT_8)),
                    to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.Compression.TYPE_NAMES)),
                PrimitiveField('header_CompressionFlags', 
                    BitFieldEncodedSerializer(UINT_8, Rdp.GraphicsPipelineExtention.Compression.FLAG_NAMES.keys()),
                    to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.Compression.FLAG_NAMES)),
            ]),
            CompressedField(
                decompression_type = ValueDependency(lambda x: Rdp.GraphicsPipelineExtention.Compression.to_compression_type(self.header_CompressionType)),
                decompression_flags = ValueDependency(lambda x: Rdp.GraphicsPipelineExtention.Compression.to_compression_flags(self.header_CompressionFlags)),
                decompression_length = data_length_dependency,
                field = DataUnitField('data', Rdp_RDPGFX_commands_PDU())),
        ])


class Rdp_RDPGFX_commands_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_commands_PDU, self).__init__(fields = [
            DataUnitField('header', 
                Rdp_RDPGFX_HEADER(
                    ValueDependency(lambda x: self.as_field_objects().payload.get_length()))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.header.pduLength - self.as_field_objects().header.get_length()))),
        ])

class Rdp_RDPGFX_HEADER(BaseDataUnit):
    def __init__(self, pdu_length_dependency):
        super(Rdp_RDPGFX_HEADER, self).__init__(fields = [
            PrimitiveField('cmdId', 
                # StructEncodedSerializer(UINT_8),
                StructEncodedSerializer(UINT_16_LE),
                to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.Commands.RDPGFX_CMDID_NAMES)),
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_16_LE, set())),
            PrimitiveField('pduLength', 
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_32_LE),
                    pdu_length_dependency)),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self.as_field_objects().cmdId.get_human_readable_value())
        retval.extend(super(Rdp_RDPGFX_HEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        
        return [PduLayerSummary('RDP-GFX', self.as_field_objects().cmdId.get_human_readable_value())]

class Rdp_RDPGFX_POINT16(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_POINT16, self).__init__(fields = [
            PrimitiveField('x', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('y', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_RDPGFX_RECT16(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_RECT16, self).__init__(fields = [
            PrimitiveField('left', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('top', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('right', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('bottom', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_RDPGFX_COLOR32(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_COLOR32, self).__init__(fields = [
            PrimitiveField('B', StructEncodedSerializer(UINT_8)),
            PrimitiveField('G', StructEncodedSerializer(UINT_8)),
            PrimitiveField('R', StructEncodedSerializer(UINT_8)),
            PrimitiveField('XA', StructEncodedSerializer(UINT_8)),
        ])

class Rdp_RDPGFX_PIXELFORMAT(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_PIXELFORMAT, self).__init__(fields = [
            PrimitiveField('format', 
                StructEncodedSerializer(UINT_8),
                to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.PixelFormat.PIXEL_FORMAT_NAMES)),
        ])

class Rdp_RDPGFX_CAPSET(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDPGFX_CAPSET, self).__init__(fields = [
            PrimitiveField('version', 
                StructEncodedSerializer(UINT_16_LE),
                to_human_readable = lookup_name_in(Rdp.GraphicsPipelineExtention.Versions.RDPGFX_CAPVERSION_NAMES)),
            PrimitiveField('capsDataLength', 
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_32_LE),
                    ValueDependency(lambda x: self.as_field_objects().capsData.get_length()))),
            PrimitiveField('capsData', 
                RawLengthSerializer(LengthDependency(lambda x: self.capsDataLength))),
        ])

