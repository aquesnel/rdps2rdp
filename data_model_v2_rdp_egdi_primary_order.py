from typing import Tuple, Set
import functools
import struct

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    DefaultValueField,
    PolymophicField,
    
    AutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
    PduLayerSummary,
    SerializationContext,
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

import math
def field_count_to_flags_length(numberOfOrderFields):
    return math.ceil((numberOfOrderFields + 1) / 8)

class PRIMARY_DRAWING_ORDER_fieldFlagsSerializer(BaseSerializer[Set[int]]):
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272
    
    FIELD_COUNT_BY_ORDER = {
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DSTBLT_ORDER: 5,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER: 12,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SCRBLT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DRAWNINEGRID_ORDER: 5,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTI_DRAWNINEGRID_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_LINETO_ORDER: 10,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_OPAQUERECT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SAVEBITMAP_ORDER: 6,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEMBLT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEM3BLT_ORDER: 16,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIDSTBLT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIPATBLT_ORDER: 14,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTISCRBLT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIOPAQUERECT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_INDEX_ORDER: 15,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_SC_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_CB_ORDER: 13,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYLINE_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_GLYPH_ORDER: 15,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_SC_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_CB_ORDER: 13,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_INDEX_ORDER: 22,
    }
    FIELD_FLAG_LENGTH_BY_ORDER = {k: field_count_to_flags_length(v) for k,v in FIELD_COUNT_BY_ORDER.items()}
    STRUCT_1BYTE = struct.Struct(UINT_8)

    def __init__(self, zero_field_byte_dependency, orderType_dependency):
        self._zero_field_byte = zero_field_byte_dependency
        self._orderType = orderType_dependency
    
    def get_serialized_length(self, value: Set[int]) -> int:
        return self.FIELD_FLAG_LENGTH_BY_ORDER[self._orderType.get_value(None)] - self._zero_field_byte.get_value(None)
        
    def unpack_from(self, raw_data: bytes, offset: int) -> Tuple[Set[int], int]:
        length = self.get_serialized_length(None)
        value = set()
        max_field_count = self.FIELD_COUNT_BY_ORDER[self._orderType.get_value(None)]
        field_count = 1
        for i in range(length):
            b = self.STRUCT_1BYTE.unpack_from(raw_data, offset+i)[0]
            for _ in range(8):
                if b & 0x01 == 1:
                    value.add(field_count)
                field_count += 1
                b >>= 1
                if field_count > max_field_count:
                    return value, length
        return value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: Set[int]) -> None:
        raise NotImplementedError('TODO')
   
class Rdp_PRIMARY_DRAWING_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_PRIMARY_DRAWING_ORDER, self).__init__(fields = [
            DefaultValueField(
                ValueDependency(lambda x: rdp_context.previous_primary_drawing_orders['order_type']),
                ConditionallyPresentField( # Note: when the orderType is not present then the orderType value is equal to the previous order type sent
                    lambda: Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_TYPE_CHANGE in drawing_order.header.controlFlags,
                    PrimitiveField('orderType', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.PrimaryOrderTypes.PRIMARY_ORDER_NAMES)))),
            PrimitiveField('fieldFlags', 
                PRIMARY_DRAWING_ORDER_fieldFlagsSerializer(
                    zero_field_byte_dependency = ValueDependency(lambda x: self.get_zero_field_bytes(drawing_order)),
                    orderType_dependency = ValueDependency(lambda x: self.orderType))),
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_BOUNDS in drawing_order.header.controlFlags 
                        and not Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_ZERO_BOUNDS_DELTAS in drawing_order.header.controlFlags),
                DataUnitField('bounds', Rdp_TS_BOUNDS())),
            PolymophicField('primaryOrderData',
                    type_getter = ValueDependency(lambda x: self.orderType), 
                    fields_by_type = {
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DSTBLT_ORDER: 
                            DataUnitField('primaryOrderData_DSTBLT_ORDER', Rdp_DSTBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER: 
                            DataUnitField('primaryOrderData_PATBLT_ORDER', Rdp_PATBLT_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SCRBLT_ORDER: 
                            DataUnitField('primaryOrderData_SCRBLT_ORDER', Rdp_SCRBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DRAWNINEGRID_ORDER: 
                            DataUnitField('primaryOrderData_DRAWNINEGRID_ORDER', Rdp_DRAWNINEGRID_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTI_DRAWNINEGRID_ORDER: 
                            DataUnitField('primaryOrderData_MULTI_DRAWNINEGRID_ORDER', Rdp_MULTI_DRAWNINEGRID_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_LINETO_ORDER: 
                            DataUnitField('primaryOrderData_LINETO_ORDER', Rdp_LINETO_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_OPAQUERECT_ORDER: 
                            DataUnitField('primaryOrderData_OPAQUERECT_ORDER', Rdp_OPAQUERECT_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SAVEBITMAP_ORDER: 
                            DataUnitField('primaryOrderData_SAVEBITMAP_ORDER', Rdp_SAVEBITMAP_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEMBLT_ORDER: 
                            DataUnitField('primaryOrderData_MEMBLT_ORDER', Rdp_MEMBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEM3BLT_ORDER: 
                            DataUnitField('primaryOrderData_MEM3BLT_ORDER', Rdp_MEM3BLT_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIDSTBLT_ORDER: 
                            DataUnitField('primaryOrderData_MULTIDSTBLT_ORDER', Rdp_MULTI_DSTBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIPATBLT_ORDER: 
                            DataUnitField('primaryOrderData_MULTIPATBLT_ORDER', Rdp_MULTI_PATBLT_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTISCRBLT_ORDER: 
                            DataUnitField('primaryOrderData_MULTISCRBLT_ORDER', Rdp_MULTI_SCRBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIOPAQUERECT_ORDER: 
                            DataUnitField('primaryOrderData_MULTIOPAQUERECT_ORDER', Rdp_MULTI_OPAQUERECT_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_INDEX_ORDER: 
                            DataUnitField('primaryOrderData_FAST_INDEX_ORDER', Rdp_FAST_INDEX_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_SC_ORDER: 
                            DataUnitField('primaryOrderData_POLYGON_SC_ORDER', Rdp_POLYGON_SC_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_CB_ORDER: 
                            DataUnitField('primaryOrderData_POLYGON_CB_ORDER', Rdp_POLYGON_CB_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYLINE_ORDER: 
                            DataUnitField('primaryOrderData_POLYLINE_ORDER', Rdp_POLYLINE_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_GLYPH_ORDER: 
                            DataUnitField('primaryOrderData_FAST_GLYPH_ORDER', Rdp_FAST_GLYPH_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_SC_ORDER: 
                            DataUnitField('primaryOrderData_ELLIPSE_SC_ORDER', Rdp_ELLIPSE_SC_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_CB_ORDER: 
                            DataUnitField('primaryOrderData_ELLIPSE_CB_ORDER', Rdp_ELLIPSE_CB_ORDER(rdp_context, drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_INDEX_ORDER: 
                            DataUnitField('primaryOrderData_GLYPH_INDEX_ORDER', Rdp_GLYPH_INDEX_ORDER(rdp_context, drawing_order)),
                }),
        ])

    def deserialize_apply_context(self, serde_context: SerializationContext) -> None:
        previous_primary_drawing_orders = serde_context.get_rdp_context().previous_primary_drawing_orders
        previous_primary_drawing_orders['order_type'] = self.orderType

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['orderType'].get_human_readable_value()))
        retval.extend(super(Rdp_PRIMARY_DRAWING_ORDER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('PRIMARY_DRAWING_ORDER', str(self._fields_by_name['orderType'].get_human_readable_value()))]

    @staticmethod
    def get_zero_field_bytes(drawing_order):
        retval = 0
        if Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 in drawing_order.header.controlFlags:
            retval |= 0x01
        if Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_ZERO_FIELD_BYTE_BIT1 in drawing_order.header.controlFlags:
            retval |= 0x02
        return retval

class Rdp_TS_BOUNDS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_BOUNDS, self).__init__(fields = [
            PrimitiveField('boundsDescription', BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.Bounds.TS_BOUND_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.DrawingOrders.Bounds.TS_BOUND_NAMES)),
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_LEFT in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription),
                PrimitiveField('left', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription,
                PrimitiveField('left_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_TOP in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_TOP in self.boundsDescription),
                PrimitiveField('top', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_TOP in self.boundsDescription,
                PrimitiveField('top_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_RIGHT in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_RIGHT in self.boundsDescription),
                PrimitiveField('right', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_RIGHT in self.boundsDescription,
                PrimitiveField('right_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_BOTTOM in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription),
                PrimitiveField('bottom', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_BOTTOM in self.boundsDescription,
                PrimitiveField('bottom_delta', StructEncodedSerializer(SINT_8))),
        ])


class Rdp_COORD_FIELD(BaseDataUnit):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74
    def __init__(self, drawing_order):
        super(Rdp_COORD_FIELD, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_DELTA_COORDINATES in drawing_order.header.controlFlags,
                PrimitiveField('signedValue_delta', StructEncodedSerializer(SINT_8))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_DELTA_COORDINATES not in drawing_order.header.controlFlags,
                PrimitiveField('signedValue_absolute', StructEncodedSerializer(SINT_16_LE))),
        ])

class Rdp_DSTBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_DSTBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
        ])

class Rdp_TS_COLOR(BaseDataUnit):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/f99c616b-876d-4371-99fe-cc656d0a610b
    def __init__(self, rdp_context):
        super(Rdp_TS_COLOR, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: rdp_context.caps_preferredBitsPerPixel <= 8,
                PrimitiveField('PaletteIndex', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: rdp_context.caps_preferredBitsPerPixel > 8,
                PrimitiveField('Red', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: rdp_context.caps_preferredBitsPerPixel > 8,
                PrimitiveField('Green', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: rdp_context.caps_preferredBitsPerPixel > 8,
                PrimitiveField('Blue', StructEncodedSerializer(UINT_8))),
        ])

class Rdp_PATBLT_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_PATBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
        ])

class Rdp_SCRBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_SCRBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYSrc', Rdp_COORD_FIELD(drawing_order))),
        ])


class Rdp_DRAWNINEGRID_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_DRAWNINEGRID_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bitmapId', StructEncodedSerializer(UINT_16_LE))),
        ])

class Rdp_MULTI_DRAWNINEGRID_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_MULTI_DRAWNINEGRID_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('srcBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bitmapId', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('nDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE2_FIELD())),
        # ],
        # auto_reinterpret_configs = [
        #     AutoReinterpret('CodedDeltaList.rgbData',
        #         type_getter = ValueDependency(lambda x: 1), # DeltaEncodedRectangles 
        #         config_by_type = {
        #             # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/b89f2058-b180-4da0-9bd1-aa694c87768c
        #             1: AutoReinterpretConfig('', functools.partial(Rdp_DELTA_RECTS_FIELD, ValueDependency(lambda: self.nDeltaEntries))),
        #         }),
        ])


class Rdp_VARIABLE1_FIELD(BaseDataUnit):
    def __init__(self):
        super(Rdp_VARIABLE1_FIELD, self).__init__(fields = [
            PrimitiveField('cbData', StructEncodedSerializer(UINT_8)),
            PrimitiveField('rgbData', RawLengthSerializer(LengthDependency(lambda x: self.cbData))),
        ])

class Rdp_VARIABLE2_FIELD(BaseDataUnit):
    def __init__(self):
        super(Rdp_VARIABLE2_FIELD, self).__init__(fields = [
            PrimitiveField('cbData', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('rgbData', RawLengthSerializer(LengthDependency(lambda x: self.cbData))),
        ])

class Rdp_LINETO_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_LINETO_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BackMode', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXEnd', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYEnd', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('PenStyle', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('PenWidth', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('PenColor', Rdp_TS_COLOR(rdp_context))),
        ])

class Rdp_OPAQUERECT_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_OPAQUERECT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: rdp_context.caps_preferredBitsPerPixel <= 8,
                        PrimitiveField('PaletteIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: rdp_context.caps_preferredBitsPerPixel > 8,
                        PrimitiveField('Red', StructEncodedSerializer(UINT_8))),
                ])),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Green', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Blue', StructEncodedSerializer(UINT_8))),
        ])


class Rdp_SAVEBITMAP_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_SAVEBITMAP_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('SavedBitmapPosition', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nRightRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nBottomRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Operation', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.Operation.OPERATION_NAMES))),
        ])
        
class Rdp_MEMBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_MEMBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheId', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheIndex', StructEncodedSerializer(UINT_16_LE))),
        ])

class Rdp_MEM3BLT_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_MEM3BLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheId', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 14 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 15 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
            ConditionallyPresentField(
                lambda: 16 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheIndex', StructEncodedSerializer(UINT_16_LE))),
        ])


class Rdp_MULTI_DSTBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_MULTI_DSTBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('nDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE2_FIELD())),
        ])

class Rdp_MULTI_PATBLT_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_MULTI_PATBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('nDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 14 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE2_FIELD())),
        ])

class Rdp_MULTI_SCRBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_MULTI_SCRBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nXSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nYSrc', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('nDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE2_FIELD())),
        ])

class Rdp_MULTI_OPAQUERECT_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_MULTI_OPAQUERECT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: rdp_context.caps_preferredBitsPerPixel <= 8,
                        PrimitiveField('PaletteIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: rdp_context.caps_preferredBitsPerPixel > 8,
                        PrimitiveField('Red', StructEncodedSerializer(UINT_8))),
                ])),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Green', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Blue', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('nDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE2_FIELD())),
        ])

class Rdp_FAST_INDEX_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_FAST_INDEX_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheId', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags, # note: the 'fDrawing' field is split into two parts
                PrimitiveField('fDrawing_ulCharInc', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags, # note: the 'fDrawing' field is split into two parts
                PrimitiveField('fDrawing_flAccel', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('X', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Y', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('VariableBytes', Rdp_VARIABLE1_FIELD())),
        ])


class Rdp_POLYGON_SC_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_POLYGON_SC_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('xStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('yStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('FillMode', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BrushColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('NumDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE1_FIELD())),
        ])


class Rdp_POLYGON_CB_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_POLYGON_CB_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('xStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('yStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('FillMode', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('NumDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE1_FIELD())),
        ])
        

class Rdp_POLYLINE_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_POLYLINE_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('xStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('yStart', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushCacheEntry', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('PenColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('NumDeltaEntries', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('CodedDeltaList', Rdp_VARIABLE1_FIELD())),
        ])
        

class Rdp_FAST_GLYPH_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_FAST_GLYPH_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheId', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags, # note: the 'fDrawing' field is split into two parts
                PrimitiveField('fDrawing_ulCharInc', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags, # note: the 'fDrawing' field is split into two parts
                PrimitiveField('fDrawing_flAccel', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('X', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 14 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Y', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 15 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('VariableBytes', Rdp_VARIABLE1_FIELD())),
        ])

class Rdp_ELLIPSE_SC_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_ELLIPSE_SC_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('LeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('TopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('RightRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BottomRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('FillMode', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BrushColor', Rdp_TS_COLOR(rdp_context))),
        ])

class Rdp_ELLIPSE_CB_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_ELLIPSE_CB_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('LeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('TopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('RightRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BottomRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop2', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('FillMode', StructEncodedSerializer(UINT_8))),

            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
        ])


class Rdp_GLYPH_INDEX_ORDER(BaseDataUnit):
    def __init__(self, rdp_context, drawing_order):
        super(Rdp_GLYPH_INDEX_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('cacheId', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('flAccel', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('ulCharInc', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('fOpRedundant', 
                    ValueTransformSerializer(
                        StructEncodedSerializer(UINT_8),
                        ValueTransformer(
                            to_serialized = lambda x: 0x01 if x else 0x00,
                            from_serialized = lambda x: x == 0x01)))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(rdp_context))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BkBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpLeft', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpTop', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 13 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpRight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 14 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('OpBottom', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 15 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 16 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 17 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    PrimitiveField('BrushStyle_cached',
                        ValueTransformSerializer(
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH_MASK, StructEncodedSerializer(UINT_8)),
                            ValueTransformer(
                                to_serialized = lambda x: Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH if x else 0,
                                from_serialized = lambda x: x == Rdp.DrawingOrders.BrushStyle.TS_CACHED_BRUSH))),
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushStyle_colourDepth', 
                            BitMaskSerializer(Rdp.DrawingOrders.BrushStyle.COLOUR_DEPTH_MASK, StructEncodedSerializer(UINT_8)), 
                            to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BMF_NAMES))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.BRUSH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 18 in drawing_order.orderSpecificData.fieldFlags,
                UnionField([
                    ConditionallyPresentField(
                        lambda: self.BrushStyle_cached,
                        PrimitiveField('BrushHatch_cacheIndex', StructEncodedSerializer(UINT_8))),
                    ConditionallyPresentField(
                        lambda: not self.BrushStyle_cached,
                        PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.HATCH_STYLE_NAMES))),
                ])),
            ConditionallyPresentField(
                lambda: 19 in drawing_order.orderSpecificData.fieldFlags and self.BrushStyle == Rdp.DrawingOrders.BrushStyle.BS_PATTERN,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
            ConditionallyPresentField(
                lambda: 20 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('X', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 21 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('Y', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: 22 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('VariableBytes', Rdp_VARIABLE1_FIELD())),
        ])

