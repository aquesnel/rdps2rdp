import functools

from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    PolymophicField,
    
    AutoReinterpret,
    ArrayAutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
    PduLayerSummary,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
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
    Utf16leEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    
    ValueTransformSerializer,
    ValueTransformer,
    
    ValueDependency,
    LengthDependency,
)
from data_model_v2_rdp import (
    Rdp,
)

class Rdp_TS_RAIL_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_PDU, self).__init__(fields = [
            DataUnitField('header', Rdp_TS_RAIL_PDU_HEADER()),
            PolymophicField('payload',
                length_dependency = LengthDependency(lambda x: self.header.orderLength - self.as_field_objects().header.get_length()),
                type_getter = ValueDependency(lambda x: self.header.orderType),
                fields_by_type = {
                    Rdp.Rail.TS_RAIL_ORDER_EXEC: DataUnitField('RAIL_ORDER_EXEC', Rdp_TS_RAIL_ORDER_EXEC()),
                    Rdp.Rail.TS_RAIL_ORDER_EXEC_RESULT: DataUnitField('RAIL_ORDER_EXEC_RESULT', Rdp_TS_RAIL_ORDER_EXEC_RESULT()),
                    Rdp.Rail.TS_RAIL_ORDER_HANDSHAKE: DataUnitField('RAIL_ORDER_HANDSHAKE', Rdp_TS_RAIL_ORDER_HANDSHAKE()),
                    Rdp.Rail.TS_RAIL_ORDER_HANDSHAKE_EX: DataUnitField('RAIL_ORDER_HANDSHAKE_EX', Rdp_TS_RAIL_ORDER_HANDSHAKE_EX()),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_REQ: DataUnitField('RAIL_ORDER_GET_APPID_REQ', Rdp_TS_RAIL_ORDER_GET_APPID_REQ()),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_RESP: DataUnitField('RAIL_ORDER_GET_APPID_RESP', Rdp_TS_RAIL_ORDER_GET_APPID_RESP()),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_RESP_EX: DataUnitField('RAIL_ORDER_GET_APPID_RESP_EX', Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX()),
                    Rdp.Rail.TS_RAIL_ORDER_MINMAXINFO: DataUnitField('RAIL_ORDER_MINMAXINFO', Rdp_TS_RAIL_ORDER_MINMAXINFO()),
                    Rdp.Rail.TS_RAIL_ORDER_CLOAK: DataUnitField('RAIL_ORDER_CLOAK', Rdp_TS_RAIL_ORDER_CLOAK()),
                    Rdp.Rail.TS_RAIL_ORDER_ACTIVATE: DataUnitField('RAIL_ORDER_ACTIVATE', Rdp_TS_RAIL_ORDER_ACTIVATE()),
                    Rdp.Rail.TS_RAIL_ORDER_SYSMENU: DataUnitField('RAIL_ORDER_SYSMENU', Rdp_TS_RAIL_ORDER_SYSMENU()),
                    Rdp.Rail.TS_RAIL_ORDER_SYSCOMMAND: DataUnitField('RAIL_ORDER_SYSCOMMAND', Rdp_TS_RAIL_ORDER_SYSCOMMAND()),
                    Rdp.Rail.TS_RAIL_ORDER_SYSPARAM: DataUnitField('RAIL_ORDER_SYSPARAM', Rdp_TS_RAIL_ORDER_SYSPARAM()),
                }),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self.header._fields_by_name['orderType'].get_human_readable_value())
        retval.extend(super(Rdp_TS_RAIL_PDU, self).get_pdu_types(rdp_context))
        return retval
        
    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RAIL', str(self.header._fields_by_name['orderType'].get_human_readable_value()))]

class Rdp_TS_RAIL_PDU_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_PDU_HEADER, self).__init__(fields = [
            PrimitiveField('orderType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_ORDER_NAMES)),
            PrimitiveField('orderLength', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_RAIL_ORDER_HANDSHAKE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_HANDSHAKE, self).__init__(fields = [
            PrimitiveField('buildNumber', StructEncodedSerializer(UINT_32_LE)),
        ])
    
class Rdp_TS_RAIL_ORDER_HANDSHAKE_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_HANDSHAKE_EX, self).__init__(fields = [
            PrimitiveField('buildNumber', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('railHandshakeFlags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_NAMES)),
        ])

class Rdp_TS_RAIL_ORDER_CLIENTSTATUS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_CLIENTSTATUS, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.TS_RAIL_CLIENTSTATUS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLIENTSTATUS_NAMES)),
        ])


class Rdp_TS_RAIL_ORDER_EXEC(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_EXEC, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES)),
            PrimitiveField('ExeOrFileLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('WorkingDirLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ArgumentsLen', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ExeOrFile', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ExeOrFileLength), delimiter = None)),
            PrimitiveField('WorkingDir', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.WorkingDirLength), delimiter = None)),
            PrimitiveField('Arguments', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ArgumentsLen), delimiter = None)),
        ])
        
class Rdp_TS_RAIL_ORDER_EXEC_RESULT(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_EXEC_RESULT, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES)),
            PrimitiveField('ExecResult', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('RawResult', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Padding1', StructEncodedSerializer(PAD)),
            PrimitiveField('Padding2', StructEncodedSerializer(PAD)),
            PrimitiveField('ExeOrFileLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ExeOrFile', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ExeOrFileLength), delimiter = None)),
        ])
        
class Rdp_TS_RAIL_ORDER_GET_APPID_REQ(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_REQ, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
        ])

class Rdp_TS_RAIL_ORDER_GET_APPID_RESP(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_RESP, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ApplicationId', FixedLengthUtf16leEncodedStringSerializer(520)),
        ])
        
class Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ApplicationId', FixedLengthUtf16leEncodedStringSerializer(520)),
            PrimitiveField('ProcessId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ProcessImageName', FixedLengthUtf16leEncodedStringSerializer(520)),
        ])

class Rdp_TS_RAIL_ORDER_MINMAXINFO(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_MINMAXINFO, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('MaxWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxPosX', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxPosY', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MinTrackWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MinTrackHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxTrackWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxTrackHeight', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_RAIL_ORDER_CLOAK(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_CLOAK, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Cloaked', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOAKED_NAMES)),
        ])

class Rdp_TS_RAIL_ORDER_ACTIVATE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_ACTIVATE, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Enabled', StructEncodedSerializer(UINT_8), to_human_readable = bool),
        ])

class Rdp_TS_RAIL_ORDER_SYSMENU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_SYSMENU, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Left', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('Top', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_RAIL_ORDER_SYSCOMMAND(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_SYSCOMMAND, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Command', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_SYSCOMMAND_NAMES)),
        ])

class Rdp_TS_RAIL_ORDER_SYSPARAM(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_SYSPARAM, self).__init__(fields = [
            PrimitiveField('SystemParam', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_SYSPARAM_NAMES)),
            PolymophicField('body',
                type_getter = ValueDependency(lambda x: self.SystemParam),
                fields_by_type = {
                    # Client allowed fields:
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETDRAGFULLWINDOWS: PrimitiveField('SET_DRAG_FULL_WINDOWS', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETKEYBOARDCUES: PrimitiveField('SET_KEYBOARD_CUES', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETKEYBOARDPREF: PrimitiveField('SET_KEYBOARD_PREF', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETMOUSEBUTTONSWAP: PrimitiveField('SET_MOUSE_BUTTON_SWAP', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETWORKAREA: DataUnitField('SET_WORKAREA', Rdp_TS_RECTANGLE_16()),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAYCHANGE: DataUnitField('DISPLAY_CHANGE', Rdp_TS_RECTANGLE_16()),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_TASKBARPOS: DataUnitField('TASKBAR_POS', Rdp_TS_RECTANGLE_16()),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETHIGHCONTRAST: DataUnitField('SET_HIGH_CONTRAST', Rdp_TS_HIGHCONTRAST()),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETCARETWIDTH: PrimitiveField('SET_CARET_WIDTH', StructEncodedSerializer(UINT_32_LE)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETSTICKYKEYS: DataUnitField('SET_STICKY_KEYS', Rdp_TS_STICKYKEYS()),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETTOGGLEKEYS: DataUnitField('SET_TOGGLE_KEYS', Rdp_TS_TOGGLEKEYS()),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETFILTERKEYS: DataUnitField('SET_FILTER_KEYS', Rdp_TS_FILTERKEYS()),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAY_ANIMATIONS_ENABLED: PrimitiveField('DISPLAY_ANIMATIONS_ENABLED', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAY_ADVANCED_EFFECTS_ENABLED: PrimitiveField('DISPLAY_ADVANCED_EFFECTS_ENABLED', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAY_AUTO_HIDE_SCROLLBARS: PrimitiveField('DISPLAY_AUTO_HIDE_SCROLLBARS', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAY_MESSAGE_DURATION: PrimitiveField('DISPLAY_MESSAGE_DURATION', StructEncodedSerializer(UINT_32_LE)),
                    Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_DISPLAY_MESSAGE_DURATION: PrimitiveField('DISPLAY_AUTO_HIDE_SCROLLBARS', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_FONT_COLOR: PrimitiveField('CLOSED_CAPTION_FONT_COLOR', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_FONT_COLOR_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_FONT_OPACITY: PrimitiveField('CLOSED_CAPTION_FONT_OPACITY', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_FONT_OPACITY_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_FONT_SIZE: PrimitiveField('CLOSED_CAPTION_FONT_SIZE', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_FONT_SIZE_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_FONT_STYLE: PrimitiveField('CLOSED_CAPTION_FONT_STYLE', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_FONT_STYLE_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_FONT_EDGE_EFFECT: PrimitiveField('CLOSED_CAPTION_FONT_EDGE_EFFECT', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_FONT_EDGE_EFFECT_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_BACKGROUND_COLOR: PrimitiveField('CLOSED_CAPTION_BACKGROUND_COLOR', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_BACKGROUND_COLOR_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_BACKGROUND_OPACITY: PrimitiveField('CLOSED_CAPTION_BACKGROUND_OPACITY', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_BACKGROUND_OPACITY_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_REGION_COLOR: PrimitiveField('CLOSED_CAPTION_REGION_COLOR', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_REGION_COLOR_NAMES)),
                    # Rdp.Rail.TS_RAIL_SYSPARAM_RAIL_SPI_CLOSED_CAPTION_REGION_OPACITY: PrimitiveField('CLOSED_CAPTION_REGION_OPACITY', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOSED_CAPTION_REGION_OPACITY_NAMES)),

                    # Server allowed fields:
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETSCREENSAVEACTIVE: PrimitiveField('SET_SCREENSAVE_ACTIVE', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                    Rdp.Rail.TS_RAIL_SYSPARAM_SPI_SETSCREENSAVESECURE: PrimitiveField('SET_SCREENSAVE_SECURE', StructEncodedSerializer(UINT_8), to_human_readable = bool),
                }),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self.as_field_objects().SystemParam.get_human_readable_value())
        retval.extend(super(Rdp_TS_RAIL_ORDER_SYSPARAM, self).get_pdu_types(rdp_context))
        return retval
        
    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RAIL_ORDER_SYSPARAM', str(self.as_field_objects().SystemParam.get_human_readable_value()))]



class Rdp_TS_HIGHCONTRAST(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_HIGHCONTRAST, self).__init__(fields = [
            PrimitiveField('Flags', 
                    BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.HighContrast.HCF_NAMES.keys()), 
                    to_human_readable = lookup_name_in(Rdp.Rail.HighContrast.HCF_NAMES)),
            PrimitiveField('ColorSchemeLength', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ColorScheme', Utf16leEncodedStringSerializer(length_dependency = LengthDependency(lambda x: self.ColorSchemeLength), delimiter = None)),
        ])

class Rdp_TS_RECTANGLE_16(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RECTANGLE_16, self).__init__(fields = [
            PrimitiveField('Left', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('Top', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('Right', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('Bottom', StructEncodedSerializer(UINT_16_LE)),
        ])


class Rdp_ALTSEC_WINDOW_ORDER_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_ALTSEC_WINDOW_ORDER_HEADER, self).__init__(fields = [
            PrimitiveField('OrderSize', StructEncodedSerializer(UINT_16_LE)),
            UnionField(name = 'FieldsPresentFlags_union', fields = [
                PrimitiveField('FieldsPresentFlags_type',
                    BitMaskSerializer(Rdp.Rail.WINDOW_ORDER_TYPE_MASK, StructEncodedSerializer(UINT_32_LE)),
                    to_human_readable = lookup_name_in(Rdp.Rail.WINDOW_ORDER_TYPE_NAMES)),
                PrimitiveField('FieldsPresentFlags_flags', 
                    BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.WINDOW_ORDER_FLAG_NAMES.keys()), 
                    to_human_readable = lookup_name_in(Rdp.Rail.WINDOW_ORDER_FLAG_NAMES)),
                PolymophicField('FieldsPresentFlags_fields',
                    type_getter = ValueDependency(lambda x: self.FieldsPresentFlags_type), 
                    fields_by_type = {
                        Rdp.Rail.WINDOW_ORDER_TYPE_WINDOW: PrimitiveField('FieldsPresentFlags_flags', 
                            BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.Window.FIELD_NAMES.keys()), 
                            to_human_readable = lookup_name_in(Rdp.Rail.Window.FIELD_NAMES)),
                        Rdp.Rail.WINDOW_ORDER_TYPE_NOTIFY: PrimitiveField('FieldsPresentFlags_flags', 
                            BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.Notification.FIELD_NAMES.keys()), 
                            to_human_readable = lookup_name_in(Rdp.Rail.Notification.FIELD_NAMES)),
                        Rdp.Rail.WINDOW_ORDER_TYPE_DESKTOP: PrimitiveField('FieldsPresentFlags_flags', 
                            BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.Desktop.FIELD_NAMES.keys()), 
                            to_human_readable = lookup_name_in(Rdp.Rail.Desktop.FIELD_NAMES)),
                }),
            ]),
            PrimitiveField('payload', RawLengthSerializer(LengthDependency(lambda x: (self.OrderSize - 1 # for the Alternate Secondary Order Header
                                                                                                    - self._fields_by_name['OrderSize'].get_length()
                                                                                                    - self._fields_by_name['FieldsPresentFlags_union'].get_length())))),
        ])

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('ALTERNATE_SECONDARY_DRAWING_ORDER', 'ALTSEC_WINDOW', command_extra = str(self._fields_by_name['FieldsPresentFlags_type'].get_human_readable_value()))]
