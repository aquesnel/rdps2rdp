import functools
from enum import Enum, unique

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
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
    ArraySerializer,
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
    
    ValueDependency,
    LengthDependency,
)

class Rdp(object):
    class ConnectionSequence(object):
        SEQUENCE = [
            'connection negotiate',
            'optional - authentication',
            'MCS connect - basic setting exchange',
            'MCS - channel connection',
            'RDP - security comencement',
            'RDP - security settings',
            'RDP - optional - auto detect',
            'RDP - licensing',
            'RDP - optional - multi-transport',
            'RDP - capability exchange',
            'RDP - connection finalization',
            'RDP - remote control',
        ]
    
    @add_constants_names_mapping('FASTPATH_FLAG_', 'FASTPATH_FLAG_NAMES')
    @add_constants_names_mapping('FASTPATH_ACTION_', 'FASTPATH_ACTION_NAMES')
    @add_constants_names_mapping('FASTPATH_UPDATETYPE_', 'FASTPATH_UPDATETYPE_NAMES')
    @add_constants_names_mapping('FASTPATH_FRAGMENT_', 'FASTPATH_FRAGMENT_NAMES')
    @add_constants_names_mapping('FASTPATH_OUTPUT_COMPRESSION_', 'FASTPATH_OUTPUT_COMPRESSION_NAMES')
    class FastPath(object):
        FASTPATH_ACTIONS_MASK = 0x03
        FASTPATH_NUM_EVENTS_MASK = 0x3c
        
        FASTPATH_UPDATE_CODE_MASK = 0x0f
        FASTPATH_FRAGMENTATION_MASK = 0x30
        FASTPATH_COMPRESSION_MASK = 0xc0
        
        FASTPATH_ACTION_FASTPATH = 0x00
        FASTPATH_ACTION_X224 = 0x03
        
        FASTPATH_FLAG_SECURE_CHECKSUM = (0x1 << 6)
        FASTPATH_FLAG_ENCRYPTED = (0x2 << 6)
        
        FASTPATH_UPDATETYPE_ORDERS = 0x0
        FASTPATH_UPDATETYPE_BITMAP = 0x1
        FASTPATH_UPDATETYPE_PALETTE = 0x2
        FASTPATH_UPDATETYPE_SYNCHRONIZE = 0x3
        FASTPATH_UPDATETYPE_SURFCMDS = 0x4
        FASTPATH_UPDATETYPE_PTR_NULL = 0x5
        FASTPATH_UPDATETYPE_PTR_DEFAULT = 0x6
        FASTPATH_UPDATETYPE_PTR_POSITION = 0x8
        FASTPATH_UPDATETYPE_COLOR = 0x9
        FASTPATH_UPDATETYPE_CACHED = 0xA
        FASTPATH_UPDATETYPE_POINTER = 0xB
        FASTPATH_UPDATETYPE_LARGE_POINTER = 0xC
        
        FASTPATH_FRAGMENT_SINGLE = 0x0
        FASTPATH_FRAGMENT_LAST = 0x1
        FASTPATH_FRAGMENT_FIRST = 0x2
        FASTPATH_FRAGMENT_NEXT = 0x3
        
        FASTPATH_OUTPUT_COMPRESSION_USED = 0x2
        
    @add_constants_names_mapping('HRESULT_', 'HRESULT_NAMES')
    class HResult(object):
        # From
        # HRESULT struct: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/0642cb2f-2075-4469-918c-4441e69c548a
        # Win32 error codes: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
        
        HRESULT_ERROR_SUCCESS = 0x00000000
    
    @add_constants_names_mapping('RDP_NEG_', 'RDP_NEG_NAMES')
    class Negotiate(object):
        RDP_NEG_REQ = 0x01
        RDP_NEG_RSP = 0x02
        RDP_NEG_FAILURE = 0x03
        
        RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
        REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
        CORRELATION_INFO_PRESENT = 0x03
        REQUEST_FLAGS = {
            RESTRICTED_ADMIN_MODE_REQUIRED: 'RESTRICTED_ADMIN_MODE_REQUIRED',
            REDIRECTED_AUTHENTICATION_MODE_REQUIRED: 'REDIRECTED_AUTHENTICATION_MODE_REQUIRED',
            CORRELATION_INFO_PRESENT: 'CORRELATION_INFO_PRESENT',
        }
        
        EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
        DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
        NEGRSP_FLAG_RESERVED = 0x04
        RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
        REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10
        RESPONSE_FLAGS = {
            EXTENDED_CLIENT_DATA_SUPPORTED: 'EXTENDED_CLIENT_DATA_SUPPORTED',
            DYNVC_GFX_PROTOCOL_SUPPORTED: 'DYNVC_GFX_PROTOCOL_SUPPORTED',
            NEGRSP_FLAG_RESERVED: 'NEGRSP_FLAG_RESERVED',
            RESTRICTED_ADMIN_MODE_SUPPORTED: 'RESTRICTED_ADMIN_MODE_SUPPORTED',
            REDIRECTED_AUTHENTICATION_MODE_SUPPORTED: 'REDIRECTED_AUTHENTICATION_MODE_SUPPORTED',
        }
    
    class UserData(object):
        CS_CORE = 0xC001
        CS_SECURITY = 0xC002
        CS_NET = 0xC003
        
        SC_CORE = 0x0C01
        SC_SECURITY = 0x0C02
        SC_NET = 0x0C03
        SC_MCS_MSGCHANNEL = 0x0C04
        
        USER_DATA_NAMES = {
            CS_CORE: 'CS_CORE',
            CS_SECURITY: 'CS_SECURITY',
            CS_NET: 'CS_NET',
            
            SC_CORE: 'SC_CORE',
            SC_SECURITY: 'SC_SECURITY',
            SC_NET: 'SC_NET',
            SC_MCS_MSGCHANNEL: 'SC_MCS_MSGCHANNEL'
        }
        
        @add_constants_names_mapping('RNS_UD_CS_', 'RNS_UD_CS_NAMES')
        class Core(object):
            RNS_UD_CS_SUPPORT_ERRINFO_PDU = 0x0001
            RNS_UD_CS_WANT_32BPP_SESSION = 0x0002
            RNS_UD_CS_SUPPORT_STATUSINFO_PDU = 0x0004
            RNS_UD_CS_STRONG_ASYMMETRIC_KEYS = 0x0008
            RNS_UD_CS_UNUSED = 0x0010
            RNS_UD_CS_VALID_CONNECTION_TYPE = 0x0020
            RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU = 0x0040
            RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT = 0x0080
            RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL = 0x0100
            RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE = 0x0200
            RNS_UD_CS_SUPPORT_HEARTBEAT_PDU = 0x0400

    @add_constants_names_mapping('PROTOCOL_', 'PROTOCOL_NAMES')
    class Protocols(object):
        PROTOCOL_RDP = 0x00000000
        PROTOCOL_SSL = 0x00000001
        PROTOCOL_HYBRID = 0x00000002
        PROTOCOL_RDSTLS = 0x00000004
        PROTOCOL_HYBRID_EX = 0x00000008
        
    @add_constants_names_mapping('SEC_', 'SEC_FLAG_NAMES')
    @add_constants_names_mapping('ENCRYPTION_METHOD_', 'ENCRYPTION_METHOD_NAMES')
    @add_constants_names_mapping('ENCRYPTION_LEVEL_', 'ENCRYPTION_LEVEL_NAMES')
    class Security(object):
        # SEC_HDR_BASIC = 'Basic'
        # SEC_HDR_NON_FIPS = 'Non-FIPS'
        # SEC_HEADER_TYPE = {
        #     1: SEC_HDR_BASIC,
        #     2: SEC_HDR_NON_FIPS,
        #     3: 'FIPS',
        # }
        
        SEC_EXCHANGE_PKT = 0x0001
        SEC_TRANSPORT_REQ = 0x0002
        SEC_TRANSPORT_RSP = 0x0004
        SEC_ENCRYPT = 0x0008
        SEC_RESET_SEQNO = 0x0010
        SEC_IGNORE_SEQNO = 0x0020
        SEC_INFO_PKT = 0x0040
        SEC_LICENSE_PKT = 0x0080
        SEC_LICENSE_ENCRYPT = 0x0200
        SEC_LICENSE_ENCRYPT_CS = 0x0200
        SEC_REDIRECTION_PKT = 0x0400
        SEC_SECURE_CHECKSUM = 0x0800
        SEC_AUTODETECT_REQ = 0x1000
        SEC_AUTODETECT_RSP = 0x2000
        SEC_HEARTBEAT = 0x4000
        SEC_FLAGSHI_VALID = 0x8000
        PACKET_MASK = (
            SEC_EXCHANGE_PKT
            | SEC_TRANSPORT_REQ
            | SEC_TRANSPORT_RSP
            | SEC_INFO_PKT
            | SEC_LICENSE_PKT
            | SEC_REDIRECTION_PKT
            | SEC_AUTODETECT_REQ
            | SEC_AUTODETECT_RSP
            | SEC_HEARTBEAT
            )
        
    
        ENCRYPTION_METHOD_NONE = 0x00000000
        ENCRYPTION_METHOD_40BIT = 0x00000001
        ENCRYPTION_METHOD_128BIT = 0x00000002
        ENCRYPTION_METHOD_56BIT = 0x00000008
        ENCRYPTION_METHOD_FIPS = 0x00000010
        
        ENCRYPTION_LEVEL_NONE = 0
        ENCRYPTION_LEVEL_LOW = 1
        ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 2
        ENCRYPTION_LEVEL_HIGH = 3
        ENCRYPTION_LEVEL_FIPS = 4
        
        # @property
        # def sec_header_type(self, rdp_context):
        #     if self.rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_FIPS:
        #         raise ValueError('not yet supported')
        #     elif self.is_SEC_ENCRYPT:
        #         return Rdp.Security.SEC_HDR_NON_FIPS
        #     elif self.rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
        #         return Rdp.Security.SEC_HDR_BASIC
        #     elif (self.rdp_context.encrypted_client_random is None and 
        #             self.rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_LOW):
        #         return Rdp.Security.SEC_HDR_BASIC
        #     else:
        #         return Rdp.Security.SEC_HDR_NON_FIPS
        
    @add_constants_names_mapping('PACKET_COMPR_TYPE_', 'PACKET_COMPR_TYPE_NAMES')
    class Info(object):
        INFO_MOUSE = 0x00000001
        INFO_DISABLECTRLALTDEL = 0x00000002
        INFO_AUTOLOGON = 0x00000008
        INFO_UNICODE = 0x00000010
        INFO_MAXIMIZESHELL = 0x00000020
        INFO_LOGONNOTIFY = 0x00000040
        INFO_COMPRESSION = 0x00000080
        INFO_ENABLEWINDOWSKEY = 0x00000100
        INFO_REMOTECONSOLEAUDIO = 0x00002000
        INFO_FORCE_ENCRYPTED_CS_PDU = 0x00004000
        INFO_RAIL = 0x00008000
        INFO_LOGONERRORS = 0x00010000
        INFO_MOUSE_HAS_WHEEL = 0x00020000
        INFO_PASSWORD_IS_SC_PIN = 0x00040000
        INFO_NOAUDIOPLAYBACK = 0x00080000
        INFO_USING_SAVED_CREDS = 0x00100000
        INFO_AUDIOCAPTURE = 0x00200000
        INFO_VIDEO_DISABLE = 0x00400000
        INFO_RESERVED1 = 0x00800000
        INFO_RESERVED2 = 0x01000000
        INFO_HIDEF_RAIL_SUPPORTED = 0x02000000
        
        INFO_FLAG_NAMES = {
            INFO_MOUSE: 'INFO_MOUSE',
            INFO_DISABLECTRLALTDEL: 'INFO_DISABLECTRLALTDEL',
            INFO_AUTOLOGON: 'INFO_AUTOLOGON',
            INFO_UNICODE: 'INFO_UNICODE',
            INFO_MAXIMIZESHELL: 'INFO_MAXIMIZESHELL',
            INFO_LOGONNOTIFY: 'INFO_LOGONNOTIFY',
            INFO_COMPRESSION: 'INFO_COMPRESSION',
            INFO_ENABLEWINDOWSKEY: 'INFO_ENABLEWINDOWSKEY',
            INFO_REMOTECONSOLEAUDIO: 'INFO_REMOTECONSOLEAUDIO',
            INFO_FORCE_ENCRYPTED_CS_PDU: 'INFO_FORCE_ENCRYPTED_CS_PDU',
            INFO_RAIL: 'INFO_RAIL',
            INFO_LOGONERRORS: 'INFO_LOGONERRORS',
            INFO_MOUSE_HAS_WHEEL: 'INFO_MOUSE_HAS_WHEEL',
            INFO_PASSWORD_IS_SC_PIN: 'INFO_PASSWORD_IS_SC_PIN',
            INFO_NOAUDIOPLAYBACK: 'INFO_NOAUDIOPLAYBACK',
            INFO_USING_SAVED_CREDS: 'INFO_USING_SAVED_CREDS',
            INFO_AUDIOCAPTURE: 'INFO_AUDIOCAPTURE',
            INFO_VIDEO_DISABLE: 'INFO_VIDEO_DISABLE',
            INFO_RESERVED1: 'INFO_RESERVED1',
            INFO_RESERVED2: 'INFO_RESERVED2',
            INFO_HIDEF_RAIL_SUPPORTED: 'INFO_HIDEF_RAIL_SUPPORTED',
            INFO_MOUSE: 'INFO_MOUSE',
            INFO_MOUSE: 'INFO_MOUSE',
        }

        CompressionTypeMask = 0x00001E00
        PACKET_COMPR_TYPE_8K = 0x00000000
        PACKET_COMPR_TYPE_64K = (0x1 << 9)
        PACKET_COMPR_TYPE_RDP6 = (0x2 << 9)
        PACKET_COMPR_TYPE_RDP61 = (0x3 << 9)
    
    @add_constants_names_mapping('CHANNEL_OPTION_', 'CHANNEL_OPTION_NAMES')
    @add_constants_names_mapping('CHANNEL_FLAG_', 'CHANNEL_FLAG_NAMES')
    class Channel(object):
        @unique
        class ChannelType(Enum):
            STATIC = 'static'
            DYNAMIC = 'dynamic'
        
        CHANNEL_OPTION_INITIALIZED = 0x80000000
        CHANNEL_OPTION_ENCRYPT_RDP = 0x40000000
        CHANNEL_OPTION_ENCRYPT_SC = 0x20000000
        CHANNEL_OPTION_ENCRYPT_CS = 0x10000000
        CHANNEL_OPTION_PRI_HIGH = 0x08000000
        CHANNEL_OPTION_PRI_MED = 0x04000000
        CHANNEL_OPTION_PRI_LOW = 0x02000000
        CHANNEL_OPTION_COMPRESS_RDP = 0x00800000
        CHANNEL_OPTION_COMPRESS = 0x00400000
        CHANNEL_OPTION_SHOW_PROTOCOL = 0x00200000
        CHANNEL_OPTION_REMOTE_CONTROL_PERSISTENT = 0x00100000
        
        CHANNEL_FLAG_FIRST = 0x00000001
        CHANNEL_FLAG_LAST = 0x00000002
        CHANNEL_FLAG_SHADOW_PERSISTENT = 0x00000080
        CHANNEL_FLAG_SHOW_PROTOCOL = 0x00000010
        CHANNEL_FLAG_SUSPEND = 0x00000020
        CHANNEL_FLAG_RESUME = 0x00000040
        CHANNEL_FLAG_PACKET_COMPRESSED = 0x00200000
        CHANNEL_FLAG_PACKET_AT_FRONT = 0x00400000
        CHANNEL_FLAG_PACKET_FLUSHED = 0x00800000
        
        CompressionTypeMask = 0x000F0000
        PACKET_COMPR_TYPE_8K = 0x00000000
        PACKET_COMPR_TYPE_64K = (0x1 << 16)
        PACKET_COMPR_TYPE_RDP6 = (0x2 << 16)
        PACKET_COMPR_TYPE_RDP61 = (0x3 << 16)
        
        MCS_GLOBAL_CHANNEL_ID = 1003
        DRDYNVC_CHANNEL_NAME = 'drdynvc'
        RAIL_CHANNEL_NAME = 'rail'
        MESSAGE_CHANNEL_NAME = 'McsMessageChannel'
        IO_CHANNEL_NAME = 'I/O Channel'
        
    class License(object):
        ERROR_ALERT = 0xff

    @add_constants_names_mapping('PDUTYPE_', 'PDUTYPE_NAMES')
    class ShareControlHeader(object):
        PDU_TYPE_MASK = 0x000f
        PDU_VERSION_MASK = 0xfff0
        
        PDUTYPE_DEMANDACTIVEPDU = 0x1
        PDUTYPE_CONFIRMACTIVEPDU = 0x3
        PDUTYPE_DEACTIVATEALLPDU = 0x6
        PDUTYPE_DATAPDU = 0x7
        PDUTYPE_SERVER_REDIR_PKT = 0xA
        # PDUTYPE_NAMES = {
        #     PDUTYPE_DEMANDACTIVEPDU: 'PDUTYPE_DEMANDACTIVEPDU',
        #     PDUTYPE_CONFIRMACTIVEPDU: 'PDUTYPE_CONFIRMACTIVEPDU',
        #     PDUTYPE_DEACTIVATEALLPDU: 'PDUTYPE_DEACTIVATEALLPDU',
        #     PDUTYPE_DATAPDU: 'PDUTYPE_DATAPDU',
        #     PDUTYPE_SERVER_REDIR_PKT: 'PDUTYPE_SERVER_REDIR_PKT',
        # }
    
    @add_constants_names_mapping('PACKET_ARG_', 'PACKET_ARG_NAMES')
    @add_constants_names_mapping('PACKET_COMPR_TYPE_', 'PACKET_COMPR_TYPE_NAMES')
    @add_constants_names_mapping('PDUTYPE2_', 'PDUTYPE2_NAMES')
    class ShareDataHeader(object):
        PACKET_COMPR_TYPE_MASK = 0x0F
        PACKET_ARG_MASK = 0xF0
        
        PACKET_ARG_COMPRESSED = 0x20
        PACKET_ARG_AT_FRONT = 0x40
        PACKET_ARG_FLUSHED = 0x80
        
        PACKET_COMPR_TYPE_8K = 0x00
        PACKET_COMPR_TYPE_64K = 0x01
        PACKET_COMPR_TYPE_RDP6 = 0x02
        PACKET_COMPR_TYPE_RDP61 = 0x03
        
        PDUTYPE2_UPDATE = 0x02
        PDUTYPE2_CONTROL = 0x14
        PDUTYPE2_POINTER = 0x1B
        PDUTYPE2_INPUT = 0x1C
        PDUTYPE2_SYNCHRONIZE = 0x1f
        PDUTYPE2_REFRESH_RECT = 0x21
        PDUTYPE2_PLAY_SOUND = 0x22
        PDUTYPE2_SUPPRESS_OUTPUT = 0x23
        PDUTYPE2_SHUTDOWN_REQUEST = 0x24
        PDUTYPE2_SHUTDOWN_DENIED = 0x25
        PDUTYPE2_SAVE_SESSION_INFO = 0x26
        PDUTYPE2_FONTLIST = 0x27
        PDUTYPE2_FONTMAP = 0x28
        PDUTYPE2_SET_KEYBOARD_INDICATORS = 0x29
        PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST = 0x2B
        PDUTYPE2_BITMAPCACHE_ERROR_PDU = 0x2C
        PDUTYPE2_SET_KEYBOARD_IME_STATUS = 0x2D
        PDUTYPE2_OFFSCRCACHE_ERROR_PDU = 0x2E
        PDUTYPE2_SET_ERROR_INFO_PDU = 0x2F
        PDUTYPE2_DRAWNINEGRID_ERROR_PDU = 0x30
        PDUTYPE2_DRAWGDIPLUS_ERROR_PDU = 0x31
        PDUTYPE2_ARC_STATUS_PDU = 0x32
        PDUTYPE2_STATUS_INFO_PDU = 0x36
        PDUTYPE2_MONITOR_LAYOUT_PDU = 0x37

    @add_constants_names_mapping('CAPSTYPE_', 'CAPSTYPE_NAMES')
    class Capabilities(object):
        CAPSTYPE_GENERAL = 0x0001
        CAPSTYPE_VIRTUALCHANNEL = 0x0014
        CAPSTYPE_RAIL = 0x0017
        CAPSTYPE_WINDOW = 0x0018
        
        @add_constants_names_mapping('VCCAPS_', 'VCCAPS_NAMES')
        class VirtualChannel(object):
            VCCAPS_NO_COMPR = 0x00000000
            VCCAPS_COMPR_SC = 0x00000001
            VCCAPS_COMPR_CS_8K = 0x00000002

    @add_constants_names_mapping('TS_RAIL_ORDER_', 'TS_RAIL_ORDER_NAMES')
    @add_constants_names_mapping('TS_RAIL_EXEC_FLAG_', 'TS_RAIL_EXEC_FLAG_NAMES')
    @add_constants_names_mapping('TS_RAIL_HANDSHAKE_EX_FLAGS_', 'TS_RAIL_HANDSHAKE_EX_FLAGS_NAMES')
    @add_constants_names_mapping('TS_RAIL_CLIENTSTATUS_', 'TS_RAIL_CLIENTSTATUS_NAMES')
    @add_constants_names_mapping('TS_RAIL_CLOAKED_', 'TS_RAIL_CLOAKED_NAMES')
    @add_constants_names_mapping('WINDOW_ORDER_TYPE_', 'WINDOW_ORDER_TYPE_NAMES')
    @add_constants_names_mapping('WINDOW_ORDER_FLAG_', 'WINDOW_ORDER_FLAG_NAMES')
    class Rail(object):
        TS_RAIL_ORDER_EXEC = 0x0001
        TS_RAIL_ORDER_ACTIVATE = 0x0002
        TS_RAIL_ORDER_SYSPARAM = 0x0003
        TS_RAIL_ORDER_SYSCOMMAND = 0x0004
        TS_RAIL_ORDER_HANDSHAKE = 0x0005
        TS_RAIL_ORDER_NOTIFY_EVENT = 0x0006
        TS_RAIL_ORDER_WINDOWMOVE = 0x0008
        TS_RAIL_ORDER_LOCALMOVESIZE = 0x0009
        TS_RAIL_ORDER_MINMAXINFO = 0x000a
        TS_RAIL_ORDER_CLIENTSTATUS = 0x000b
        TS_RAIL_ORDER_SYSMENU = 0x000c
        TS_RAIL_ORDER_LANGBARINFO = 0x000d
        TS_RAIL_ORDER_EXEC_RESULT = 0x0080
        TS_RAIL_ORDER_GET_APPID_REQ = 0x000E
        TS_RAIL_ORDER_GET_APPID_RESP = 0x000F
        TS_RAIL_ORDER_TASKBARINFO = 0x0010
        TS_RAIL_ORDER_LANGUAGEIMEINFO = 0x0011
        TS_RAIL_ORDER_COMPARTMENTINFO = 0x0012
        TS_RAIL_ORDER_HANDSHAKE_EX = 0x0013
        TS_RAIL_ORDER_ZORDER_SYNC = 0x0014
        TS_RAIL_ORDER_CLOAK = 0x0015
        TS_RAIL_ORDER_POWER_DISPLAY_REQUEST = 0x0016
        TS_RAIL_ORDER_SNAP_ARRANGE = 0x0017
        TS_RAIL_ORDER_GET_APPID_RESP_EX = 0x0018
        TS_RAIL_ORDER_TEXTSCALEINFO = 0x0019
        TS_RAIL_ORDER_CARETBLINKINFO = 0x001A
        
        TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY = 0x0001
        TS_RAIL_EXEC_FLAG_TRANSLATE_FILES = 0x0002
        TS_RAIL_EXEC_FLAG_FILE = 0x0004
        TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS = 0x0008
        TS_RAIL_EXEC_FLAG_APP_USER_MODEL_ID = 0x0010
        
        # note the following in the spec are actually TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_...
        TS_RAIL_HANDSHAKE_EX_FLAGS_HIDEF = 0x00000001
        TS_RAIL_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_SUPPORTED = 0x00000002
        TS_RAIL_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED = 0x00000004
        TS_RAIL_HANDSHAKE_EX_FLAGS_TEXT_SCALE_SUPPORTED = 0x00000008
        TS_RAIL_HANDSHAKE_EX_FLAGS_CARET_BLINK_SUPPORTED = 0x00000010
        TS_RAIL_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_2_SUPPORTED = 0x00000020
        
        TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE = 0x00000001
        TS_RAIL_CLIENTSTATUS_AUTORECONNECT = 0x00000002
        TS_RAIL_CLIENTSTATUS_ZORDER_SYNC = 0x00000004
        TS_RAIL_CLIENTSTATUS_WINDOW_RESIZE_MARGIN_SUPPORTED = 0x00000010
        TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED = 0x00000020
        TS_RAIL_CLIENTSTATUS_APPBAR_REMOTING_SUPPORTED = 0x00000040
        TS_RAIL_CLIENTSTATUS_POWER_DISPLAY_REQUEST_SUPPORTED = 0x00000080
        TS_RAIL_CLIENTSTATUS_BIDIRECTIONAL_CLOAK_SUPPORTED = 0x00000200
        TS_RAIL_CLIENTSTATUS_SUPPRESS_ICON_ORDERS = 0x00000400
        
        TS_RAIL_CLOAKED_FALSE = 0x00
        TS_RAIL_CLOAKED_TRUE = 0x01
        
        WINDOW_ORDER_TYPE_WINDOW =  0x01000000
        WINDOW_ORDER_TYPE_NOTIFY =  0x02000000
        WINDOW_ORDER_TYPE_DESKTOP = 0x04000000
        WINDOW_ORDER_TYPE_MASK = (WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_TYPE_NOTIFY | WINDOW_ORDER_TYPE_DESKTOP)
        
        WINDOW_ORDER_FLAG_STATE_NEW =     0x10000000
        WINDOW_ORDER_FLAG_STATE_DELETED = 0x20000000
        WINDOW_ORDER_FLAG_ICON =          0x40000000
        WINDOW_ORDER_FLAG_CACHEDICON =    0x80000000
        
        @add_constants_names_mapping('WINDOW_ORDER_FIELD_', 'FIELD_NAMES')
        class Window(object):
            WINDOW_ORDER_FIELD_APPBAR_EDGE =           0x00000001
            WINDOW_ORDER_FIELD_OWNER =                 0x00000002
            WINDOW_ORDER_FIELD_TITLE =                 0x00000004
            WINDOW_ORDER_FIELD_STYLE =                 0x00000008
            WINDOW_ORDER_FIELD_SHOW =                  0x00000010
            WINDOW_ORDER_FIELD_APPBAR_STATE =          0x00000040
            WINDOW_ORDER_FIELD_RESIZE_MARGIN_X =       0x00000080
            WINDOW_ORDER_FIELD_WNDRECTS =              0x00000100
            WINDOW_ORDER_FIELD_VISIBILITY =            0x00000200
            WINDOW_ORDER_FIELD_WNDSIZE =               0x00000400
            WINDOW_ORDER_FIELD_WNDOFFSET =             0x00000800
            WINDOW_ORDER_FIELD_VISOFFSET =             0x00001000
            WINDOW_ORDER_FIELD_CLIENTAREAOFFSET =      0x00004000
            WINDOW_ORDER_FIELD_CLIENTDELTA =           0x00008000
            WINDOW_ORDER_FIELD_CLIENTAREASIZE =        0x00010000
            WINDOW_ORDER_FIELD_RPCONTENT =             0x00020000
            WINDOW_ORDER_FIELD_ROOTPARENT =            0x00040000
            WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER = 0x00080000
            WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL =     0x00200000
            WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION =   0x00400000
            WINDOW_ORDER_FIELD_TASKBAR_BUTTON =        0x00800000
            WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y =       0x08000000

        @add_constants_names_mapping('WINDOW_ORDER_FIELD_', 'FIELD_NAMES')
        class Icon(object):
            WINDOW_ORDER_FIELD_ICON_BIG =              0x00002000
            WINDOW_ORDER_FIELD_ICON_OVERLAY =          0x00100000
        
        @add_constants_names_mapping('WINDOW_ORDER_FIELD_', 'FIELD_NAMES')
        class Notification(object):
            WINDOW_ORDER_FIELD_NOTIFY_TIP =      0x00000001
            WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP = 0x00000002
            WINDOW_ORDER_FIELD_NOTIFY_STATE =    0x00000004
            WINDOW_ORDER_FIELD_NOTIFY_VERSION =  0x00000008
            
        @add_constants_names_mapping('WINDOW_ORDER_FIELD_', 'FIELD_NAMES')
        class Desktop(object):
            WINDOW_ORDER_FIELD_DESKTOP_NONE =          0x00000001
            WINDOW_ORDER_FIELD_DESKTOP_HOOKED =        0x00000002
            WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED = 0x00000004
            WINDOW_ORDER_FIELD_DESKTOP_ARC_BEGAN =     0x00000008
            WINDOW_ORDER_FIELD_DESKTOP_ZORDER =        0x00000010
            WINDOW_ORDER_FIELD_DESKTOP_ACTIVEWND =     0x00000020
            

    @add_constants_names_mapping('COMMAND_', 'COMMAND_NAMES')
    class DynamicVirtualChannels(object): # from [MS-RDPEDYC]
        HEADER_MASK_CBID = 0x03
        HEADER_MASK_PRI  = 0x0C
        HEADER_MASK_CMD  = 0xF0
        
        DYNAMIC_VIRTUAL_CHANNEL_OPTIONS = 0
        
        COMMAND_CREATE = 0x01
        COMMAND_DATA_FIRST = 0x02
        COMMAND_DATA = 0x03
        COMMAND_CLOSE = 0x04
        COMMAND_CAPABILITIES = 0x05
        COMMAND_COMPRESSED_DATA_FIRST = 0x06 
        COMMAND_COMPRESSED_DATA = 0x07
        COMMAND_SOFT_SYNC_REQUEST = 0x08
        COMMAND_SOFT_SYNC_RESPONSE = 0x09
        
    @add_constants_names_mapping('CMDTYPE_', 'CMDTYPE_NAMES')
    class Surface(object):
        CMDTYPE_SET_SURFACE_BITS = 0x0001
        CMDTYPE_FRAME_MARKER = 0x0004
        CMDTYPE_STREAM_SURFACE_BITS = 0x0006

    @add_constants_names_mapping('EX_', 'BITMAP_FLAG_NAMES')
    class Bitmap(object):
        EX_COMPRESSED_BITMAP_HEADER_PRESENT = 0x01

    @add_constants_names_mapping('SURFACECMD_FRAMEACTION_', 'SURFACECMD_FRAMEACTION_NAMES')
    class Frame(object):
        SURFACECMD_FRAMEACTION_BEGIN = 0x0000
        SURFACECMD_FRAMEACTION_END = 0x0001

    @add_constants_names_mapping('ORDERS_', 'ORDERS_NAMES')
    class DrawingOrders(object):
        @add_constants_names_mapping('TS_S', 'ORDER_FLAG_NAMES')
        @add_constants_names_mapping('TS_', 'PRIMARY_ORDER_FLAG_NAMES')
        class OrderFlags(object):
            TS_STANDARD = 0x01
            TS_SECONDARY = 0x02
            
            PRIMARY_ORDER_FLAG_MASK = 0xfc
            SECONDARY_ORDER_FLAG_MASK = 0x00
            ALT_SECAONDARY_ORDER_TYPE_MASK = 0xfc
            ALT_SECAONDARY_FLAG_MASK_offscreenBitmapId = 0x7fff
            ALT_SECAONDARY_FLAG_MASK_deleteList = 0x8000
            
            # in the spec, these constants are all named without the "PRIMARY_"
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272
            TS_PRIMARY_BOUNDS = 0x04
            TS_PRIMARY_TYPE_CHANGE = 0x08
            TS_PRIMARY_DELTA_COORDINATES = 0x10
            TS_PRIMARY_ZERO_BOUNDS_DELTAS = 0x20
            TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 = 0x40
            TS_PRIMARY_ZERO_FIELD_BYTE_BIT1 = 0x80
            
        ORDER_TYPE_MASK = OrderFlags.TS_STANDARD | OrderFlags.TS_SECONDARY
        ORDERS_PRIMARY = OrderFlags.TS_STANDARD
        ORDERS_SECONDARY = OrderFlags.TS_STANDARD | OrderFlags.TS_SECONDARY
        ORDERS_SECONDARY_ALTERNATE = OrderFlags.TS_SECONDARY
        DRAWING_ORDER_TYPE_NAMES = {
            ORDERS_PRIMARY: 'PRIMARY_DRAWING_ORDER',
            ORDERS_SECONDARY: 'SECONDARY_DRAWING_ORDER',
            ORDERS_SECONDARY_ALTERNATE: 'ALTERNATE_SECONDARY_DRAWING_ORDER',
        }

        @add_constants_names_mapping('TS_ENC_', 'PRIMARY_ORDER_NAMES')
        class PrimaryOrderTypes(object):
            TS_ENC_DSTBLT_ORDER = 0x00
            TS_ENC_PATBLT_ORDER = 0x01
            TS_ENC_SCRBLT_ORDER = 0x02
            TS_ENC_DRAWNINEGRID_ORDER = 0x07
            TS_ENC_MULTI_DRAWNINEGRID_ORDER = 0x08
            TS_ENC_LINETO_ORDER = 0x09
            TS_ENC_OPAQUERECT_ORDER = 0x0A
            TS_ENC_SAVEBITMAP_ORDER = 0x0B
            TS_ENC_MEMBLT_ORDER = 0x0D
            TS_ENC_MEM3BLT_ORDER = 0x0E
            TS_ENC_MULTIDSTBLT_ORDER = 0x0F
            TS_ENC_MULTIPATBLT_ORDER = 0x10
            TS_ENC_MULTISCRBLT_ORDER = 0x11
            TS_ENC_MULTIOPAQUERECT_ORDER = 0x12
            TS_ENC_FAST_INDEX_ORDER = 0x13
            TS_ENC_POLYGON_SC_ORDER = 0x14
            TS_ENC_POLYGON_CB_ORDER = 0x15
            TS_ENC_POLYLINE_ORDER = 0x16
            TS_ENC_FAST_GLYPH_ORDER = 0x18
            TS_ENC_ELLIPSE_SC_ORDER = 0x19
            TS_ENC_ELLIPSE_CB_ORDER = 0x1A
            TS_ENC_INDEX_ORDER = 0x1B

        @add_constants_names_mapping('TS_CACHE_', 'SECONDARY_ORDER_NAMES')
        class SecondaryOrderTypes(object):
            TS_CACHE_BITMAP_UNCOMPRESSED = 0x00
            TS_CACHE_COLOR_TABLE = 0x01
            TS_CACHE_BITMAP_COMPRESSED = 0x02
            TS_CACHE_GLYPH = 0x03
            TS_CACHE_BITMAP_UNCOMPRESSED_REV2 = 0x04
            TS_CACHE_BITMAP_COMPRESSED_REV2 = 0x05
            TS_CACHE_BRUSH = 0x07
            TS_CACHE_BITMAP_COMPRESSED_REV3 = 0x08
            
        @add_constants_names_mapping('TS_ALTSEC_', 'ALT_SECONDARY_ORDER_NAMES')
        class AltSecondaryOrderTypes(object):
            TS_ALTSEC_SWITCH_SURFACE = 0x00
            TS_ALTSEC_CREATE_OFFSCR_BITMAP = 0x01
            TS_ALTSEC_STREAM_BITMAP_FIRST = 0x02
            TS_ALTSEC_STREAM_BITMAP_NEXT = 0x03
            TS_ALTSEC_CREATE_NINEGRID_BITMAP = 0x04
            TS_ALTSEC_GDIP_FIRST = 0x05
            TS_ALTSEC_GDIP_NEXT = 0x06
            TS_ALTSEC_GDIP_END = 0x07
            TS_ALTSEC_GDIP_CACHE_FIRST = 0x08
            TS_ALTSEC_GDIP_CACHE_NEXT = 0x09
            TS_ALTSEC_GDIP_CACHE_END = 0x0A
            TS_ALTSEC_WINDOW = 0x0B
            TS_ALTSEC_COMPDESK_FIRST = 0x0C
            TS_ALTSEC_FRAME_MARKER = 0x0D

        @add_constants_names_mapping('TS_BOUND_', 'TS_BOUND_NAMES')
        class Bounds(object):
            TS_BOUND_LEFT = 0x01
            TS_BOUND_TOP = 0x02
            TS_BOUND_RIGHT = 0x04
            TS_BOUND_BOTTOM = 0x08
            TS_BOUND_DELTA_LEFT = 0x10
            TS_BOUND_DELTA_TOP = 0x20
            TS_BOUND_DELTA_RIGHT = 0x40
            TS_BOUND_DELTA_BOTTOM = 0x80
            
        @add_constants_names_mapping('BMF_', 'BMF_NAMES')
        @add_constants_names_mapping('BS_', 'BRUSH_STYLE_NAMES')
        @add_constants_names_mapping('HS_', 'HATCH_STYLE_NAMES')
        class BrushStyle(object):
            TS_CACHED_BRUSH = 0x80
            TS_CACHED_BRUSH_MASK = 0x80
            COLOUR_DEPTH_MASK = 0x0f

            BMF_1BPP = 0x01
            BMF_8BPP = 0x03
            BMF_16BPP = 0x04
            BMF_24BPP = 0x05
            BMF_32BPP = 0x06
            
            BS_SOLID = 0x00
            BS_NULL = 0x01
            BS_HATCHED = 0x02
            BS_PATTERN = 0x03
            
            HS_HORIZONTAL = 0x00
            HS_VERTICAL = 0x01
            HS_FDIAGONAL = 0x02
            HS_BDIAGONAL = 0x03
            HS_CROSS = 0x04
            HS_DIAGCROSS = 0x05
            
        @add_constants_names_mapping('SV_', 'OPERATION_NAMES')
        class Operation(object):
            SV_SAVEBITS = 0x00
            SV_RESTOREBITS = 0x01
            
        @add_constants_names_mapping('STREAM_BITMAP_', 'BITMAP_FLAG_NAMES')
        class BitmapFlags(object):
            STREAM_BITMAP_END = 0x01
            STREAM_BITMAP_COMPRESSED = 0x02
            STREAM_BITMAP_REV2 = 0x04
            
            
class DataUnitTypes(object):
    X224 = Rdp.FastPath.FASTPATH_ACTION_X224
    FAST_PATH = Rdp.FastPath.FASTPATH_ACTION_FASTPATH
    CREDSSP = 0x30 # 0x30 is the DER identifier for SEQUNCE which is the top level type of the [MS-CSSP] TSRequest struct.

Rdp.DataUnitTypes = DataUnitTypes  
            

class Rdp_RDP_NEG_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_header, self).__init__(fields = [
            PrimitiveField('type', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Negotiate.RDP_NEG_NAMES)),
        ])
        
    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RDP', str(self._fields_by_name['type'].get_human_readable_value()))]

        
class Rdp_RDP_NEG_REQ(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_REQ, self).__init__(
            use_class_as_pdu_name = True,
            fields = [
                PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.Negotiate.REQUEST_FLAGS.keys()), to_human_readable = lookup_name_in(Rdp.Negotiate.REQUEST_FLAGS)),
                PrimitiveField('length', StructEncodedSerializer(UINT_16_LE)),
                PrimitiveField('requestedProtocols', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Protocols.PROTOCOL_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Protocols.PROTOCOL_NAMES)),
            ])

class Rdp_RDP_NEG_RSP(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_RSP, self).__init__(
            use_class_as_pdu_name = True,
            fields = [
                PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.Negotiate.RESPONSE_FLAGS.keys()), to_human_readable = lookup_name_in(Rdp.Negotiate.RESPONSE_FLAGS)),
                PrimitiveField('length', StructEncodedSerializer(UINT_16_LE)),
                PrimitiveField('selectedProtocol', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Protocols.PROTOCOL_NAMES)),
            ])

class Rdp_RDP_NEG_FAILURE(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_FAILURE, self).__init__(
            use_class_as_pdu_name = True,
            fields = [
                PrimitiveField('flags', StructEncodedSerializer(UINT_8)),
                PrimitiveField('length', StructEncodedSerializer(UINT_16_LE)),
                PrimitiveField('failureCode', StructEncodedSerializer(UINT_32_LE)),
            ])
        
class RdpUserDataBlock(BaseDataUnit):
    def __init__(self):
        super(RdpUserDataBlock, self).__init__(fields = [
            DataUnitField('header', 
                Rdp_TS_UD_HEADER(ValueDependency(lambda x: len(self)))),
            PrimitiveField('payload', 
                RawLengthSerializer(LengthDependency(lambda x: self.header.length - self.header.get_length()))),
        ],
        auto_reinterpret_configs = [
            AutoReinterpret('payload',
                type_getter = ValueDependency(lambda x: self.header.type), 
                config_by_type = {
                    Rdp.UserData.CS_CORE: AutoReinterpretConfig('', Rdp_TS_UD_CS_CORE),
                    Rdp.UserData.CS_SECURITY: AutoReinterpretConfig('', Rdp_TS_UD_CS_SEC),
                    Rdp.UserData.CS_NET: AutoReinterpretConfig('', Rdp_TS_UD_CS_NET),
                    
                    Rdp.UserData.SC_CORE: AutoReinterpretConfig('', Rdp_TS_UD_SC_CORE),
                    Rdp.UserData.SC_NET: AutoReinterpretConfig('', Rdp_TS_UD_SC_NET),
                    Rdp.UserData.SC_SECURITY: AutoReinterpretConfig('', Rdp_TS_UD_SC_SEC1),
                    Rdp.UserData.SC_MCS_MSGCHANNEL: AutoReinterpretConfig('', Rdp_TS_UD_SC_MCS_MSGCHANNEL),
                }),
        ])
    
class Rdp_TS_UD_HEADER(BaseDataUnit):
    def __init__(self, length_value_dependency):
        super(Rdp_TS_UD_HEADER, self).__init__(fields = [
            PrimitiveField('type', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.UserData.USER_DATA_NAMES)),
            PrimitiveField('length', 
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_16_LE),
                    length_value_dependency)),
        ])

class Rdp_TS_UD_CS_CORE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_CS_CORE, self).__init__(fields = [
            PrimitiveField('version', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('desktopWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('desktopHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('colorDepth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('SASSequence', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('keyboardLayout', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('clientBuild', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('clientName', FixedLengthUtf16leEncodedStringSerializer(32)),
            PrimitiveField('keyboardType', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('keyboardSubType', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('keyboardFunctionKey', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('imeFileName', FixedLengthUtf16leEncodedStringSerializer(64)),
            OptionalField(
                PrimitiveField('postBeta2ColorDepth', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('clientProductId', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('serialNumber', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('highColorDepth', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('supportedColorDepths', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('earlyCapabilityFlags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.UserData.Core.RNS_UD_CS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.UserData.Core.RNS_UD_CS_NAMES))),
            OptionalField(
                PrimitiveField('clientDigProductId', FixedLengthUtf16leEncodedStringSerializer(64))),
            OptionalField(
                PrimitiveField('connectionType', StructEncodedSerializer(UINT_8))),
            OptionalField(
                PrimitiveField('pad1octet ', StructEncodedSerializer(PAD))),
            OptionalField(
                PrimitiveField('serverSelectedProtocol', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopPhysicalWidth', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopPhysicalHeight', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('desktopOrientation', StructEncodedSerializer(UINT_16_LE))),
            OptionalField(
                PrimitiveField('desktopScaleFactor', StructEncodedSerializer(UINT_32_LE))),
            OptionalField(
                PrimitiveField('deviceScaleFactor', StructEncodedSerializer(UINT_32_LE))),
        ])

class Rdp_TS_UD_CS_SEC(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_CS_SEC, self).__init__(fields = [
            PrimitiveField(
                'encryptionMethods', 
                BitFieldEncodedSerializer(UINT_32_LE, Rdp.Security.ENCRYPTION_METHOD_NAMES.keys()), 
                to_human_readable = lookup_name_in(Rdp.Security.ENCRYPTION_METHOD_NAMES)),
            PrimitiveField('extEncryptionMethods', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Security.ENCRYPTION_METHOD_NAMES)),
        ])

class Rdp_TS_UD_CS_NET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_CS_NET, self).__init__(fields = [
            PrimitiveField('channelCount', StructEncodedSerializer(UINT_32_LE)),
            DataUnitField('channelDefArray',
                ArrayDataUnit(Rdp_CHANNEL_DEF,
                    item_count_dependency = ValueDependency(lambda x: self.channelCount))),
        ])

class Rdp_CHANNEL_DEF(BaseDataUnit):
    def __init__(self):
        super(Rdp_CHANNEL_DEF, self).__init__(fields = [
            PrimitiveField('name', FixedLengthEncodedStringSerializer(EncodedStringSerializer.ASCII, 8)),
            PrimitiveField('options', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Channel.CHANNEL_OPTION_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Channel.CHANNEL_OPTION_NAMES)),
        ])

class Rdp_TS_UD_SC_CORE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_CORE, self).__init__(fields = [
            PrimitiveField('version', StructEncodedSerializer(UINT_32_LE)),
            OptionalField(
                PrimitiveField(
                    'clientRequestedProtocols', 
                    BitFieldEncodedSerializer(UINT_32_LE, Rdp.Protocols.PROTOCOL_NAMES.keys()), 
                    to_human_readable = lookup_name_in(Rdp.Protocols.PROTOCOL_NAMES))),
            OptionalField(
                PrimitiveField('earlyCapabilityFlags', StructEncodedSerializer(UINT_32_LE))),
        ])

class Rdp_TS_UD_SC_NET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_NET, self).__init__(fields = [
            PrimitiveField('MCSChannelId', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('channelCount', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('channelIdArray',
                ArraySerializer(
                        StructEncodedSerializer(UINT_16_LE),
                        item_count_dependency = ValueDependency(lambda x: self.channelCount))),
            OptionalField(
                PrimitiveField('Pad', StructEncodedSerializer(PAD*2))),
        ])

class Rdp_TS_UD_SC_MCS_MSGCHANNEL(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_MCS_MSGCHANNEL, self).__init__(fields = [
            PrimitiveField('MCSChannelId', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_UD_SC_SEC1(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_UD_SC_SEC1, self).__init__(fields = [
            PrimitiveField('encryptionMethod', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Security.ENCRYPTION_METHOD_NAMES)),
            PrimitiveField('encryptionLevel', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Security.ENCRYPTION_LEVEL_NAMES)),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverRandomLen', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverCertLen', StructEncodedSerializer(UINT_32_LE))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverRandom', 
                    RawLengthSerializer(LengthDependency(lambda x: self.serverRandomLen)))),
            ConditionallyPresentField(
                lambda: self.encryptionMethod != 0 or self.encryptionLevel != 0,
                PrimitiveField('serverCertificate', 
                    RawLengthSerializer(LengthDependency(lambda x: self.serverCertLen)))),
        ])


class Rdp_TS_SECURITY_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SECURITY_HEADER, self).__init__(fields = [
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Security.SEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Security.SEC_FLAG_NAMES)),
            PrimitiveField('flagsHi', StructEncodedSerializer(UINT_16_LE)),
        ])

    def _get_packet_name(self):
        packet_name = 'unknown'
        for f in self.flags:
            if f & Rdp.Security.PACKET_MASK:
                packet_name = Rdp.Security.SEC_FLAG_NAMES[f]
                break
        return packet_name

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self._get_packet_name())
        retval.extend(super(Rdp_TS_SECURITY_HEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RDP', self._get_packet_name())]


class Rdp_TS_SECURITY_HEADER1(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SECURITY_HEADER1, self).__init__(fields = [
            PrimitiveField('dataSignature', RawLengthSerializer(LengthDependency(lambda x: 8))),
        ])
        
class Rdp_TS_SECURITY_PACKET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SECURITY_PACKET, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_32_LE),
                    ValueDependency(lambda x: len(self.encryptedClientRandom)))),
            PrimitiveField('encryptedClientRandom',
                RawLengthSerializer(LengthDependency(lambda x: self.length))),
        ])

class Rdp_TS_INFO_PACKET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_INFO_PACKET, self).__init__(fields = [
            PrimitiveField('CodePage', StructEncodedSerializer(UINT_32_LE)),
            UnionField([
                PrimitiveField('flags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Info.INFO_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Info.INFO_FLAG_NAMES)),
                PrimitiveField('compressionType', 
                    BitMaskSerializer(Rdp.Info.CompressionTypeMask, StructEncodedSerializer(UINT_32_LE)), to_human_readable = lookup_name_in(Rdp.Info.PACKET_COMPR_TYPE_NAMES)),
            ]),
            PrimitiveField('cbDomain', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbUserName', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbPassword', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbAlternateShell', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbWorkingDir', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('Domain', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.cbDomain))),
            PrimitiveField('UserName', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.cbUserName))),
            PrimitiveField('Password', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.cbPassword))),
            PrimitiveField('AlternateShell', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.cbAlternateShell))),
            PrimitiveField('WorkingDir', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.cbWorkingDir))),
            OptionalField(DataUnitField('extraInfo', Rdp_TS_EXTENDED_INFO_PACKET())),
        ],
        use_class_as_pdu_name = True)

class Rdp_TS_EXTENDED_INFO_PACKET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_EXTENDED_INFO_PACKET, self).__init__(fields = [
            PrimitiveField('payload_todo', RawLengthSerializer()),
        ])

class Rdp_SEC_TRANSPORT_REQ(BaseDataUnit):
    def __init__(self):
        super(Rdp_SEC_TRANSPORT_REQ, self).__init__(fields = [
            PrimitiveField('requestId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('requestedProtocol', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('reserved', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('securityCookie', RawLengthSerializer(LengthDependency(lambda x: 16))),
        ],
        use_class_as_pdu_name = True)

class Rdp_SEC_TRANSPORT_RSP(BaseDataUnit):
    def __init__(self):
        super(Rdp_SEC_TRANSPORT_RSP, self).__init__(fields = [
            PrimitiveField('requestId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('hrResponse', StructEncodedSerializer(UINT_32_LE)),
        ],
        use_class_as_pdu_name = True)

class Rdp_LICENSE_VALID_CLIENT_DATA(BaseDataUnit):
    def __init__(self):
        super(Rdp_LICENSE_VALID_CLIENT_DATA, self).__init__(fields = [
            DataUnitField('preamble', Rdp_LICENSE_PREAMBLE()),
            PrimitiveField('validClientMessage', 
                RawLengthSerializer(LengthDependency(lambda x: self.preamble.wMsgSize - self.preamble.get_length()))),
        ],
        use_class_as_pdu_name = True)
        
class Rdp_LICENSE_PREAMBLE(BaseDataUnit):
    def __init__(self):
        super(Rdp_LICENSE_PREAMBLE, self).__init__(fields = [
            PrimitiveField('bMsgType', StructEncodedSerializer(UINT_8)),
            PrimitiveField('flags', StructEncodedSerializer(UINT_8)),
            PrimitiveField('wMsgSize', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_SHARECONTROLHEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SHARECONTROLHEADER, self).__init__(fields = [
            PrimitiveField('totalLength', StructEncodedSerializer(UINT_16_LE)),
            UnionField([
                PrimitiveField(
                    'pduType', 
                    BitMaskSerializer(Rdp.ShareControlHeader.PDU_TYPE_MASK, StructEncodedSerializer(UINT_16_LE)), 
                    to_human_readable = lookup_name_in(Rdp.ShareControlHeader.PDUTYPE_NAMES)),
                PrimitiveField('pduVersion', BitMaskSerializer(Rdp.ShareControlHeader.PDU_VERSION_MASK, StructEncodedSerializer(UINT_16_LE))),
            ]),
            PrimitiveField('pduSource', StructEncodedSerializer(UINT_16_LE)),
        ])
    
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append('RDP')
        retval.append(str(self._fields_by_name['pduType'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_SHARECONTROLHEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RDP', str(self._fields_by_name['pduType'].get_human_readable_value()))]


class Rdp_TS_SHAREDATAHEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SHAREDATAHEADER, self).__init__(fields = [
            PrimitiveField('shareID', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('pad1', StructEncodedSerializer(PAD)),
            PrimitiveField('streamID', StructEncodedSerializer(UINT_8)),
            PrimitiveField('uncompressedLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pduType2', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PDUTYPE2_NAMES)),
            UnionField([
                PrimitiveField('compressionArgs', BitFieldEncodedSerializer(UINT_8, Rdp.ShareDataHeader.PACKET_ARG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_ARG_NAMES)),
                PrimitiveField('compressionType', BitMaskSerializer(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_NAMES)),
            ]),
            PrimitiveField('compressedLength', StructEncodedSerializer(UINT_16_LE)),
        ])
    
    def get_pdu_types(self, rdp_context):
        retval = []
        if Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in self.compressionArgs:
            retval.append('(compressed)')
        retval.append(str(self._fields_by_name['pduType2'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_SHAREDATAHEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        retval = []
        retval.append(PduLayerSummary('RDP', str(self._fields_by_name['pduType2'].get_human_readable_value())))
        if Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in self.compressionArgs:
            retval.append(PduLayerSummary('RDP', 'compressed'))
        return retval


class Rdp_TS_DEMAND_ACTIVE_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_DEMAND_ACTIVE_PDU, self).__init__(fields = [
            PrimitiveField('shareID', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('lengthSourceDescriptor', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthCombinedCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('sourceDescriptor', RawLengthSerializer(LengthDependency(lambda x: self.lengthSourceDescriptor))),
            PrimitiveField('numberCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pad2Octets', StructEncodedSerializer(PAD * 2)),
            DataUnitField('capabilitySets', 
                ArrayDataUnit(Rdp_TS_CAPS_SET,
                    item_count_dependency = ValueDependency(lambda x: self.numberCapabilities),
                    alias_hinter = Rdp_TS_CAPS_SET.ALIAS_HINTER)),
            PrimitiveField('sessionId', StructEncodedSerializer(UINT_32_LE)),
        ],
        use_class_as_pdu_name = True)

class Rdp_TS_CONFIRM_ACTIVE_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_CONFIRM_ACTIVE_PDU, self).__init__(fields = [
            PrimitiveField('shareID', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('originatorID', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthSourceDescriptor', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthCombinedCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('sourceDescriptor', RawLengthSerializer(LengthDependency(lambda x: self.lengthSourceDescriptor))),
            PrimitiveField('numberCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pad2Octets', StructEncodedSerializer(PAD * 2)),
            DataUnitField('capabilitySets', 
                ArrayDataUnit(Rdp_TS_CAPS_SET,
                    item_count_dependency = ValueDependency(lambda x: self.numberCapabilities),
                    alias_hinter = Rdp_TS_CAPS_SET.ALIAS_HINTER)),
        ],
        use_class_as_pdu_name = True)

class Rdp_TS_CAPS_SET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_CAPS_SET, self).__init__(fields = [
            PrimitiveField('capabilitySetType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Capabilities.CAPSTYPE_NAMES)),
            PrimitiveField('lengthCapability', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('capabilityData', RawLengthSerializer(LengthDependency(lambda x: self.lengthCapability - self._fields_by_name['capabilitySetType'].get_length() - self._fields_by_name['lengthCapability'].get_length()))),
        ],
        auto_reinterpret_configs = [
            AutoReinterpret(
                field_to_reinterpret_name = 'capabilityData',
                type_getter = ValueDependency(lambda x: self.capabilitySetType),
                config_by_type = {
                    Rdp.Capabilities.CAPSTYPE_GENERAL: AutoReinterpretConfig('', Rdp_TS_GENERAL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_VIRTUALCHANNEL: AutoReinterpretConfig('', Rdp_TS_VIRTUALCHANNEL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_RAIL: AutoReinterpretConfig('', Rdp_TS_RAIL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_WINDOW: AutoReinterpretConfig('', Rdp_TS_WINDOW_CAPABILITYSET),
                }),
        ])
        
    ALIAS_HINTER = ValueDependency(lambda self: {
                Rdp.Capabilities.CAPSTYPE_GENERAL: 'generalCapability',
                Rdp.Capabilities.CAPSTYPE_VIRTUALCHANNEL: 'virtualChannelCapability',
                Rdp.Capabilities.CAPSTYPE_RAIL: 'railCapability',
                Rdp.Capabilities.CAPSTYPE_WINDOW: 'waindowCapability',
            }.get(self.capabilitySetType, None))

class Rdp_TS_GENERAL_CAPABILITYSET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_GENERAL_CAPABILITYSET, self).__init__(fields = [
            PrimitiveField('osMajorType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('osMinorType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('protocolVersion', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pad2octetsA', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('compressionTypes', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('extraFlags', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('updateCapabilityFlag', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('remoteUnshareFlag', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('compressionLevel', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('refreshRectSupport', StructEncodedSerializer(UINT_8)),
            PrimitiveField('suppressOutputSupport', StructEncodedSerializer(UINT_8)),
        ])

class Rdp_TS_VIRTUALCHANNEL_CAPABILITYSET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_VIRTUALCHANNEL_CAPABILITYSET, self).__init__(fields = [
            PrimitiveField('flags', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Capabilities.VirtualChannel.VCCAPS_NAMES)),
            OptionalField(PrimitiveField('VCChunkSize', StructEncodedSerializer(UINT_32_LE))),
        ])

class Rdp_TS_RAIL_CAPABILITYSET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_CAPABILITYSET, self).__init__(fields = [
            PrimitiveField('RailSupportLevel', StructEncodedSerializer(UINT_32_LE)),
        ])

class Rdp_TS_WINDOW_CAPABILITYSET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_WINDOW_CAPABILITYSET, self).__init__(fields = [
            PrimitiveField('WndSupportLevel', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('NumIconCaches', StructEncodedSerializer(UINT_8)),
            PrimitiveField('NumIconCacheEntries', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_CHANNEL_PDU_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_CHANNEL_PDU_HEADER, self).__init__(fields = [
            PrimitiveField('length', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Channel.CHANNEL_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Channel.CHANNEL_FLAG_NAMES)),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        if Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in self.flags:
            retval.append('(compressed)')
        retval.extend(super(Rdp_CHANNEL_PDU_HEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        retval = []
        if Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in self.flags:
            retval.append(PduLayerSummary('RDP', 'compressed'))
        return retval
