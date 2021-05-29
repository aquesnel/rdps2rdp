import functools

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
    RawLengthSerializer,
    DependentValueSerializer,
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
    
    ValueDependency,
    LengthDependency,
)

class Rdp(object):
    @add_constants_names_mapping('FASTPATH_INPUT_FLAG_', 'FASTPATH_INPUT_FLAG_NAMES')
    @add_constants_names_mapping('FASTPATH_INPUT_ACTION_', 'FASTPATH_INPUT_ACTION_NAMES')
    class FastPath(object):
        FASTPATH_INPUT_ACTIONS_MASK = 0x03
        FASTPATH_INPUT_NUM_EVENTS_MASK = 0x3c
        
        FASTPATH_INPUT_ACTION_FASTPATH = 0x00
        FASTPATH_INPUT_ACTION_X224 = 0x03
        
        FASTPATH_INPUT_FLAG_SECURE_CHECKSUM = (0x1 << 6)
        FASTPATH_INPUT_FLAG_ENCRYPTED = (0x2 << 6)
        
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
        
        USER_DATA_NAMES = {
            CS_CORE: 'CS_CORE',
            CS_SECURITY: 'CS_SECURITY',
            CS_NET: 'CS_NET',
            
            SC_CORE: 'SC_CORE',
            SC_SECURITY: 'SC_SECURITY',
            SC_NET: 'SC_NET',
        }

    @add_constants_names_mapping('PROTOCOL_', 'PROTOCOL_NAMES')
    class Protocols(object):
        PROTOCOL_RDP = 0x00000000
        PROTOCOL_SSL = 0x00000001
        PROTOCOL_HYBRID = 0x00000002
        PROTOCOL_RDSTLS = 0x00000004
        PROTOCOL_HYBRID_EX = 0x00000008
        
    @add_constants_names_mapping('ENCRYPTION_METHOD_', 'ENCRYPTION_METHOD_NAMES')
    @add_constants_names_mapping('ENCRYPTION_LEVEL_', 'ENCRYPTION_LEVEL_NAMES')
    class Security(object):
        SEC_HDR_BASIC = 'Basic'
        SEC_HDR_NON_FIPS = 'Non-FIPS'
        SEC_HEADER_TYPE = {
            1: SEC_HDR_BASIC,
            2: SEC_HDR_NON_FIPS,
            3: 'FIPS',
        }
        
        SEC_EXCHANGE_PKT = 0x0001
        SEC_ENCRYPT = 0x0008
        SEC_RESET_SEQNO = 0x0010
        SEC_IGNORE_SEQNO = 0x0020
        SEC_INFO_PKT = 0x0040
        SEC_LICENSE_PKT = 0x0080
        SEC_LICENSE_ENCRYPT = 0x0200
        SEC_LICENSE_ENCRYPT_CS = 0x0200
        SEC_PACKET_FLAGS = {
            SEC_EXCHANGE_PKT: 'SEC_EXCHANGE_PKT',
            SEC_ENCRYPT: 'SEC_ENCRYPT',
            SEC_RESET_SEQNO: 'SEC_RESET_SEQNO',
            SEC_IGNORE_SEQNO: 'SEC_IGNORE_SEQNO',
            SEC_INFO_PKT: 'SEC_INFO_PKT',
            SEC_LICENSE_PKT: 'SEC_LICENSE_PKT',
            SEC_LICENSE_ENCRYPT: 'SEC_LICENSE_ENCRYPT',
            SEC_LICENSE_ENCRYPT_CS: 'SEC_LICENSE_ENCRYPT_CS',
        }
        SEC_PACKET_MASK = 0
        for key in SEC_PACKET_FLAGS.keys():
            SEC_PACKET_MASK |= key
    
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
        
        PDUTYPE2_CONTROL = 0x14
        PDUTYPE2_SYNCHRONIZE = 0x1f

    @add_constants_names_mapping('CAPSTYPE_', 'CAPSTYPE_NAMES')
    class Capabilities(object):
        CAPSTYPE_VIRTUALCHANNEL = 0x0014
        CAPSTYPE_RAIL = 0x0017
        CAPSTYPE_WINDOW = 0x0018
        
        @add_constants_names_mapping('VCCAPS_', 'VCCAPS_NAMES')
        class VirtualChannel(object):
            VCCAPS_NO_COMPR = 0x00000000
            VCCAPS_COMPR_SC = 0x00000001
            VCCAPS_COMPR_CS_8K = 0x00000002

class DataUnitTypes(object):
    X224 = Rdp.FastPath.FASTPATH_INPUT_ACTION_X224
    FAST_PATH = Rdp.FastPath.FASTPATH_INPUT_ACTION_FASTPATH
    CREDSSP = 0x30 # 0x30 is the DER identifier for SEQUNCE which is the top level type of the [MS-CSSP] TSRequest struct.

Rdp.DataUnitTypes = DataUnitTypes  
            

class Rdp_RDP_NEG_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_header, self).__init__(fields = [
            PrimitiveField('type', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Negotiate.RDP_NEG_NAMES)),
        ])
        
class Rdp_RDP_NEG_REQ(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_REQ, self).__init__(fields = [
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.Negotiate.REQUEST_FLAGS.keys()), to_human_readable = lookup_name_in(Rdp.Negotiate.REQUEST_FLAGS)),
            PrimitiveField('length', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('requestedProtocols', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Protocols.PROTOCOL_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Protocols.PROTOCOL_NAMES)),
        ])

class Rdp_RDP_NEG_RSP(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_RSP, self).__init__(fields = [
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.Negotiate.RESPONSE_FLAGS.keys()), to_human_readable = lookup_name_in(Rdp.Negotiate.RESPONSE_FLAGS)),
            PrimitiveField('length', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('selectedProtocol', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.Protocols.PROTOCOL_NAMES)),
        ])

class Rdp_RDP_NEG_FAILURE(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP_NEG_FAILURE, self).__init__(fields = [
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
                RawLengthSerializer(LengthDependency(lambda x: self.header.length - len(self.header)))),
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
                PrimitiveField('earlyCapabilityFlags', StructEncodedSerializer(UINT_16_LE))),
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
            PrimitiveField('channelDefArray',
                ArraySerializer(
                    DataUnitSerializer(Rdp_CHANNEL_DEF),
                    item_count_dependency = ValueDependency(lambda x: self.channelCount))),
        ])

class Rdp_CHANNEL_DEF(BaseDataUnit):
    def __init__(self):
        super(Rdp_CHANNEL_DEF, self).__init__(fields = [
            PrimitiveField('name', FixedLengthEncodedStringSerializer(EncodedStringSerializer.ASCII, 8)),
            PrimitiveField('options', StructEncodedSerializer(UINT_32_LE)),
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
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Security.SEC_PACKET_FLAGS.keys()), to_human_readable = lookup_name_in(Rdp.Security.SEC_PACKET_FLAGS)),
            PrimitiveField('flagsHi', StructEncodedSerializer(UINT_16_LE)),
        ])

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
        ])

class Rdp_TS_EXTENDED_INFO_PACKET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_EXTENDED_INFO_PACKET, self).__init__(fields = [
            PrimitiveField('payload_todo', RawLengthSerializer()),
        ])

class Rdp_LICENSE_VALID_CLIENT_DATA(BaseDataUnit):
    def __init__(self):
        super(Rdp_LICENSE_VALID_CLIENT_DATA, self).__init__(fields = [
            DataUnitField('preamble', Rdp_LICENSE_PREAMBLE()),
            PrimitiveField('validClientMessage', 
                RawLengthSerializer(LengthDependency(lambda x: self.preamble.wMsgSize - len(self.preamble)))),
        ])
        
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
                PrimitiveField('pduType', BitMaskSerializer(Rdp.ShareControlHeader.PDU_TYPE_MASK, StructEncodedSerializer(UINT_16_LE))),
                PrimitiveField('pduVersion', BitMaskSerializer(Rdp.ShareControlHeader.PDU_VERSION_MASK, StructEncodedSerializer(UINT_16_LE))),
            ]),
            PrimitiveField('pduSource', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_SHAREDATAHEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SHAREDATAHEADER, self).__init__(fields = [
            PrimitiveField('shareID', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('pad1', StructEncodedSerializer(PAD)),
            PrimitiveField('streamID', StructEncodedSerializer(UINT_8)),
            PrimitiveField('uncompressedLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pduType2', StructEncodedSerializer(UINT_8)),
            UnionField([
                PrimitiveField('compressionArgs', BitFieldEncodedSerializer(UINT_8, Rdp.ShareDataHeader.PACKET_ARG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_ARG_NAMES)),
                PrimitiveField('compressionType', BitMaskSerializer(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_NAMES)),
            ]),
            PrimitiveField('compressedLength', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_DEMAND_ACTIVE_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_DEMAND_ACTIVE_PDU, self).__init__(fields = [
            PrimitiveField('shareID', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('lengthSourceDescriptor', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('lengthCombinedCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('sourceDescriptor', RawLengthSerializer(LengthDependency(lambda x: self.lengthSourceDescriptor))),
            PrimitiveField('numberCapabilities', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('pad2Octets', StructEncodedSerializer(PAD * 2)),
            PrimitiveField('capabilitySets', 
                ArraySerializer(
                    DataUnitSerializer(Rdp_TS_CAPS_SET),
                    item_count_dependency = ValueDependency(lambda x: self.numberCapabilities))),
            PrimitiveField('sessionId', StructEncodedSerializer(UINT_32_LE)),
        ],
        auto_reinterpret_configs = [
            ArrayAutoReinterpret(
                array_field_to_reinterpret_name = 'capabilitySets',
                item_field_to_reinterpret_name = 'capabilityData',
                type_getter = ValueDependency(lambda capability_item: capability_item.capabilitySetType),
                type_mapping = {
                    Rdp.Capabilities.CAPSTYPE_VIRTUALCHANNEL: AutoReinterpretItem('virtualChannelCapability', Rdp_TS_VIRTUALCHANNEL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_RAIL: AutoReinterpretItem('railCapability', Rdp_TS_RAIL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_WINDOW: AutoReinterpretItem('waindowCapability', Rdp_TS_WINDOW_CAPABILITYSET),
                })
        ])

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
            PrimitiveField('capabilitySets', 
                ArraySerializer(
                    DataUnitSerializer(Rdp_TS_CAPS_SET),
                    item_count_dependency = ValueDependency(lambda x: self.numberCapabilities))),
        ],
        auto_reinterpret_configs = [
            ArrayAutoReinterpret(
                array_field_to_reinterpret_name = 'capabilitySets',
                item_field_to_reinterpret_name = 'capabilityData',
                type_getter = ValueDependency(lambda capability_item: capability_item.capabilitySetType),
                type_mapping = {
                    Rdp.Capabilities.CAPSTYPE_VIRTUALCHANNEL: AutoReinterpretItem('virtualChannelCapability', Rdp_TS_VIRTUALCHANNEL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_RAIL: AutoReinterpretItem('railCapability', Rdp_TS_RAIL_CAPABILITYSET),
                    Rdp.Capabilities.CAPSTYPE_WINDOW: AutoReinterpretItem('waindowCapability', Rdp_TS_WINDOW_CAPABILITYSET),
                })
        ])

class Rdp_TS_CAPS_SET(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_CAPS_SET, self).__init__(fields = [
            PrimitiveField('capabilitySetType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Capabilities.CAPSTYPE_NAMES)),
            PrimitiveField('lengthCapability', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('capabilityData', RawLengthSerializer(LengthDependency(lambda x: self.lengthCapability - self._fields_by_name['capabilitySetType'].get_length() - self._fields_by_name['lengthCapability'].get_length()))),
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
