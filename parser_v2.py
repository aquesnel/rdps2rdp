import struct
import collections

from data_model_v2 import (
    PrimitiveField,
    DataUnitField,
    OptionalField,
    ConditionallyPresentField,

    RawDataUnit,
    BerEncodedDataUnit,
)
        
from serializers import (
    UINT_16_LE,
    
    ArraySerializer,
    EncodedStringSerializer,
    DelimitedEncodedStringSerializer,
)

from data_model_v2_tpkt import (
    Tpkt,
    TpktDataUnit, 
)
from data_model_v2_x224 import (
    X224,
    X224HeaderDataUnit, 
    X224DataHeaderDataUnit,
    X224ConnectionDataUnit,
)
from data_model_v2_mcs import (
    Mcs,
    McsHeaderDataUnit, 
    McsConnectHeaderDataUnit,
    McsConnectInitialDataUnit,
    McsConnectResponseDataUnit,
    McsGccConnectionDataUnit,
    McsSendDataUnit,
    McsChannelJoinRequestDataUnit,
)
from data_model_v2_rdp import (
    Rdp,

    Rdp_RDP_NEG_header,
    Rdp_RDP_NEG_REQ,
    Rdp_RDP_NEG_RSP,
    
    RdpUserDataBlock,
    Rdp_TS_UD_CS_CORE,
    Rdp_TS_UD_CS_SEC,
    Rdp_TS_UD_CS_NET,
    
    Rdp_TS_UD_SC_CORE,
    Rdp_TS_UD_SC_NET,
    Rdp_TS_UD_SC_SEC1,
    
    Rdp_TS_SECURITY_HEADER,
    Rdp_TS_SECURITY_HEADER1,
    Rdp_TS_SECURITY_PACKET,
    Rdp_TS_INFO_PACKET,
    Rdp_SEC_TRANSPORT_REQ,
    Rdp_SEC_TRANSPORT_RSP,
    Rdp_LICENSE_VALID_CLIENT_DATA,
    
    Rdp_TS_SHARECONTROLHEADER,
    Rdp_TS_SHAREDATAHEADER,
    Rdp_TS_DEMAND_ACTIVE_PDU,
    Rdp_TS_CONFIRM_ACTIVE_PDU,
    
    Rdp_CHANNEL_PDU_HEADER,
)

from data_model_v2_rdp_fast_path import (
    Rdp_TS_FP_INPUT_HEADER,
    Rdp_TS_FP_INPUT_PDU,
    Rdp_TS_FP_INPUT_PDU_length_only,
)

class RdpContext(object):
    def __init__(self):
        self.is_gcc_confrence = False
        self.encryption_level = None
        self.encryption_method = None
        self.encrypted_client_random = None
        self.pre_capability_exchange = True
        
        self.auto_logon = False
        self.rail_enabled = False
        self.compression_type = None
        self.domain = None
        self.user_name = None
        self.password = None
        self.alternate_shell = None
        self.working_dir = None
        
        self.channel_defs = []
        self.channels = {}
        
        
    def clone(self):
        import copy
        return copy.deepcopy(self)
        
    def __str__(self):
        return str({k:v for k,v in self.__dict__.items() if not callable(v)})

ChannelDef = collections.namedtuple('ChannelDef', ['name', 'options'])

IS_DECRYPTION_SUPPORTED = False

def _get_pdu_type(data, rdp_context):
    
    # the first byte value of the payload for each type is:
    # FASTPATH = xxxx xx00
    # CREDSSP  = 0011 0000
    # X224     = 0000 0011
    #
    # this give the possibility that CREDSSP and FASTPATH could have the same 
    # value. This can be resolved because a CREDSSP pdu will only be sent during 
    # connection initialization, while FASTPATH will only be sent after the 
    # connection initialization is complete.
    
    first_byte = data[0]
    if first_byte == Rdp.DataUnitTypes.X224:
        return Rdp.DataUnitTypes.X224
    
    elif (not rdp_context.pre_capability_exchange) and (first_byte & Rdp.FastPath.FASTPATH_INPUT_ACTIONS_MASK) == Rdp.DataUnitTypes.FAST_PATH:
        return Rdp.DataUnitTypes.FAST_PATH
    
    elif rdp_context.pre_capability_exchange and first_byte == Rdp.DataUnitTypes.CREDSSP:
        return Rdp.DataUnitTypes.CREDSSP
    
    elif data == b'\x00\x00\x00\x00':
        # this is the special end of CREDSSP pdu that was observed in the prod Win10 RDP server traffic
        return Rdp.DataUnitTypes.CREDSSP
        
    else:
        raise ValueError('Unsupported packet type')

def parse_pdu_length(data, rdp_context = None):
    if rdp_context is None:
        rdp_context = RdpContext()
    
    pdu_type = _get_pdu_type(data, rdp_context)
    
    if pdu_type == Rdp.DataUnitTypes.X224:
        pdu = RawDataUnit().with_value(data)
        pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_INPUT_HEADER()))
        pdu.reinterpret_field('payload.remaining', DataUnitField('tpkt', TpktDataUnit()))
        
        return pdu.tpkt.length
    
    elif pdu_type == Rdp.DataUnitTypes.FAST_PATH:
        pdu = RawDataUnit().with_value(data)
        pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_INPUT_HEADER()))
        pdu.reinterpret_field('payload.remaining', DataUnitField('rdp_fp', Rdp_TS_FP_INPUT_PDU_length_only()))
        
        return pdu.rdp_fp.length
    
    elif pdu_type == Rdp.DataUnitTypes.CREDSSP:
        # the pdu.credssp.length field only contains the length of 
        # the payload and not the header. Taking the length of the DataUnit 
        # works eventhough we only have the partial pdu because the 
        # RawLengthField size is taken from the value of the length field.
        pdu = RawDataUnit().with_value(data)
        pdu.reinterpret_field('payload', DataUnitField('credssp', BerEncodedDataUnit()))
        
        return len(pdu.credssp)
    
    else:
        raise ValueError('Unsupported packet type')

def parse(data, rdp_context = None):
    if rdp_context is None:
        rdp_context = RdpContext()
        
    # rdp_context.is_gcc_confrence = False
    pdu_type = _get_pdu_type(data, rdp_context)
    
    pdu = RawDataUnit().with_value(data)
    
    if pdu_type in { Rdp.DataUnitTypes.X224, Rdp.DataUnitTypes.FAST_PATH }:
        pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_INPUT_HEADER()))
    
    if pdu_type == Rdp.DataUnitTypes.X224:
        pdu.reinterpret_field('payload.remaining', DataUnitField('tpkt', TpktDataUnit()))
        pdu.tpkt.reinterpret_field('tpktUserData', DataUnitField('x224', X224HeaderDataUnit()))
        if pdu.tpkt.x224.type == X224.TPDU_CONNECTION_REQUEST:
            pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_connect', X224ConnectionDataUnit()))
            routing_token_or_cookie_field = PrimitiveField('routing_token_or_cookie', DelimitedEncodedStringSerializer(EncodedStringSerializer.ASCII, '\r\n'))
            if pdu.tpkt.x224.x224_connect.x224UserData[0] != b'C'[0]:
                routing_token_or_cookie_field = ConditionallyPresentField(lambda: False, routing_token_or_cookie_field)
            pdu.tpkt.x224.x224_connect.reinterpret_field('x224UserData', routing_token_or_cookie_field)
            
            pdu.tpkt.x224.x224_connect.reinterpret_field(
                'x224UserData.remaining', 
                OptionalField(DataUnitField('rdpNegReq_header', Rdp_RDP_NEG_header())))
            if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type != Rdp.Negotiate.RDP_NEG_REQ:
                raise ValueError('incorrect rdpNegReq.type, expected RDP_NEG_REQ, but got %s'% (
                    pdu.tpkt.x224.x224_connect.rdpNegReq_header.get_type_name()))
            pdu.tpkt.x224.x224_connect.reinterpret_field(
                'x224UserData.remaining', 
                OptionalField(DataUnitField('rdpNegReq', Rdp_RDP_NEG_REQ())))

        elif pdu.tpkt.x224.type == X224.TPDU_CONNECTION_CONFIRM:
            pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_connect', X224ConnectionDataUnit()))
            pdu.tpkt.x224.x224_connect.reinterpret_field(
                'x224UserData.remaining', 
                OptionalField(DataUnitField('rdpNegReq_header', Rdp_RDP_NEG_header())))
            if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type != Rdp.Negotiate.RDP_NEG_RSP:
                raise ValueError('incorrect rdpNegReq.type, expected RDP_NEG_RSP, but got %s'% (
                    pdu.tpkt.x224.x224_connect.rdpNegReq_header.get_type_name()))
            pdu.tpkt.x224.x224_connect.reinterpret_field(
                'x224UserData.remaining', 
                OptionalField(DataUnitField('rdpNegRsp', Rdp_RDP_NEG_RSP())))
            

        elif pdu.tpkt.x224.type == X224.TPDU_DATA:
            pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_data_header', X224DataHeaderDataUnit()))
            # print('pdu.tpkt.x224 = ', pdu.tpkt.x224)
            pdu.tpkt.reinterpret_field('tpktUserData.remaining', DataUnitField('mcs', McsHeaderDataUnit()))
            
            if pdu.tpkt.mcs.type == Mcs.CHANNEL_JOIN_REQUEST:
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('channel_join_request', McsChannelJoinRequestDataUnit()))
                
            elif pdu.tpkt.mcs.type == Mcs.CONNECT:
                rdp_context.is_gcc_confrence = True
                # print('pdu.tpkt.mcs = ', pdu.tpkt.mcs)
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_connect_header', McsConnectHeaderDataUnit()))

                if pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_INITIAL:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectInitialDataUnit()))
                
                elif pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_RESPONSE:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectResponseDataUnit()))
                
                else:
                    raise ValueError('not supported')
                
                pdu.tpkt.mcs.alias_field('rdp', 'connect_payload.userData.payload')
                if hasattr(pdu.tpkt.mcs.rdp, 'clientNetworkData'):
                    for channel_def in pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray:
                        rdp_context.channel_defs.append(ChannelDef(channel_def.name, channel_def.options))
                if hasattr(pdu.tpkt.mcs.rdp, 'serverNetworkData'):
                    for channel_def, id in zip(rdp_context.channel_defs, pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray):
                        rdp_context.channels[id] = channel_def
                if hasattr(pdu.tpkt.mcs.rdp, 'serverMessageChannelData'):
                    channel_id = pdu.tpkt.mcs.rdp.serverMessageChannelData.payload.MCSChannelId
                    channel_def = ChannelDef('McsChannel', 0)
                    rdp_context.channels[channel_id] = channel_def
                    rdp_context.channel_defs.append(channel_def)
                
                if hasattr(pdu.tpkt.mcs.rdp, 'serverSecurityData'):
                    rdp_context.encryption_level = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel
                    rdp_context.encryption_method = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod
                    
                
            if pdu.tpkt.mcs.type in {Mcs.SEND_DATA_FROM_CLIENT, Mcs.SEND_DATA_FROM_SERVER}:
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_user_data', McsSendDataUnit()))
                pdu.tpkt.mcs.alias_field('rdp', 'mcs_user_data.mcs_data')

                if rdp_context.encryption_level is None:
                   raise ValueError('Protocol Error: the excryption level must be set by a previous Mcs.CONNECT_RESPONSE PDU, but it has not been set yet')
                
                if pdu.tpkt.mcs.mcs_user_data.channelId == 1003:
                    pdu_header_type_hint = None
                    if rdp_context.pre_capability_exchange:
                        first_two_bytes = pdu.tpkt.mcs.rdp.payload[0:2]
                        first_two_bytes_int = struct.unpack(UINT_16_LE, first_two_bytes)[0]
                        if bin(first_two_bytes_int & Rdp.Security.PACKET_MASK).count("1") in {0, 1}:
                            pdu_header_type_hint = 'TS_SECURITY_HEADER'
                        if len(pdu.tpkt.mcs.rdp.payload) == first_two_bytes_int:
                            if pdu_header_type_hint is not None:
                                raise ValueError('Ambiguous RDP header. The header could be either TS_SECURITY_HEADER or TS_SHARECONTROLHEADER')
                            pdu_header_type_hint = 'TS_SHARECONTROLHEADER'
                        if pdu_header_type_hint is None:
                            raise ValueError('Uknown RDP header. The header is neither TS_SECURITY_HEADER nor TS_SHARECONTROLHEADER')
    
                    is_payload_encrypted = False
                    is_payload_handeled = False
                    if (pdu_header_type_hint == 'TS_SECURITY_HEADER' or 
                            rdp_context.encryption_level != Rdp.Security.ENCRYPTION_LEVEL_NONE):
                        pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('sec_header', Rdp_TS_SECURITY_HEADER()))
                        is_payload_encrypted = Rdp.Security.SEC_ENCRYPT in pdu.tpkt.mcs.rdp.sec_header.flags
                        
                    if hasattr(pdu.tpkt.mcs.rdp, 'sec_header'):
                        if Rdp.Security.SEC_EXCHANGE_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SECURITY_PACKET', Rdp_TS_SECURITY_PACKET()))
                            rdp_context.encrypted_client_random = pdu.tpkt.mcs.rdp.TS_SECURITY_PACKET.encryptedClientRandom
                            is_payload_handeled = True
                            
                        elif Rdp.Security.SEC_INFO_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                            if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                pass
                            elif rdp_context.encryption_method in {
                                    Rdp.Security.ENCRYPTION_METHOD_40BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_56BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_128BIT,
                                    }:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()))
                            else:
                                raise ValueError('FIPS encryption not supported yet')
                            
                            # if is_payload_encrypted:
                            #     if IS_DECRYPTION_SUPPORTED:
                            #         # TODO: decrypt payload
                            #         is_payload_encrypted = False
                            #         raise ValueError('RDP Standard encrypted payloads are not supported')
                            #     pass
                            if not is_payload_encrypted:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_INFO_PACKET', Rdp_TS_INFO_PACKET()))
                                if Rdp.Info.INFO_UNICODE not in pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags:
                                    raise ValueError('Non-unicode not supported yet')
                                rdp_context.auto_logon = Rdp.Info.INFO_AUTOLOGON in pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags
                                rdp_context.rail_enabled = Rdp.Info.INFO_RAIL in pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags
                                if Rdp.Info.INFO_COMPRESSION in pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags:
                                    rdp_context.compression_type = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.compressionType
                                rdp_context.domain = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.Domain
                                rdp_context.user_name = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.UserName
                                rdp_context.password = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.Password
                                rdp_context.alternate_shell = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.AlternateShell
                                rdp_context.working_dir = pdu.tpkt.mcs.rdp.TS_INFO_PACKET.WorkingDir
                                is_payload_handeled = True
    
                        elif Rdp.Security.SEC_LICENSE_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                            if (rdp_context.encryption_level in {
                                    Rdp.Security.ENCRYPTION_LEVEL_NONE, 
                                    Rdp.Security.ENCRYPTION_LEVEL_LOW
                                    }):
                                pass
                            elif (rdp_context.encryption_method in {
                                    Rdp.Security.ENCRYPTION_METHOD_40BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_56BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_128BIT,
                                    }):
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()))
                            else:
                                raise ValueError('FIPS encryption not supported yet')
                            
                            if is_payload_encrypted:
                                if IS_DECRYPTION_SUPPORTED:
                                    # TODO: decrypt payload
                                    is_payload_encrypted = False
                                raise ValueError('RDP Standard encrypted payloads are not supported')
                            if not is_payload_encrypted:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('LICENSE_VALID_CLIENT_DATA', Rdp_LICENSE_VALID_CLIENT_DATA()))
                                is_payload_handeled = True
                        
                        elif Rdp.Security.SEC_TRANSPORT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags:
                            if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                pass
                            else:
                                raise ValueError('encryption not supported yet')
                            
                            if not is_payload_encrypted:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('SEC_TRANSPORT_REQ', Rdp_SEC_TRANSPORT_REQ()))
                                is_payload_handeled = True
                                # rdp_context.pre_capability_exchange = False
                        
                        elif Rdp.Security.SEC_TRANSPORT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags:
                            if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                pass
                            else:
                                raise ValueError('encryption not supported yet')
                            
                            if not is_payload_encrypted:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('SEC_TRANSPORT_RSP', Rdp_SEC_TRANSPORT_RSP()))
                                is_payload_handeled = True
                            
                        else:
                            # raise ValueError('Protocol error: unknown security packet type')
                            if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                pass
                            elif rdp_context.encryption_method in {
                                    Rdp.Security.ENCRYPTION_METHOD_40BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_56BIT,
                                    Rdp.Security.ENCRYPTION_METHOD_128BIT,
                                    }:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()))
                            else:
                                raise ValueError('FIPS encryption not supported yet')
                            # if is_payload_encrypted:
                            #     if IS_DECRYPTION_SUPPORTED:
                            #         # TODO: decrypt payload
                            #         is_payload_encrypted = False
                            #         raise ValueError('RDP Standard encrypted payloads are not supported')
    
                    if not is_payload_encrypted and not is_payload_handeled:
                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SHARECONTROLHEADER', Rdp_TS_SHARECONTROLHEADER()))
                        
                        if pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_DEMANDACTIVEPDU:
                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_DEMAND_ACTIVE_PDU', Rdp_TS_DEMAND_ACTIVE_PDU()))
                            rdp_context.pre_capability_exchange = False
                            
                        elif pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU:
                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_CONFIRM_ACTIVE_PDU', Rdp_TS_CONFIRM_ACTIVE_PDU()))
                            
                        elif pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_DATAPDU:
                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SHAREDATAHEADER', Rdp_TS_SHAREDATAHEADER()))
                else:
                    pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('CHANNEL_PDU_HEADER', Rdp_CHANNEL_PDU_HEADER()))
                    
    elif pdu_type == Rdp.DataUnitTypes.FAST_PATH:
        pdu.reinterpret_field('payload.remaining', 
                DataUnitField('rdp_fp', 
                    Rdp_TS_FP_INPUT_PDU(
                        is_fips_present = (rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_FIPS), 
                        is_data_signature_present = Rdp.FastPath.FASTPATH_INPUT_FLAG_SECURE_CHECKSUM in pdu.rdp_fp_header.flags, 
                        is_num_events_present = pdu.rdp_fp_header.numEvents == 0)))
        
        
    elif pdu_type == Rdp.DataUnitTypes.CREDSSP:
        pass
    
    else:
        ValueError('Unsupported packet type')
        
    # if rdp_context.is_gcc_confrence and tpkt.x224.mcs.rdp.rdpGcc_SERVER_SECURITY:
    #     rdp_context.encryption_level = tpkt.x224.mcs.rdp.rdpGcc_SERVER_SECURITY.encryption_level

    # if (tpkt.x224.mcs 
    #         and tpkt.x224.mcs.rdp
    #         and tpkt.x224.mcs.rdp.sec_header 
    #         and tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT):
    #     raise ValueError('RDP Standard encrypted payloads are not supported')
            
    # if (tpkt.x224.mcs 
    #         and tpkt.x224.mcs.rdp
    #         and tpkt.x224.mcs.rdp.TS_SECURITY_PACKET):
    #     rdp_context.encrypted_client_random = tpkt.x224.mcs.rdp.TS_SECURITY_PACKET.encrypted_client_random
    
    # if (tpkt.x224.mcs 
    #         and tpkt.x224.mcs.rdp 
    #         and tpkt.x224.mcs.rdp.is_license_success()):
    #     rdp_context.pre_capability_exchange = False
    
    return pdu


