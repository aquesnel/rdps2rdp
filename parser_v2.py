import struct
import collections
import functools

import compression

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
    RawLengthSerializer,
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
    
    Rdp_CHANNEL_PDU,
)

from data_model_v2_rdp_fast_path import (
    Rdp_TS_FP_HEADER,
    Rdp_TS_FP_length_only,
    Rdp_TS_FP_INPUT_PDU,
    Rdp_TS_FP_UPDATE_PDU,
)

from data_model_v2_rdp_edyc import (
    Rdp_DYNVC_PDU,
    # Rdp_DYNVC_Header,
    # Rdp_DYNVC_CAPS_VERSION,
    # Rdp_DYNVC_CAPS_RSP,
    # Rdp_DYNVC_CREATE_REQ,
    # Rdp_DYNVC_CREATE_RSP,
    # Rdp_DYNVC_DATA_FIRST,
    # Rdp_DYNVC_DATA,
    # Rdp_DYNVC_CLOSE,
)
from data_model_v2_rdp_erp import (
    Rdp_TS_RAIL_PDU,
)
from data_model_v2_rdp_egfx import (
    # Rdp_RDP_SEGMENTED_DATA,
    Rdp_RDPGFX_PDU,
    # Rdp_RDPGFX_commands_PDU,
)
from parser_v2_context import (
    RdpContext,
    ChannelDef,
    DataChunk,
)

IS_DECRYPTION_SUPPORTED = False
NULL_CHANNEL = ChannelDef('null', 0, Rdp.Channel.ChannelType.STATIC)
# this is the special end of CREDSSP pdu that was observed in the prod Win10 RDP server traffic
CREDSSP_END_PDU = b'\x00\x00\x00\x00'

class ParserException(Exception):
    def __init__(self, pdu):
        self.pdu = pdu

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
    
    elif data == CREDSSP_END_PDU:
        return Rdp.DataUnitTypes.CREDSSP

    # Note: Rdp.DataUnitTypes.FAST_PATH == CREDSSP_END_PDU[0] so we need to check the more specific CREDSSP_END_PDU first
    elif (first_byte & Rdp.FastPath.FASTPATH_ACTIONS_MASK) == Rdp.DataUnitTypes.FAST_PATH:
        return Rdp.DataUnitTypes.FAST_PATH
    
    elif first_byte == Rdp.DataUnitTypes.CREDSSP:
        return Rdp.DataUnitTypes.CREDSSP

    # elif (not rdp_context.pre_capability_exchange) and (first_byte & Rdp.FastPath.FASTPATH_ACTIONS_MASK) == Rdp.DataUnitTypes.FAST_PATH:
    #     return Rdp.DataUnitTypes.FAST_PATH
    
    # elif rdp_context.pre_capability_exchange and first_byte == Rdp.DataUnitTypes.CREDSSP:
    #     return Rdp.DataUnitTypes.CREDSSP
        
    else:
        raise ValueError('Unsupported packet type: (len: %d) %s' % (len(data), data[:len(CREDSSP_END_PDU)]))

def parse_pdu_length(data, rdp_context = None):
    if rdp_context is None:
        rdp_context = RdpContext()
    pdu_type = _get_pdu_type(data, rdp_context)
    pdu_length = None
    
    if pdu_type == Rdp.DataUnitTypes.X224:
        pdu = RawDataUnit().with_value(data)
        pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_HEADER()), rdp_context)
        pdu.reinterpret_field('payload.remaining', DataUnitField('tpkt', TpktDataUnit()), rdp_context)
        
        pdu_length = pdu.tpkt.length
    
    elif pdu_type == Rdp.DataUnitTypes.FAST_PATH:
        pdu = RawDataUnit().with_value(data)
        pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_HEADER()), rdp_context)
        pdu.reinterpret_field('payload.remaining', DataUnitField('rdp_fp', Rdp_TS_FP_length_only()), rdp_context)
        
        pdu_length = pdu.rdp_fp.length
    
    elif pdu_type == Rdp.DataUnitTypes.CREDSSP:
        if data == CREDSSP_END_PDU:
            pdu_length = len(CREDSSP_END_PDU)
        else:
            # the pdu.credssp.length field only contains the length of 
            # the payload and not the header. Taking the length of the DataUnit 
            # works eventhough we only have the partial pdu because the 
            # RawLengthField size is taken from the value of the length field.
            pdu = RawDataUnit().with_value(data)
            pdu.reinterpret_field('payload', DataUnitField('credssp', BerEncodedDataUnit()), rdp_context)
            
            pdu_length = pdu.credssp.get_length()
    
    else:
        raise ValueError('Unsupported packet type')

    return pdu_length

def parse(pdu_source, data, rdp_context = None, parser_config = None):
    if rdp_context is None:
        rdp_context = RdpContext()

    try:
        # initialize with raw value so that the error message will be initialized
        pdu = RawDataUnit().with_value(data)

        with rdp_context.set_parser_config(parser_config):
            with rdp_context.set_pdu_source(pdu_source):
                
                pdu_type = _get_pdu_type(data, rdp_context)
                declared_length = parse_pdu_length(data, rdp_context)
                if declared_length != len(data):
                    raise ValueError('Unexpected data length for pdu type %s: declared_length = %d, acctual_length = %d' % (pdu_type, declared_length, len(data)))
                
                # pdu = RawDataUnit().with_value(data)
                
                if pdu_type == Rdp.DataUnitTypes.X224:
                    pdu.reinterpret_field('payload', DataUnitField('rdp_fp_header', Rdp_TS_FP_HEADER()), rdp_context)
                    pdu.reinterpret_field('payload.remaining', DataUnitField('tpkt', TpktDataUnit()), rdp_context)
                    pdu.tpkt.reinterpret_field('tpktUserData', DataUnitField('x224', X224HeaderDataUnit()), rdp_context)
                    if pdu.tpkt.x224.type == X224.TPDU_CONNECTION_REQUEST:
                        pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_connect', X224ConnectionDataUnit()), rdp_context)
                        routing_token_or_cookie_field = PrimitiveField('routing_token_or_cookie', DelimitedEncodedStringSerializer(EncodedStringSerializer.ASCII, '\r\n'))
                        if pdu.tpkt.x224.x224_connect.x224UserData[0] != b'C'[0]:
                            routing_token_or_cookie_field = ConditionallyPresentField(lambda: False, routing_token_or_cookie_field)
                        pdu.tpkt.x224.x224_connect.reinterpret_field('x224UserData', routing_token_or_cookie_field, rdp_context)
                        
                        pdu.tpkt.x224.x224_connect.reinterpret_field(
                            'x224UserData.remaining', 
                            OptionalField(DataUnitField('rdpNegReq_header', Rdp_RDP_NEG_header())),
                            rdp_context)
                        if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type != Rdp.Negotiate.RDP_NEG_REQ:
                            raise ValueError('incorrect rdpNegReq.type, expected RDP_NEG_REQ, but got %s'% (
                                pdu.tpkt.x224.x224_connect.rdpNegReq_header.get_type_name()))
                        pdu.tpkt.x224.x224_connect.reinterpret_field(
                            'x224UserData.remaining', 
                            OptionalField(DataUnitField('rdpNegReq', Rdp_RDP_NEG_REQ())),
                            rdp_context)
            
                    elif pdu.tpkt.x224.type == X224.TPDU_CONNECTION_CONFIRM:
                        pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_connect', X224ConnectionDataUnit()), rdp_context)
                        pdu.tpkt.x224.x224_connect.reinterpret_field(
                            'x224UserData.remaining', 
                            OptionalField(DataUnitField('rdpNegReq_header', Rdp_RDP_NEG_header())),
                            rdp_context)
                        if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type != Rdp.Negotiate.RDP_NEG_RSP:
                            raise ValueError('incorrect rdpNegReq.type, expected RDP_NEG_RSP, but got %s'% (
                                pdu.tpkt.x224.x224_connect.rdpNegReq_header.get_type_name()))
                        pdu.tpkt.x224.x224_connect.reinterpret_field(
                            'x224UserData.remaining', 
                            OptionalField(DataUnitField('rdpNegRsp', Rdp_RDP_NEG_RSP())),
                            rdp_context)
                        
            
                    elif pdu.tpkt.x224.type == X224.TPDU_DATA:
                        pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_data_header', X224DataHeaderDataUnit()), rdp_context)
                        # print('pdu.tpkt.x224 = ', pdu.tpkt.x224)
                        pdu.tpkt.reinterpret_field('tpktUserData.remaining', DataUnitField('mcs', McsHeaderDataUnit()), rdp_context)
                        
                        if pdu.tpkt.mcs.type == Mcs.CHANNEL_JOIN_REQUEST:
                            pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('channel_join_request', McsChannelJoinRequestDataUnit()), rdp_context)
                            
                        elif pdu.tpkt.mcs.type == Mcs.CONNECT:
                            rdp_context.is_gcc_confrence = True
                            # print('pdu.tpkt.mcs = ', pdu.tpkt.mcs)
                            pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_connect_header', McsConnectHeaderDataUnit()), rdp_context)
            
                            if pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_INITIAL:
                                pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectInitialDataUnit()), rdp_context)
                            
                            elif pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_RESPONSE:
                                pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectResponseDataUnit()), rdp_context)
                            
                            else:
                                raise ValueError('not supported')
                            
                            pdu.tpkt.mcs.alias_field('rdp', 'connect_payload.userData.payload.gcc_userData.payload')
                            if hasattr(pdu.tpkt.mcs.rdp, 'clientNetworkData'):
                                for i, channel_def in enumerate(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray):
                                    rdp_context.add_channel(ChannelDef(channel_def.name, channel_def.options, Rdp.Channel.ChannelType.STATIC, channel_index = i))
                            if hasattr(pdu.tpkt.mcs.rdp, 'serverNetworkData'):
                                for channel_def, id in zip(rdp_context.get_channels_by_index(), pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray):
                                    channel_def.channel_id = id
                                channel_id = pdu.tpkt.mcs.rdp.serverNetworkData.payload.MCSChannelId
                                mcs_channel_def = ChannelDef(Rdp.Channel.IO_CHANNEL_NAME, 0, Rdp.Channel.ChannelType.STATIC, channel_id)
                                rdp_context.add_channel(mcs_channel_def)
                            if hasattr(pdu.tpkt.mcs.rdp, 'serverMessageChannelData'):
                                channel_id = pdu.tpkt.mcs.rdp.serverMessageChannelData.payload.MCSChannelId
                                mcs_channel_def = ChannelDef(Rdp.Channel.MESSAGE_CHANNEL_NAME, 0, Rdp.Channel.ChannelType.STATIC, channel_id)
                                rdp_context.add_channel(mcs_channel_def)
                            
                            if hasattr(pdu.tpkt.mcs.rdp, 'serverSecurityData'):
                                rdp_context.encryption_level = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel
                                rdp_context.encryption_method = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod
                                
                            
                        if pdu.tpkt.mcs.type in {Mcs.SEND_DATA_FROM_CLIENT, Mcs.SEND_DATA_FROM_SERVER}:
                            pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_user_data', McsSendDataUnit()), rdp_context)
                            pdu.tpkt.mcs.alias_field('rdp', 'mcs_user_data.mcs_data')
            
                            if rdp_context.encryption_level is None:
                                raise ValueError('Protocol Error: the excryption level must be set by a previous Mcs.CONNECT_RESPONSE PDU, but it has not been set yet')
                            
                            if pdu.tpkt.mcs.mcs_user_data.channelId == Rdp.Channel.MCS_GLOBAL_CHANNEL_ID:
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
                                    pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('sec_header', Rdp_TS_SECURITY_HEADER()), rdp_context)
                                    is_payload_encrypted = Rdp.Security.SEC_ENCRYPT in pdu.tpkt.mcs.rdp.sec_header.flags
                                    
                                if hasattr(pdu.tpkt.mcs.rdp, 'sec_header'):
                                    if Rdp.Security.SEC_EXCHANGE_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SECURITY_PACKET', Rdp_TS_SECURITY_PACKET()), rdp_context)
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
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()), rdp_context)
                                        else:
                                            raise ValueError('FIPS encryption not supported yet')
                                        
                                        # if is_payload_encrypted:
                                        #     if IS_DECRYPTION_SUPPORTED:
                                        #         # TODO: decrypt payload
                                        #         is_payload_encrypted = False
                                        #         raise ValueError('RDP Standard encrypted payloads are not supported')
                                        #     pass
                                        if not is_payload_encrypted:
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_INFO_PACKET', Rdp_TS_INFO_PACKET()), rdp_context)
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
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()), rdp_context)
                                        else:
                                            raise ValueError('FIPS encryption not supported yet')
                                        
                                        if is_payload_encrypted:
                                            if IS_DECRYPTION_SUPPORTED:
                                                # TODO: decrypt payload
                                                is_payload_encrypted = False
                                            raise ValueError('RDP Standard encrypted payloads are not supported')
                                        if not is_payload_encrypted:
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('LICENSE_VALID_CLIENT_DATA', Rdp_LICENSE_VALID_CLIENT_DATA()), rdp_context)
                                            is_payload_handeled = True
                                    
                                    elif Rdp.Security.SEC_TRANSPORT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags:
                                        if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                            pass
                                        else:
                                            raise ValueError('encryption not supported yet')
                                        
                                        if not is_payload_encrypted:
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('SEC_TRANSPORT_REQ', Rdp_SEC_TRANSPORT_REQ()), rdp_context)
                                            is_payload_handeled = True
                                            # rdp_context.pre_capability_exchange = False
                                    
                                    elif Rdp.Security.SEC_TRANSPORT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags:
                                        if rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_NONE:
                                            pass
                                        else:
                                            raise ValueError('encryption not supported yet')
                                        
                                        if not is_payload_encrypted:
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('SEC_TRANSPORT_RSP', Rdp_SEC_TRANSPORT_RSP()), rdp_context)
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
                                            pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('sec_header1', Rdp_TS_SECURITY_HEADER1()), rdp_context)
                                        else:
                                            raise ValueError('FIPS encryption not supported yet')
                                        # if is_payload_encrypted:
                                        #     if IS_DECRYPTION_SUPPORTED:
                                        #         # TODO: decrypt payload
                                        #         is_payload_encrypted = False
                                        #         raise ValueError('RDP Standard encrypted payloads are not supported')
                
                                if not is_payload_encrypted and not is_payload_handeled:
                                    pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SHARECONTROLHEADER', Rdp_TS_SHARECONTROLHEADER()), rdp_context)
                                    
                                    if pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_DEMANDACTIVEPDU:
                                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_DEMAND_ACTIVE_PDU', Rdp_TS_DEMAND_ACTIVE_PDU()), rdp_context)
                                        rdp_context.pre_capability_exchange = False
                                        if pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags == Rdp.Capabilities.VirtualChannel.VCCAPS_COMPR_CS_8K:
                                            rdp_context.compression_virtual_chan_cs_encoder = compression.CompressionFactory.new_RDP_40()
                                        
                                    elif pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU:
                                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_CONFIRM_ACTIVE_PDU', Rdp_TS_CONFIRM_ACTIVE_PDU()), rdp_context)
                                        
                                    elif pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_DATAPDU:
                                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SHAREDATAHEADER', Rdp_TS_SHAREDATAHEADER()), rdp_context)
                            
                            elif rdp_context.get_channel_by_id(pdu.tpkt.mcs.mcs_user_data.channelId, NULL_CHANNEL).name == Rdp.Channel.MESSAGE_CHANNEL_NAME:
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('sec_header', Rdp_TS_SECURITY_HEADER()), rdp_context)
                                
                            else: # all other channels
                                pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('channel', Rdp_CHANNEL_PDU()), rdp_context)
                                channel_id = pdu.tpkt.mcs.mcs_user_data.channelId
                                
                                if Rdp.Channel.CHANNEL_FLAG_FIRST in pdu.tpkt.mcs.rdp.channel.header.flags:
                                    rdp_context.set_channel_chunk(channel_id, chunk = DataChunk(pdu.tpkt.mcs.rdp.channel.header.length))
                                data_chunk = rdp_context.get_channel_chunk(channel_id)
                                data_chunk.append_data(pdu.tpkt.mcs.rdp.channel.payload)
                                
                                if Rdp.Channel.CHANNEL_FLAG_LAST in pdu.tpkt.mcs.rdp.channel.header.flags:
                                    if not data_chunk.is_full():
                                        raise ValueError("The DataChunk is expected to be full because we got the last chunk flag but the chunk is not full. %s" % (data_chunk,))
                                    rdp_context.set_channel_chunk(channel_id, chunk = None)
                                    pdu.tpkt.mcs.rdp.channel.payload = data_chunk.get_data()
                                    
                                    channel_name = rdp_context.get_channel_by_id(channel_id, NULL_CHANNEL).name
                                    if channel_name == Rdp.Channel.RAIL_CHANNEL_NAME:
                                        pdu.tpkt.mcs.rdp.channel.reinterpret_field('payload', DataUnitField('TS_RAIL_PDU', Rdp_TS_RAIL_PDU()), rdp_context)
                                    elif channel_name == Rdp.Channel.DRDYNVC_CHANNEL_NAME: 
                                        pdu.tpkt.mcs.rdp.channel.reinterpret_field('payload.remaining', DataUnitField('dyvc', Rdp_DYNVC_PDU(rdp_context.pdu_source)), rdp_context)
                                        if (pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd == Rdp.DynamicVirtualChannels.COMMAND_CREATE
                                                and rdp_context.pdu_source == RdpContext.PduSource.SERVER):
                                            channel_name = pdu.tpkt.mcs.rdp.channel.dyvc.payload.ChannelName
                                            channel_id = pdu.tpkt.mcs.rdp.channel.dyvc.payload.ChannelId
                                            if channel_name in rdp_context.get_channel_names():
                                                channel = rdp_context.get_channel_by_name(channel_name)
                                                channel.options = Rdp.DynamicVirtualChannels.DYNAMIC_VIRTUAL_CHANNEL_OPTIONS
                                                channel.type = Rdp.Channel.ChannelType.DYNAMIC
                                                channel.channel_id = channel_id
                                            else:
                                                channel = ChannelDef(channel_name, Rdp.DynamicVirtualChannels.DYNAMIC_VIRTUAL_CHANNEL_OPTIONS, Rdp.Channel.ChannelType.DYNAMIC, channel_id)
                                                rdp_context.add_channel(channel)
                                        
                                        elif pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd == Rdp.DynamicVirtualChannels.COMMAND_CLOSE:
                                            channel_id = pdu.tpkt.mcs.rdp.channel.dyvc.payload.ChannelId
                                            rdp_context.remove_channel_by_id(channel_id)
                                        
                                        elif pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd in {
                                                    Rdp.DynamicVirtualChannels.COMMAND_DATA_FIRST,
                                                    Rdp.DynamicVirtualChannels.COMMAND_DATA,
                                                    # Rdp.DynamicVirtualChannels.COMMAND_COMPRESSED_DATA_FIRST,
                                                    # Rdp.DynamicVirtualChannels.COMMAND_COMPRESSED_DATA,
                                                }:
                                            
                                            if pdu.tpkt.mcs.rdp.channel.dyvc.has_path('data_first'):
                                                pdu.tpkt.mcs.rdp.channel.dyvc.alias_field('data', 'data_first')
                                            
                                            channel_id = pdu.tpkt.mcs.rdp.channel.dyvc.data.ChannelId
                                            if pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd in {
                                                        Rdp.DynamicVirtualChannels.COMMAND_DATA_FIRST,
                                                        Rdp.DynamicVirtualChannels.COMMAND_COMPRESSED_DATA_FIRST,
                                                    }:
                                                rdp_context.set_channel_chunk(channel_id, chunk = DataChunk(pdu.tpkt.mcs.rdp.channel.dyvc.data_first.Length))
                                            elif not rdp_context.has_channel_chunk(channel_id):
                                                rdp_context.set_channel_chunk(channel_id, chunk = DataChunk(len(pdu.tpkt.mcs.rdp.channel.dyvc.data.Data)))
                                            data_chunk = rdp_context.get_channel_chunk(channel_id)
                                            data_chunk.append_data(pdu.tpkt.mcs.rdp.channel.dyvc.data.Data)
                                            
                                            if data_chunk.is_full():
                                                rdp_context.set_channel_chunk(channel_id, chunk = None)
                                                pdu.tpkt.mcs.rdp.channel.dyvc.data.Data = data_chunk.get_data()
                                                
                                                channel_name = rdp_context.get_channel_by_id(channel_id, NULL_CHANNEL).name
                                                if channel_name == Rdp.Channel.RAIL_CHANNEL_NAME:
                                                    pdu.tpkt.mcs.rdp.channel.dyvc.data.reinterpret_field('Data', DataUnitField('TS_RAIL_PDU', Rdp_TS_RAIL_PDU()), rdp_context)
                                                if channel_name == Rdp.Channel.GFX_CHANNEL_NAME:
                                                    pdu.tpkt.mcs.rdp.channel.dyvc.data.reinterpret_field('Data', DataUnitField('GFX_PDU', Rdp_RDPGFX_PDU()), rdp_context)
                                                    
                                                    
                elif pdu_type == Rdp.DataUnitTypes.FAST_PATH:
                    if rdp_context.pdu_source == RdpContext.PduSource.CLIENT:
                        pdu.reinterpret_field('payload', 
                            DataUnitField('rdp_fp', 
                                Rdp_TS_FP_INPUT_PDU(
                                    is_fips_present = (rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_FIPS))),
                            rdp_context)
                    elif rdp_context.pdu_source == RdpContext.PduSource.SERVER:
                        pdu.reinterpret_field('payload', 
                            DataUnitField('rdp_fp', 
                                Rdp_TS_FP_UPDATE_PDU(
                                    rdp_context,
                                    is_fips_present = (rdp_context.encryption_level == Rdp.Security.ENCRYPTION_LEVEL_FIPS))),
                            rdp_context)
                    else:
                        raise ValueError("Unknown PduSource when processing FAST_PATH PDU")
                    
                    
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
    except Exception as e:
        raise ParserException(pdu) from e
    return pdu
    

