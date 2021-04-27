from data_model_v2 import (
    PrimitiveField,
    DataUnitField,
    OptionalField,
    ConditionallyPresentField,

    RawDataUnit, 
)
        
from serializers import (
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
    Rdp_LICENSE_VALID_CLIENT_DATA,
    
    Rdp_TS_SHARECONTROLHEADER,
    Rdp_TS_DEMAND_ACTIVE_PDU,
    Rdp_TS_CONFIRM_ACTIVE_PDU,
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
        
    def clone(self):
        import copy
        return copy.deepcopy(self)

IS_DECRYPTION_SUPPORTED = False

def parse(data, rdp_context = None):
    if rdp_context is None:
        rdp_context = RdpContext()
        
    # rdp_context.is_gcc_confrence = False
    data = memoryview(data)
    pdu = RawDataUnit()
    pdu.deserialize_value(data)
    pdu.reinterpret_field('payload', DataUnitField('tpkt', TpktDataUnit()))
    
    if pdu.tpkt.version == Tpkt.SLOW_PATH:
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
            
            if pdu.tpkt.mcs.type == Mcs.CONNECT:
                rdp_context.is_gcc_confrence = True
                # print('pdu.tpkt.mcs = ', pdu.tpkt.mcs)
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_connect_header', McsConnectHeaderDataUnit()))

                if pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_INITIAL:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectInitialDataUnit()))
                
                elif pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type == Mcs.CONNECT_RESPONSE:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectResponseDataUnit()))
                
                else:
                    raise ValueError('not supported')
                
                pdu.tpkt.mcs.alias_field('rdp', 'connect_payload.userData.payload.gcc_userData')
                pdu.tpkt.mcs.rdp.alias_field('user_data_array', 'payload')

                USER_DATA_TYPES = {
                    Rdp.UserData.CS_CORE: ('clientCoreData', Rdp_TS_UD_CS_CORE),
                    Rdp.UserData.CS_SECURITY: ('clientSecurityData', Rdp_TS_UD_CS_SEC),
                    Rdp.UserData.CS_NET: ('clientNetworkData', Rdp_TS_UD_CS_NET),
                    
                    Rdp.UserData.SC_CORE: ('serverCoreData', Rdp_TS_UD_SC_CORE),
                    Rdp.UserData.SC_NET: ('serverNetworkData', Rdp_TS_UD_SC_NET),
                    Rdp.UserData.SC_SECURITY: ('serverSecurityData', Rdp_TS_UD_SC_SEC1),
                }
                for i, user_data_item in enumerate(pdu.tpkt.mcs.rdp.user_data_array):
                    if user_data_item.header.type in USER_DATA_TYPES:
                        field_name, factory  = USER_DATA_TYPES[user_data_item.header.type]
                        user_data_item.reinterpret_field('payload', DataUnitField('payload', factory()), allow_overwrite = True)
                        pdu.tpkt.mcs.rdp.alias_field(field_name, 'user_data_array.%d' % i)
                
                if hasattr(pdu.tpkt.mcs.rdp, 'serverSecurityData'):
                    rdp_context.encryption_level = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel
                    rdp_context.encryption_method = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod
            
            if pdu.tpkt.mcs.type in {Mcs.SEND_DATA_FROM_CLIENT, Mcs.SEND_DATA_FROM_SERVER}:
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_user_data', McsSendDataUnit()))
                pdu.tpkt.mcs.alias_field('rdp', 'mcs_user_data.mcs_data')

                if rdp_context.encryption_level is None:
                   raise ValueError('Protocol Error: the excryption level must be set by a previous Mcs.CONNECT_RESPONSE PDU, but it has not been set yet')
                is_payload_encrypted = False
                is_payload_handeled = False
                if (rdp_context.pre_capability_exchange or 
                        rdp_context.encryption_level != Rdp.Security.SEC_ENCRYPTION_NONE):
                    pdu.tpkt.mcs.rdp.reinterpret_field('payload', DataUnitField('sec_header', Rdp_TS_SECURITY_HEADER()))
                    is_payload_encrypted = Rdp.Security.SEC_ENCRYPT in pdu.tpkt.mcs.rdp.sec_header.flags
                    
                if hasattr(pdu.tpkt.mcs.rdp, 'sec_header'):
                    if Rdp.Security.SEC_EXCHANGE_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_SECURITY_PACKET', Rdp_TS_SECURITY_PACKET()))
                        rdp_context.encrypted_client_random = pdu.tpkt.mcs.rdp.TS_SECURITY_PACKET.encryptedClientRandom
                        is_payload_handeled = True
                        
                    elif Rdp.Security.SEC_INFO_PKT in pdu.tpkt.mcs.rdp.sec_header.flags:
                        if rdp_context.encryption_level == Rdp.Security.SEC_ENCRYPTION_NONE:
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
                                Rdp.Security.SEC_ENCRYPTION_NONE, 
                                Rdp.Security.SEC_ENCRYPTION_LOW
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
                            rdp_context.pre_capability_exchange = False
                            is_payload_handeled = True
                    else:
                        # raise ValueError('Protocol error: unknown security packet type')
                        if rdp_context.encryption_level == Rdp.Security.SEC_ENCRYPTION_NONE:
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
                        
                    elif pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType == Rdp.ShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU:
                        pdu.tpkt.mcs.rdp.reinterpret_field('payload.remaining', DataUnitField('TS_CONFIRM_ACTIVE_PDU', Rdp_TS_CONFIRM_ACTIVE_PDU()))
                        
    else:
        raise ValueError('not yet supported')
        
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
