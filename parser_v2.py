from data_model_v2 import (
        Tpkt,
        X224,
        Mcs,
        Rdp,
        
        PrimitiveField,
        DataUnitField,
        OptionalField,
        ConditionallyPresentField,
    
        RawDataUnit, 
        TpktDataUnit, 
        X224HeaderDataUnit, 
        X224DataHeaderDataUnit,
        X224ConnectionDataUnit,
        
        McsHeaderDataUnit, 
        McsConnectHeaderDataUnit,
        McsConnectInitialDataUnit,
        McsConnectResponseDataUnit,
        McsGccConnectionDataUnit,
        
        Rdp_RDP_NEG_header,
        Rdp_RDP_NEG_REQ,
        Rdp_RDP_NEG_RSP,
        
        RdpUserDataBlock,
        Rdp_TS_UD_CS_CORE,
        Rdp_TS_UD_CS_SEC,
        Rdp_TS_UD_CS_NET,
        
        Rdp_TS_UD_SC_CORE,
        Rdp_TS_UD_SC_NET,
        Rdp_TS_UD_SC_SEC1
        )
        
from serializers import (
    ArraySerializer,
    DelimitedEncodedStringSerializer,
    )

class RdpContext(object):
    def __init__(self):
        self.is_gcc_confrence = False
        self.encryption_level = None
        self.encrypted_client_random = None
        self.pre_capability_exchange = True
        
    def clone(self):
        import copy
        return copy.deepcopy(self)

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
        if pdu.tpkt.x224.get_x224_type_name() == X224.TPDU_CONNECTION_REQUEST:
            pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_connect', X224ConnectionDataUnit()))
            routing_token_or_cookie_field = PrimitiveField('routing_token_or_cookie', DelimitedEncodedStringSerializer('ascii', '\r\n'))
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

        elif pdu.tpkt.x224.get_x224_type_name() == X224.TPDU_CONNECTION_CONFIRM:
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
            

        elif pdu.tpkt.x224.get_x224_type_name() == X224.TPDU_DATA:
            pdu.tpkt.x224.reinterpret_field('payload', DataUnitField('x224_data_header', X224DataHeaderDataUnit()))
            # print('pdu.tpkt.x224 = ', pdu.tpkt.x224)
            pdu.tpkt.reinterpret_field('tpktUserData.remaining', DataUnitField('mcs', McsHeaderDataUnit()))
            
            if pdu.tpkt.mcs.get_mcs_type_name() == Mcs.CONNECT:
                rdp_context.is_gcc_confrence = True
                # print('pdu.tpkt.mcs = ', pdu.tpkt.mcs)
                pdu.tpkt.mcs.reinterpret_field('payload', DataUnitField('mcs_connect_header', McsConnectHeaderDataUnit()))

                if pdu.tpkt.mcs.mcs_connect_header.get_mcs_connect_type() == Mcs.CONNECT_INITIAL:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectInitialDataUnit()))
                elif pdu.tpkt.mcs.mcs_connect_header.get_mcs_connect_type() == Mcs.CONNECT_RESPONSE:
                    pdu.tpkt.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectResponseDataUnit()))
                else:
                    raise ValueError('not yet supported')
                
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
                        user_data_item.reinterpret_field('payload', DataUnitField('payload', factory()))
                        pdu.tpkt.mcs.rdp.alias_field(field_name, 'user_data_array.%d' % i)
                
                if hasattr(pdu.tpkt.mcs.rdp, 'serverSecurityData'):
                    rdp_context.encryption_level = pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel

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
