from data_model_v2 import (
        Tpkt,
        X224,
        Mcs,
        Rdp,
        
        PrimitiveField,
        DataUnitField,
    
        RawDataUnit, 
        TpktDataUnit, 
        X224HeaderDataUnit, 
        
        McsHeaderDataUnit, 
        McsConnectHeaderDataUnit,
        McsConnectInitialDataUnit,
        McsConnectResponseDataUnit,
        McsGccConnectionDataUnit,
        
        RdpUserDataBlock,
        Rdp_TS_UD_CS_CORE,
        
        Rdp_TS_UD_SC_CORE,
        Rdp_TS_UD_SC_NET,
        Rdp_TS_UD_SC_SEC1
        )
        
from serializers import (
    ArraySerializer,
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
        if pdu.tpkt.x224.get_x224_type_name() == X224.TPDU_DATA:
            pdu.tpkt.x224.reinterpret_field('x224UserData', DataUnitField('mcs', McsHeaderDataUnit()))
            if pdu.tpkt.x224.mcs.get_mcs_type_name() == Mcs.CONNECT:
                rdp_context.is_gcc_confrence = True
                # print('pdu.tpkt.x224.mcs = ', pdu.tpkt.x224.mcs)
                pdu.tpkt.x224.mcs.reinterpret_field('payload', DataUnitField('mcs_connect_header', McsConnectHeaderDataUnit()))

                if pdu.tpkt.x224.mcs.mcs_connect_header.get_mcs_connect_type() == Mcs.CONNECT_INITIAL:
                    pdu.tpkt.x224.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectInitialDataUnit()))
                elif pdu.tpkt.x224.mcs.mcs_connect_header.get_mcs_connect_type() == Mcs.CONNECT_RESPONSE:
                    pdu.tpkt.x224.mcs.reinterpret_field('payload.remaining', DataUnitField('connect_payload', McsConnectResponseDataUnit()))
                else:
                    raise ValueError('not yet supported')
                pdu.tpkt.x224.mcs.alias_field('rdp', 'connect_payload.userData.payload.gcc_userData')
                pdu.tpkt.x224.mcs.rdp.alias_field('user_data_array', 'payload')

                USER_DATA_TYPES = {
                    Rdp.UserData.CS_CORE: Rdp_TS_UD_CS_CORE,
                    
                    Rdp.UserData.SC_CORE: Rdp_TS_UD_SC_CORE,
                    Rdp.UserData.SC_NET: Rdp_TS_UD_SC_NET,
                    Rdp.UserData.SC_SECURITY: Rdp_TS_UD_SC_SEC1,
                }
                for i, user_data_item in enumerate(pdu.tpkt.x224.mcs.rdp.user_data_array):
                    user_data_item_type = user_data_item.header.get_type_name()
                    if user_data_item_type in USER_DATA_TYPES:
                        user_data_item.reinterpret_field('payload', DataUnitField('payload', USER_DATA_TYPES[user_data_item_type]()))
                        pdu.tpkt.x224.mcs.rdp.alias_field(user_data_item_type, 'user_data_array.%d' % i)
                
                if hasattr(pdu.tpkt.x224.mcs.rdp, 'serverSecurityData'):
                    rdp_context.encryption_level = pdu.tpkt.x224.mcs.rdp.serverSecurityData.payload.get_encryptionLevel_name()

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
