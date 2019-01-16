import logging
from scapy.all import *
import codecs
import json
import xdrlib

#how can imports be so painful??
sys.path.insert(0, './diameter')
from diameter.AVP import AVP
from diameter.Message import Message
from diameter.AVP_UTF8String import AVP_UTF8String
from diameter.AVP_Unsigned32 import AVP_Unsigned32
from diameter.AVP_OctetString import AVP_OctetString
from diameter.AVP_Grouped import AVP_Grouped

with open('config.json', 'r') as f:
    config = json.load(f)

logger = logging.getLogger("diameter_msg_injector")
logging.basicConfig(level=logging.INFO)

# create a file handler
handler = logging.FileHandler('diameter_msg_injector.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)


class SCTPPacket():

    def __init__(self):

        logger.info('Building packet')

    def buildRequestPacket(self):

        p = xdrlib.Packer()

        msg = Message()
        if not config['VARIOUS']['_exclude_S6A_APPLICATION_ID']:
            msg.hdr.application_id = config['VARIOUS']['S6A_APPLICATION_ID']
        if not config['AVPCODE']['_exclude_diameter_request_answer_command_code']:
            msg.hdr.command_code = config['AVPCODE']['DIAMETER_REQUEST_ANSWER_COMMAND_CODE']
        msg.hdr.setRequest(True)
        msg.hdr.setProxiable(True)
        msg.hdr.hop_by_hop_identifier = 17
        msg.hdr.end_to_end_identifier = 117

        if not config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and not config['SESSION']['_exclude_SESSION_ID']:
            avp_sessionid = AVP_UTF8String(config['AVPCODE']['DIAMETER_SESSION_ID'],
                                           config['SESSION']['SESSION_ID'])
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())

        elif not config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and config['SESSION']['_exclude_SESSION_ID']:

            #essentially empty diameter session id

            avp_sessionid = AVP_UTF8String(config['AVPCODE']['DIAMETER_SESSION_ID'],
                                           "")
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())
            logger.warn('inhibited session id data')

        elif config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and not config['SESSION']['_exclude_SESSION_ID']:

            #TBD, TODO set AVP code to zero

            avp_sessionid = AVP_UTF8String(0,
                                           config['SESSION']['SESSION_ID'])
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())
            logger.warn('inhibited session id avp code')

        else:
            logger.warn('Not building in session id at all')


        avp_origin_host = AVP_UTF8String(config['AVPCODE']['ORIGIN_HOST'],
                                         config['SESSION']['ORIGIN_HOST'])
        avp_origin_host.setMandatory(True)
        avp_origin_host.setPrivate(False)

        logger.info('avp_origin_host length: %d', avp_origin_host.encodeSize())

        avp_originrealm = AVP_UTF8String(config['AVPCODE']['ORIGIN_REALM'],
                                         config['SESSION']['ORIGIN_REALM'])
        avp_originrealm.setMandatory(True)
        avp_originrealm.setPrivate(False)

        msg.append(avp_originrealm)
        logger.info('avp_originrealm length: %d', avp_originrealm.encodeSize())

        avp_destination_host = AVP_UTF8String(config['AVPCODE']['DESTINATION_HOST'],
                                              config['SESSION']['DESTINATION_HOST'])
        avp_destination_host.setMandatory(True)
        avp_destination_host.setPrivate(False)

        msg.append(avp_destination_host)
        logger.info('avp_destination_host length: %d', avp_destination_host.encodeSize())

        avp_destinationrealm = AVP_UTF8String(config['AVPCODE']['DESTINATION_REALM'],
                                              config['SESSION']['DESTINATION_REALM'])
        avp_destinationrealm.setMandatory(True)
        avp_destinationrealm.setPrivate(False)

        msg.append(avp_destinationrealm)
        logger.info('avp_destinationrealm length: %d', avp_destinationrealm.encodeSize())

        avp_authsessionstate = AVP_Unsigned32(config['AVPCODE']['AUTH_SESSION_STATE'],
                                              1)
        avp_authsessionstate.setMandatory(True)
        avp_authsessionstate.setPrivate(False)

        msg.append(avp_authsessionstate)
        logger.info('avp_authsessionstate length: %d', avp_authsessionstate.encodeSize())

        #only used in request
        #
        if not config['AVPCODE']['_exclude_USER_NAME'] and not config['IMSI']['_exclude_USER']:

            avp_username = AVP_UTF8String(config['AVPCODE']['USER_NAME'],
                                          config['IMSI']['USER'])
            avp_username.setMandatory(True)
            avp_username.setPrivate(False)

            msg.append(avp_username)
            logger.info('avp_username length: %d', avp_username.encodeSize())

        elif not config['AVPCODE']['_exclude_USER_NAME'] and config['IMSI']['_exclude_USER']:

            #essentially empty imsi

            avp_username = AVP_UTF8String(config['AVPCODE']['USER_NAME'],
                                          "")
            avp_username.setMandatory(True)
            avp_username.setPrivate(False)

            msg.append(avp_username)
            logger.info('avp_username length: %d', avp_username.encodeSize())
            logger.warn('inhibited imsi')

        elif config['AVPCODE']['_exclude_USER_NAME'] and not config['IMSI']['_exclude_USER']:

            #TBD, TODO set AVP code to zero

            avp_username = AVP_UTF8String(0,
                                          config['IMSI']['USER'])
            avp_username.setMandatory(True)
            avp_username.setPrivate(False)

            msg.append(avp_username)
            logger.info('avp_username length: %d', avp_username.encodeSize())
            logger.warn('inhibited imsi avp code')

        else:
            logger.warn('Not building in imsi at all')


        avp_visited_plmn_id = AVP_UTF8String(config['AVPCODE']['VISITED_PLMN_ID'],
                                             config['IMSI']['VISITED_PLMN_ID'],
                                             config['VARIOUS']['VENDOR_ID'])
        avp_visited_plmn_id.setMandatory(True)
        avp_visited_plmn_id.setPrivate(False)

        msg.append(avp_visited_plmn_id)
        logger.info('avp_visited_plmn_id length: %d', avp_visited_plmn_id.encodeSize())

        avp_vendor_id = AVP_Unsigned32(config['AVPCODE']['VENDOR_ID'],
                                       config['VARIOUS']['VENDOR_ID'])
        avp_vendor_id.setMandatory(True)
        avp_vendor_id.setPrivate(False)

        avp_auth_application_id = AVP_Unsigned32(config['AVPCODE']['AUTH_APPLICATION_ID'],
                                                 config['VARIOUS']['S6A_APPLICATION_ID'])
        avp_auth_application_id.setMandatory(True)
        avp_auth_application_id.setPrivate(False)

        avp_vendor_specific_application_id = AVP_Grouped(config['AVPCODE']['AUTH_APPLICATION_ID'], [avp_vendor_id, avp_auth_application_id])
        avp_vendor_specific_application_id.setMandatory(True)
        avp_vendor_specific_application_id.setPrivate(False)
        msg.append(avp_vendor_specific_application_id)

        #variation

        if config['AVPCODE']['_exclude_NUMBER_OF_REQUESTED_VECTORS'] or config['EUTRAN_VECTOR']['_exclude_NUMBER_OF_REQUESTED_VECTORS']:
            logger.warn('Not building in number of requested vectors at all, skip the rest')

        else:
            avp_number_of_requested_vectors = AVP_Unsigned32(config['AVPCODE']['NUMBER_OF_REQUESTED_VECTORS'],
                                                             config['EUTRAN_VECTOR']['NUMBER_OF_REQUESTED_VECTORS'],
                                                             config['VARIOUS']['VENDOR_ID'])
            avp_number_of_requested_vectors.setMandatory(True)
            avp_number_of_requested_vectors.setPrivate(False)

            avp_requested_eutran_auth_info = AVP_Grouped(config['AVPCODE']['REQUESTED_EUTRAN_AUTHENTICATION_INFO'],
                                                         [avp_number_of_requested_vectors],
                                                         config['VARIOUS']['VENDOR_ID'])
            avp_requested_eutran_auth_info.setMandatory(True)
            avp_requested_eutran_auth_info.setPrivate(False)

            msg.append(avp_requested_eutran_auth_info)

        logger.info('total encoded length: %d', msg.encodeSize())

        msg.encode(p)

        #IP
        self.ip = IP(src=config['ADDRESS']['HOST_IP'])
        logger.info('ip: %s', self.ip)

        #SCTP
        self.sctp =SCTP(dport=config['ADDRESS']['DIAMETER_PORT'],sport=config['ADDRESS']['DIAMETER_PORT'])
        logger.info('sctp: %s', self.sctp)

        self.sctp.sport = config['ADDRESS']['DIAMETER_PORT']
        self.sctp.dport = config['ADDRESS']['DIAMETER_PORT']
        self.sctp.tag = config['SCTP_DATA']['tag']     #or None
        self.sctp.chksum = config['SCTP_DATA']['chksum']  #or None

        #SCTP Data Chunk
        self.sctp_data = SCTPChunkData(self.sctp)
        self.sctp_data.type = 0  #data chunk
        self.sctp_data.flags     = 0x0
        self.sctp_data.len       = msg.encodeSize()  #depending on payload
        self.sctp_data.proto_id  = config['PPID']['DIAMETER_PPID_46'] #diameter
        self.sctp_data.stream_id  = config['SCTP_DATA']['stream_id']
        self.sctp_data.stream_seq = config['SCTP_DATA']['stream_seq']

        self.sctp_data.data = p.get_buffer()

        #logger.info('the avps: %s', self.sctp_data.data)

        self.packet = self.ip / self.sctp / self.sctp_data
        (self.packet).show()


    def buildAnswerPacket(self):

        p = xdrlib.Packer()

        msg = Message()
        msg.hdr.application_id = 16777251
        msg.hdr.command_code = 318
        msg.hdr.setRequest(True)
        msg.hdr.setProxiable(True)
        msg.hdr.hop_by_hop_identifier = 17
        msg.hdr.end_to_end_identifier = 117

        if not config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and not config['SESSION']['_exclude_SESSION_ID']:

            avp_sessionid = AVP_UTF8String(config['AVPCODE']['DIAMETER_SESSION_ID'],
                                           config['SESSION']['SESSION_ID'])
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())

        elif not config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and config['SESSION']['_exclude_SESSION_ID']:

            #essentially empty diameter session id

            avp_sessionid = AVP_UTF8String(config['AVPCODE']['DIAMETER_SESSION_ID'],
                                           "")
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())
            logger.warn('inhibited session id data')

        elif config['AVPCODE']['_exclude_DIAMETER_SESSION_ID'] and not config['SESSION']['_exclude_SESSION_ID']:

            #TBD, TODO set AVP code to zero
            #
            avp_sessionid = AVP_UTF8String(0,
                                           config['SESSION']['SESSION_ID'])
            avp_sessionid.setMandatory(True)
            avp_sessionid.setPrivate(False)

            msg.append(avp_sessionid)
            logger.info('avp_sessionid length: %d', avp_sessionid.encodeSize())
            logger.warn('inhibited session id avp code')

        else:

            logger.warn('Not building in session id at all')


        avp_origin_host = AVP_UTF8String(config['AVPCODE']['ORIGIN_HOST'],
                                         config['SESSION']['ORIGIN_HOST'])
        avp_origin_host.setMandatory(True)
        avp_origin_host.setPrivate(False)

        avp_originrealm = AVP_UTF8String(config['AVPCODE']['ORIGIN_REALM'],
                                         config['SESSION']['ORIGIN_REALM'])
        avp_originrealm.setMandatory(True)
        avp_originrealm.setPrivate(False)

        msg.append(avp_originrealm)
        logger.info('avp_originrealm length: %d', avp_originrealm.encodeSize())

        avp_destination_host = AVP_UTF8String(config['AVPCODE']['DESTINATION_HOST'],
                                              config['SESSION']['DESTINATION_HOST'])
        avp_destination_host.setMandatory(True)
        avp_destination_host.setPrivate(False)

        avp_destinationrealm = AVP_UTF8String(config['AVPCODE']['DESTINATION_REALM'],
                                              config['SESSION']['DESTINATION_REALM'])
        avp_destinationrealm.setMandatory(True)
        avp_destinationrealm.setPrivate(False)

        msg.append(avp_destinationrealm)
        logger.info('avp_destinationrealm length: %d', avp_destinationrealm.encodeSize())

        avp_authsessionstate = AVP_Unsigned32(config['AVPCODE']['AUTH_SESSION_STATE'],
                                              1)
        avp_authsessionstate.setMandatory(True)
        avp_authsessionstate.setPrivate(False)

        msg.append(avp_authsessionstate)
        logger.info('avp_authsessionstate length: %d', avp_authsessionstate.encodeSize())


        avp_item_number = AVP_Unsigned32(config['AVPCODE']['ITEM_NUMBER'],
                                         2,
                                         config['VARIOUS']['VENDOR_ID'])
        avp_item_number.setMandatory(True)
        avp_item_number.setPrivate(False)

        logger.info('avp_item_number length: %d', avp_item_number.encodeSize())

        avp_rand = AVP_OctetString(config['AVPCODE']['RAND'],
                                   bytes.fromhex(config['EUTRAN_VECTOR']['RAND']),
                                   config['VARIOUS']['VENDOR_ID'])
        avp_rand.setMandatory(True)
        avp_rand.setPrivate(False)

        logger.info('avp_rand length: %d', avp_rand.encodeSize())

        avp_xres = AVP_OctetString(config['AVPCODE']['XRES'],
                                   bytes.fromhex(config['EUTRAN_VECTOR']['XRES']),
                                   config['VARIOUS']['VENDOR_ID'])
        avp_xres.setMandatory(True)
        avp_xres.setPrivate(False)

        logger.info('avp_xres length: %d', avp_xres.encodeSize())

        avp_autn = AVP_OctetString(config['AVPCODE']['AUTN'],
                                   bytes.fromhex(config['EUTRAN_VECTOR']['AUTN']),
                                   config['VARIOUS']['VENDOR_ID'])
        avp_autn.setMandatory(True)
        avp_autn.setPrivate(False)

        logger.info('avp_autn length: %d', avp_autn.encodeSize())

        avp_kasme = AVP_OctetString(config['AVPCODE']['KASME'],
                                    bytes.fromhex(config['EUTRAN_VECTOR']['KASME']),
                                    config['VARIOUS']['VENDOR_ID'])
        avp_kasme.setMandatory(True)
        avp_kasme.setPrivate(False)

        logger.info('avp_kasme length: %d', avp_kasme.encodeSize())

        if config['EUTRAN_VECTOR']['_exclude_RAND']:

            avp_EUTRANVector = AVP_Grouped(config['AVPCODE']['EUTRAN_VECTOR'],
                                           [avp_item_number, avp_xres, avp_autn, avp_kasme],
                                           config['VARIOUS']['VENDOR_ID'])

            logger.warn('excluded RAND')


        elif config['EUTRAN_VECTOR']['_exclude_XRES']:

            avp_EUTRANVector = AVP_Grouped(config['AVPCODE']['EUTRAN_VECTOR'],
                                           [avp_item_number, avp_rand, avp_autn, avp_kasme],
                                           config['VARIOUS']['VENDOR_ID'])

            logger.warn('excluded XRES')

        elif config['EUTRAN_VECTOR']['_exclude_AUTN']:

            avp_EUTRANVector = AVP_Grouped(config['AVPCODE']['EUTRAN_VECTOR'],
                                           [avp_item_number, avp_rand, avp_xres, avp_kasme],
                                           config['VARIOUS']['VENDOR_ID'])

            logger.warn('excluded AUTN')

        elif config['EUTRAN_VECTOR']['_exclude_KASME']:

            avp_EUTRANVector = AVP_Grouped(config['AVPCODE']['EUTRAN_VECTOR'],
                                           [avp_item_number, avp_rand, avp_xres, avp_autn],
                                           config['VARIOUS']['VENDOR_ID'])

            logger.warn('excluded KASME')

        else:

            avp_EUTRANVector = AVP_Grouped(config['AVPCODE']['EUTRAN_VECTOR'],
                                           [avp_item_number, avp_rand, avp_xres, avp_autn, avp_kasme],
                                           config['VARIOUS']['VENDOR_ID'])

        avp_EUTRANVector.setMandatory(True)
        avp_EUTRANVector.setPrivate(False)

        avp_AuthenticationInfo = AVP_Grouped(config['AVPCODE']['AUTHENTCATION_INFO'],
                                             [avp_EUTRANVector],
                                             config['VARIOUS']['VENDOR_ID'])
        avp_AuthenticationInfo.setMandatory(True)
        avp_AuthenticationInfo.setPrivate(False)

        msg.append(avp_AuthenticationInfo)

        logger.info('total encoded length: %d', msg.encodeSize())

        msg.encode(p)

        #IP
        self.ip = IP(src=config['ADDRESS']['HOST_IP'])
        logger.info('ip: %s', self.ip)

        #SCTP
        self.sctp =SCTP(dport=3868,sport=3868)
        logger.info('sctp: %s', self.sctp)

        self.sctp.sport = config['ADDRESS']['DIAMETER_PORT']
        self.sctp.dport = config['ADDRESS']['DIAMETER_PORT']
        self.sctp.tag = config['SCTP_DATA']['tag']     #or None
        self.sctp.chksum = config['SCTP_DATA']['chksum']  #or None

        #SCTP Data Chunk
        self.sctp_data = SCTPChunkData(self.sctp)
        self.sctp_data.type = 0  #data chunk
        self.sctp_data.flags     = 0x0
        self.sctp_data.len       = msg.encodeSize()  #depending on payload
        self.sctp_data.proto_id  = config['PPID']['DIAMETER_PPID_46'] #diameter
        self.sctp_data.stream_id  = config['SCTP_DATA']['stream_id']
        self.sctp_data.stream_seq = config['SCTP_DATA']['stream_seq']

        self.sctp_data.data = p.get_buffer()

        #logger.info('the avps: %s', self.sctp_data.data)

        self.packet = self.ip / self.sctp / self.sctp_data
        (self.packet).show()

#TODO Nuke this as can 'malform' via json config.
    def buildMalformedPacket(self):

        #IP
        self.ip = IP(src="127.0.0.1")
        logger.info('ip: %s', self.ip)

        #SCTP
        self.sctp =SCTP(dport=3868,sport=3868)
        logger.info('sctp: %s', self.sctp)

        self.sctp.sport = 3868
        self.sctp.dport = 3868
        self.sctp.tag = 0x028e0a8b     #or None
        self.sctp.chksum = 0x028e0a8b  #or None

        #SCTP Data Chunk
        self.sctp_data = SCTPChunkData()
        self.sctp_data.type = 0  #data chunk
        self.sctp_data.flags     = 0x03
        self.sctp_data.len       = 392   #depending on payload
        self.sctp_data.proto_id  = 46  #diameter
        self.sctp_data.stream_id  = None
        self.sctp_data.stream_seq = 4

        #hex stream copied from wireshark
        bytes_to_test = '010001904000013e01000023227136522271365200000107400000514c4436765347534e4d4d4530312e6570632e6d6e633031342e6d63633930312e336770706e6574776f726b2e6f72673b313537313439303835393b313b322e323b39343538323539300000000000010c4000000c000007d100000108400000334c41427648535330312e6570632e6d6e633031342e6d63633930312e336770706e6574776f726b2e6f72670000000128400000296570632e6d6e633031342e6d63633930312e336770706e6574776f726b2e6f7267000000000001154000000c0000000100000104400000200000010a4000000c000028af000001024000000c0100002300000585c0000090000028af00000586c0000084000028af000005a7c000001c000028afccbf13a96d18954fd9081e2e591e3454000005a8c0000014000028af43f0de5aa79ce41a000005a9c000001c000028af06594354621c8000c881359dc46cf84c000005aac000002c000028af6417d38ce0fc4b44e7a1faa58e6360609271e4c2ceb96fc390cfed690779e2a0'

        self.sctp_data.data = RadioTap(codecs.decode(bytes_to_test, 'hex'))

        self.packet = self.ip/self.sctp/self.sctp_data

        (self.packet).show()

    def sendPacket(self):

        #dump=hexdump(self.packet)

        send(self.packet)
        logger.info('Packet sent')

if __name__ == '__main__':

    try:
        logger.info('Start' )

######packet.buildMalformedPacket()

        if config['MESSAGE_TRANSMIT']['SEND_MODE'] == "AIR" or config['MESSAGE_TRANSMIT']['SEND_MODE'] == "both":
            packet = SCTPPacket()
            packet.buildRequestPacket()
            packet.sendPacket()

        if config['MESSAGE_TRANSMIT']['SEND_MODE'] == "AIA" or config['MESSAGE_TRANSMIT']['SEND_MODE'] == "both":
            packet = SCTPPacket()
            packet.buildAnswerPacket()
            packet.sendPacket()

        logger.info('Finished ')
    except Exception as e:
        logging.exception("error message")

    exit(0)





