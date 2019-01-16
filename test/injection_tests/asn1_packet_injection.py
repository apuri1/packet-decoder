import logging
from scapy.all import *
import json

with open('config.json', 'r') as f:
    config = json.load(f)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# create a file handler
handler = logging.FileHandler('AP.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

class SCTPPacket():

    def __init__(self):

        logger.info('initialised')

    def buildPacket(self):

        #IP
        self.ip = IP(src="127.0.0.1")
        logger.info('ip: %s', self.ip)

        #SCTP
        self.sctp =SCTP(dport=36412,sport=36412)
        logger.info('sctp: %s', self.sctp)

        self.sctp.sport = 36412
        self.sctp.dport = 36412
        self.sctp.tag = 0x028e0a8b     #or None
        self.sctp.chksum = 0x028e0a8b  #or None

        #SCTP Data Chunk
        self.sctp_data = SCTPChunkData()
        self.sctp_data.type = 0  #data chunk
        self.sctp_data.flags     = 0x0
        self.sctp_data.len       = 286   #depending on payload
        self.sctp_data.proto_id  = 18  # s1ap
        self.sctp_data.stream_id  = None
        self.sctp_data.stream_seq = 4
        #self.sctp_data.data = '000900810900000800000005c0060598130008000200130042000a1811e1a3006008f0d18000180080aa0000340080a44500093d0f800a2004411b1f0a3280942753e9cea202ccbfb8ff8dd771f58c4cbf293d9739ce113f9a3ead060ebd85eb2154a07b1aea5b6db8771ced53785c79e07e5f40456a087b2a14cdbb82362214a7bc23e88bc225c1827f0bb62faa726d8d60b3d69d1779f7a9c0869fc191a2a215f0d0e1083d4df07f0ca7cb56cfc324773d9aa4de0f415750ac2e36149bf3e6df83279eed61d3c979a305f62f7cb90801d43dfa006b000518000c000000490020b83ded13344db159d77caaf21057446bcda89c44e6cc18176448e3112fbcbba1002940040009f141006a400100'

        #asn1_obj = ASN1_Object(ASN1_Codecs.PER)
        #asn1_str = ASN1_STRING(asn1_obj)

        logger.info('Reading in from file %s', config['S1AP']['RawFilesPath'])

        infile = open(config['S1AP']['RawFilesPath'], 'rb')

        try:

            self.sctp_data.data = infile.read()

        finally:

            infile.close()

        self.packet = (self.ip/self.sctp/self.sctp_data)

        (self.packet).show()

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
        self.sctp_data.flags     = 0x0
        self.sctp_data.len       = 392   #depending on payload
        self.sctp_data.proto_id  = 18  # s1ap
        self.sctp_data.stream_id  = None
        self.sctp_data.stream_seq = 4
        self.sctp_data.data = 0x01234


        #asn1_obj = ASN1_Object(ASN1_Codecs.PER)
        #asn1_str = ASN1_STRING(asn1_obj)

        self.packet = (self.ip/self.sctp/self.sctp_data)

        (self.packet).show()

    def sendPacket(self):

        #dump=hexdump(self.packet)

        send(self.packet)

def main():

    try:
        logger.info('Start' )
        packet = SCTPPacket()
        #packet.buildMalformedPacket()
        packet.buildPacket()
        packet.sendPacket()
        logger.info('Finished ')
    except Exception as e:
        logging.exception("error message")

    exit(0)

main()




