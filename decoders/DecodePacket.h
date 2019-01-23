#ifndef __DECODE_PACKET__
#define __DECODE_PACKET__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include "sctp.h"              //Provides declarations for sctp header
#include "tcp.h"
#include <netinet/ip.h>        //Provides declarations for ip header

#include <sstream>

//Base class to fork any type of protocol decoder

class DecodePacket
{
   public:

    DecodePacket();


    virtual void ProcessSCTPPayload(iphdr *iph,
                                    struct sctp_datahdr *datah,
                                    uint32_t chunk_length,
                                    std::string packet_time_stamp){};


    virtual void ProcessTCPPayload(std::vector<uint8_t> & payload,
                                   uint32_t payload_length,      //TODO
                                   std::string packet_time_stamp){};

    std::string GetCurrentTime();
};

#endif