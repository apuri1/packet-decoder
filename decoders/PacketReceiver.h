#ifndef __PACKET_RECEIVER__
#define __PACKET_RECEIVER__

#include <stdio.h>
#include <cstdlib>
#include <cstring>

#include <pthread.h>
#include "DecodeDiameter.h"
#include "PacketBuffer.h"

struct pcap_args
{
    uint32_t link_layer_header_size;
    PacketBuffer *packet_buffer;
    std::string interface_to_sniff;
};

void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

class PacketReceiver
{
   public:
    PacketReceiver(){};
    ~PacketReceiver(){};

    int32_t PacketReceiverThread(pcap_args *args);

   private:

};

#endif