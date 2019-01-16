#ifndef __PCAP_READER__
#define __PCAP_READER__

#include <stdio.h>
#include <cstdlib>
#include <cstring>

#include <pcap.h>

#include "PacketBuffer.h"

static int packet_number = 0;

struct pcap_file_args
{
    uint32_t link_layer_header_size;
    PacketBuffer *packet_buffer;
};

void process_pcap(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

class PcapReader
{
   public:
    PcapReader();
    ~PcapReader(){};

    static PcapReader *Instance();

    void Activate(PacketBuffer *packet_buffer);

    int32_t ReadFile(std::string file);

   private:

    static PcapReader *m_instance;

    PacketBuffer *m_packet_buffer;

    pcap_t *handle; //Handle of the device that shall be sniffed

    int32_t link_layer_header_type;
};

#endif