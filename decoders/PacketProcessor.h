#ifndef __PACKET_PROCESSOR__
#define __PACKET_PROCESSOR__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sstream>
#include <pcap.h>
#include <pthread.h>

#include "PacketBuffer.h"
#include "DecodeDiameter.h"
#include "DecodeHTTP.h"
#include "DecodeMQTT.h"


#include <chrono>


class PacketProcessor
{
    public:

      PacketProcessor();
      ~PacketProcessor(){};

      uint32_t ProcessPacketHeaders(const struct pcap_pkthdr *header,
                                    const uint8_t *buffer,
                                    const uint32_t buffer_length,
                                    uint32_t link_layer_header_size);

      int32_t ProcessTransportLayer(iphdr *& iph,
                                    const struct pcap_pkthdr *header,
                                    const uint8_t *buffer,
                                    const uint32_t buffer_length,
                                    uint32_t link_layer_header_size);

       DecodeDiameter *diameter_decoder;
       DecodeHTTP     *http_decoder;
       DecodeMQTT     *mqtt_decoder;
       PacketBuffer *packet_buffer;

    private:

      iphdr* ProcessEthernetFrame(const uint8_t *buffer,
                                  uint32_t & link_layer_header_size,
                                  bool gre = false);

      std::string ExtractPacketTime(const struct pcap_pkthdr *header);

};

class PacketProcessorThread
{
    public:

      PacketProcessorThread();

      int32_t Activate(PacketBuffer *packet_buffer);

      static PacketProcessorThread *Instance();

      static void* ProcessorThread(void * ptr);

    private:

      static PacketProcessorThread *m_instance;

//TODO use particular thread throughout
      pthread_t packet_processor_thread;

      PacketProcessor *packet_processor_ptr;
};

#endif