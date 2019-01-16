#include "PcapReader.h"

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include "sctp.h"              //Provides declarations for stcp header
#include <netinet/ip.h>        //Provides declarations for ip header

#include "Config.h"

#undef MODULE_NAME
#define MODULE_NAME "PCAP READER"

PcapReader *PcapReader::m_instance = nullptr;

PcapReader *PcapReader::Instance()
{
    if(m_instance == nullptr)
    {
       printf( "Creating new instance of PcapReader\n");
       m_instance = new PcapReader();
    }

    return m_instance;
}

PcapReader::PcapReader()
{
   handle = nullptr;
}
void PcapReader::Activate(PacketBuffer *packet_buffer)
{
    m_packet_buffer      = packet_buffer;
}

int32_t PcapReader::ReadFile(std::string file)
{
   char error_buffer[PCAP_ERRBUF_SIZE];
   struct bpf_program fp;   // The compiled filter expression

   const char *protocol_filter = Config::Instance()->GetFilter().c_str();

   handle = pcap_open_offline(file.c_str(), error_buffer);

   if(handle == nullptr)
   {
      printf( "Can't open pcap file: %s\n", error_buffer);
      exit(0);
   }

   pcap_file_args *args = new pcap_file_args();

   args->packet_buffer    = m_packet_buffer;

   link_layer_header_type = pcap_datalink(handle);

   if(link_layer_header_type == kLINKTYPE_LINUX_SLL)
   {
      printf( "Using Linux cooked capture encapsulation (link layer header type %d)  \n", link_layer_header_type);

      args->link_layer_header_size = 16;
   }
   else if(link_layer_header_type == kLINKTYPE_ETHERNET)
   {
      printf( "Using ethernet (link layer header type %d)  \n", link_layer_header_type);

      args->link_layer_header_size = sizeof(struct ethhdr);
   }
   else
   {
      printf( "Can't determine link layer, exiting..\n");
      exit(0);
   }

   if(handle == nullptr)
   {
        printf( "Couldn't open file %s : %s\n" , file.c_str() , error_buffer);

        handle = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_NANO, error_buffer);

        if(handle == nullptr)
        {
           printf( "Couldn't open file %s at the second time of asking: %s\n" , file.c_str() , error_buffer);
           return -1;
        }
   }

//Apply filters

   if(pcap_compile(handle, &fp, protocol_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
   {
      printf( "Couldn't parse filter %s: %s\n", protocol_filter, pcap_geterr(handle));
      return -1;
   }
   if(pcap_setfilter(handle, &fp) == -1)
   {
      printf( "Couldn't install filter %s: %s\n", protocol_filter, pcap_geterr(handle));
      return -1;
   }


   int32_t ret_val = 0;

   if( (ret_val = pcap_loop(handle , -1 , process_pcap , (uint8_t*)args)) < 0 )
   {
      printf( "pcap_loop error: %d, %s\n", ret_val, pcap_geterr(handle));
      sleep(1);
   }

   return 0;
}

void process_pcap(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *buffer)
{
    pcap_file_args *pargs = (pcap_file_args *) args;

    packet_number++;

    printf("Packet Number %d\n", packet_number);

//Make a copy, as header & buffer are invalid after callback returns.
//
    BufferedPacket buffered_packet;

    buffered_packet.header = *header;

    buffered_packet.buffer = new uint8_t[header->caplen];

    buffered_packet.buffer_length = header->caplen;

    std::copy(buffer, buffer+header->caplen, buffered_packet.buffer);

    buffered_packet.link_layer_header_size = pargs->link_layer_header_size;

    pargs->packet_buffer->Buffer(buffered_packet);

}






