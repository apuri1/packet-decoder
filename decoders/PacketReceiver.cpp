#include "PacketReceiver.h"

#include <netinet/if_ether.h> /* includes net/ethernet.h */

#undef MODULE_NAME
#define MODULE_NAME "PACKET RECEIVER"

PacketReceiver *PacketReceiver::m_instance = nullptr;

PacketReceiver *PacketReceiver::Instance()
{
    if(m_instance == nullptr)
    {
       printf( "Creating new instance of PacketReceiver\n");
       m_instance = new PacketReceiver();
    }

    return m_instance;
}

int32_t PacketReceiver::Activate(PacketBuffer *packet_buffer,
                                 std::string interface_to_sniff)
{
    int32_t err;

    this->diameter_decoder   = diameter_decoder;

    pcap_args *args = new pcap_args();

    args->packet_buffer = packet_buffer;

    args->interface_to_sniff = interface_to_sniff;

    pthread_attr_t thread_attr_packet_receiver;

    pthread_attr_init(&thread_attr_packet_receiver);

    pthread_attr_setdetachstate(&thread_attr_packet_receiver, PTHREAD_CREATE_DETACHED);

    err = pthread_create(&packet_receiver_thread,
                         &thread_attr_packet_receiver,
                         PacketReceiverThread,
                         (void *) args);
    if(err<0)
    {
      printf( "PacketReceiverThread NOT started\n");
      return -1;
    }
    else
    {
      printf( "PacketReceiverThread has started\n");
    }

    return 0;
}

void* PacketReceiver::PacketReceiverThread(void * packet_ptr)
{
    pcap_args *pkt_receiver = static_cast<pcap_args*>(packet_ptr);

    int32_t ret_val = 0;

    pcap_t *handle; //Handle of the device that shall be sniffed
    char errbuf[100];
    uint32_t link_layer_header_type;

    struct bpf_program fp;   // The compiled filter expression
    bpf_u_int32 mask;        // The netmask of our sniffing device
    bpf_u_int32 net;         // The IP of our sniffing device

    const char *protocol_filter = Config::Instance()->GetFilter().c_str();
    const char *devname = pkt_receiver->interface_to_sniff.c_str();

    if(pcap_lookupnet(devname, &net, &mask, errbuf) == -1)
    {
       printf( "Can't get netmask for device %s\n", devname);
       net = 0;
       mask = 0;
    }

//Open the device for sniffing
//
    printf( "Opening device %s for sniffing ... \n", devname);

    handle = pcap_open_live(devname , 65535, 1, 100, errbuf);

    if (handle == nullptr)
    {
        printf( "Couldn't open device %s : %s\n", devname, errbuf);
        return nullptr;
    }

//determine ethernet or linux cooked headers

    link_layer_header_type = pcap_datalink(handle);

    if(link_layer_header_type == kLINKTYPE_LINUX_SLL)
    {
       printf( "Using Linux cooked capture encapsulation (link layer header type %d)  \n", link_layer_header_type);

       pkt_receiver->link_layer_header_size = 16;
    }
    else if(link_layer_header_type == kLINKTYPE_ETHERNET)
    {
       printf( "Using ethernet (link layer header type %d)  \n", link_layer_header_type);

       pkt_receiver->link_layer_header_size = sizeof(struct ethhdr);
    }
    else
    {
       printf( "Can't determine link layer, exiting..\n");
       exit(0);
    }

//Apply filters

   if(pcap_compile(handle, &fp, protocol_filter, 0, net) == -1)
   {
      printf( "Couldn't parse filter %s: %s\n", protocol_filter, pcap_geterr(handle));
      return nullptr;
   }
   if(pcap_setfilter(handle, &fp) == -1)
   {
      printf( "Couldn't install filter %s: %s\n", protocol_filter, pcap_geterr(handle));
      return nullptr;
   }

   //Put the device in sniff loop
   for(;;)
   {
       if( (ret_val = pcap_loop(handle , -1 , process_packet , (uint8_t*)pkt_receiver)) < 0 )
       {
          printf( "pcap_loop error: %d, %s\n", ret_val, pcap_geterr(handle));
          sleep(1); //don't stress the CPU if continuous failures
       }
   }

    return nullptr;
}

void process_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *buffer)
{
    pcap_args *pargs = (pcap_args *) args;

//Make a copy, as header & buffer are invalid after callback returns.

    BufferedPacket buffered_packet;

    buffered_packet.header = *header;

    buffered_packet.buffer = new uint8_t[header->caplen];

    buffered_packet.buffer_length = header->caplen;

    std::copy(buffer, buffer+header->caplen, buffered_packet.buffer);

    buffered_packet.link_layer_header_size = pargs->link_layer_header_size;

    pargs->packet_buffer->Buffer(buffered_packet);

}





