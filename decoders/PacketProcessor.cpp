#include "PacketProcessor.h"
#include "PacketBuffer.h"
#include "Config.h"

PacketProcessorThread *PacketProcessorThread::m_instance = nullptr;


PacketProcessor::PacketProcessor()
{
// Instantiate a bunch of protocol decoders
//
    diameter_decoder = new DecodeDiameter();
}

PacketProcessorThread::PacketProcessorThread()
{
    packet_processor_ptr = new PacketProcessor();
}

PacketProcessorThread *PacketProcessorThread::Instance()
{
    if(m_instance == nullptr)
    {
       printf( "Creating new instance of PacketProcessorThread\n");
       m_instance = new PacketProcessorThread();
    }

    return m_instance;
}

int32_t PacketProcessorThread::Activate(PacketBuffer *packet_buffer)
{
    packet_processor_ptr->packet_buffer    = packet_buffer;

    pthread_attr_t thread_attr_packet_processor;

    pthread_attr_init(&thread_attr_packet_processor);

    pthread_attr_setdetachstate(&thread_attr_packet_processor, PTHREAD_CREATE_DETACHED);

    int32_t err = pthread_create(&packet_processor_thread,
                                 &thread_attr_packet_processor,
                                 PacketProcessorThread::ProcessorThread,
                                 (void *) packet_processor_ptr);
    if(err < 0)
    {
       printf( "ProcessorThread NOT started\n");
       return -1;
    }
    else
    {
       printf( "ProcessorThread has started\n");

    }

    return 0;
}

void* PacketProcessorThread::ProcessorThread(void *ptr)
{
     PacketProcessor *packet_processor = static_cast<PacketProcessor*>(ptr);

     for(;;)
     {
           printf( "checking for any packets to decode.....\n");

           std::unique_lock<std::mutex> guard(packet_processor->packet_buffer->circ_mutex);

           while(!packet_processor->packet_buffer->buffered)
           {
              packet_processor->packet_buffer->circ_condition.wait(guard);

              printf( "wait for PacketBuffer.....\n");
           }

           packet_processor->packet_buffer->buffered  = false;
           packet_processor->packet_buffer->processed  = true;

           if(packet_processor->packet_buffer->GetBufferSize()< 1)
           {
              printf( "nothing to process, notifying PacketBuffer\n");
              guard.unlock();
              packet_processor->packet_buffer->circ_condition.notify_all();
              continue;
           }

           BufferedPacket buf = packet_processor->packet_buffer->ProcessBuffer();

           printf( "something to process, notifying PacketBuffer\n");

           guard.unlock();

           packet_processor->packet_buffer->circ_condition.notify_all();

  //
  //    Measure performance from start of packet decoding to completion of container processing
  //
           auto start = std::chrono::system_clock::now();

           if(packet_processor->ProcessPacketHeaders(&buf.header, buf.buffer, buf.buffer_length, buf.link_layer_header_size) == 0)
           {
              printf( "Processed packet\n");
           }
           else
           {
              printf( "Discarded unknown packet\n");
           }

           auto end = std::chrono::system_clock::now();

           auto duration_microseconds   = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
           auto duration_milliseconds   = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

           printf( "%lld microseconds (%lld milliseconds)\n\n", duration_microseconds.count(), duration_milliseconds.count());
     }

     return nullptr;
}

uint32_t PacketProcessor::ProcessPacketHeaders(const struct pcap_pkthdr *header,
                                               const uint8_t *buffer,
                                               const uint32_t buffer_length,
                                               uint32_t link_layer_header_size)
{
    uint32_t ret_val             = 0;
    uint16_t iphdrlen;

    printf( "Processing packet.....\n");

    iphdr *iph = ProcessEthernetFrame(buffer, link_layer_header_size);

    ret_val = ProcessTransportLayer(iph, header, buffer, buffer_length, link_layer_header_size);

    if(buffer != nullptr)
    {
       printf( "Deleting \n");
       delete buffer;
    }

    return ret_val;
}

iphdr* PacketProcessor::ProcessEthernetFrame(const uint8_t *buffer,
                                             uint32_t & link_layer_header_size,
                                             bool gre)
{
    iphdr *iph = nullptr;
    uint32_t ether_type;

    struct ethhdr *eth = nullptr;

    if(gre)
    {
       eth = (struct ethhdr*)(buffer + link_layer_header_size);
    }
    else
    {
       eth = (struct ethhdr*)(buffer);
    }

    ether_type = ntohs(eth->h_proto);

// Some routers include VLAN headers in ethernet frames, take these into account
//
    if(ether_type == kLINKTYPE_EXTENDED_VLAN)
    {
       link_layer_header_size += 4;

       printf( "ethernet proto type includes vlan (%d), link layer size now %d\n", ether_type, link_layer_header_size);
    }

    iph = (struct iphdr*)(buffer + link_layer_header_size);

    return iph;
}

std::string PacketProcessor::ExtractPacketTime(const struct pcap_pkthdr *header)
{
     char timeBuffer[48] = {'\0'};
     struct tm *tm;
     struct tm tmr = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous

     tm = gmtime_r((time_t *)&(header->ts.tv_sec), &tmr);

     if(tm)
     {
        snprintf(timeBuffer,
                 sizeof(timeBuffer),
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 tm->tm_year+1900,
                 tm->tm_mon+1,
                 tm->tm_mday,
                 tm->tm_hour,
                 tm->tm_min,
                 tm->tm_sec);
      }

      std::string str(timeBuffer);
      return str;
}

int32_t PacketProcessor::ProcessTransportLayer(iphdr *& iph,
                                               const struct pcap_pkthdr *header,
                                               const uint8_t *buffer,
                                               const uint32_t buffer_length,
                                               uint32_t link_layer_header_size)
{
    printf( "Processing Transport Layer.....\n");
    uint32_t ret_val             = 0;
    char src_ipaddr[INET_ADDRSTRLEN], dst_ipaddr[INET_ADDRSTRLEN];
    std::string packet_time_stamp = ExtractPacketTime(header);

//SCTP variables
    struct sctphdr *sctph        = nullptr; //the common header
    struct sctp_datahdr *datah   = nullptr;
    uint16_t source_port, dest_port;
    int32_t ppid;
    struct sctp_chunkhdr *chunkh = nullptr; //type, flags, length
    uint32_t chunk_length        = 0;

//TCP variables
    struct tcphdr *tcph          = nullptr;
    uint16_t tcplen              = 0;
    uint16_t payload_length;
    uint8_t *payload_ptr         = nullptr;
    uint32_t ack_number;
    uint16_t urgen_flag;
    uint16_t ack_flag;
    uint16_t push_flag;
    uint16_t reset_flag;
    uint16_t sync_flag;
    uint16_t finish_flag;
    uint16_t window;

    uint8_t _checksum[10];
    uint32_t checksum;

    int32_t padding       = 0;

    uint16_t iphdrlen = iph->ihl*4;

    printf( "total length received %d\n", buffer_length);

    printf( "Packet time stamp %s\n", packet_time_stamp.c_str() );

    if(inet_ntop(AF_INET, &(iph->saddr), src_ipaddr, INET_ADDRSTRLEN) != nullptr)
    {
        printf( "Source addr %s \n", src_ipaddr);
    }
    else
    {
       printf( "Source addr error: %s  \n", strerror(errno));
    }


    if(inet_ntop(AF_INET, &(iph->daddr), dst_ipaddr, INET_ADDRSTRLEN) != nullptr)
    {
       printf( "Destination addr %s\n", dst_ipaddr);
    }
    else
    {
       printf( "Dest addr error: %s  \n", strerror(errno));
    }

    switch(iph->protocol) //Check the Protocol and do accordingly...
    {
        case kSCTP_PROTOCOL: //SCTP Protocol 0x84
        {
            printf( "handle SCTP packet \n");

            sctph = (struct sctphdr*)(buffer + iphdrlen + link_layer_header_size);

//For verification purposes when x-checking pcap files
            unsigned char _vtag[10];

            uint32_t vtag = ntohl(sctph->vtag);
            checksum = ntohl(sctph->checksum);

            _vtag[0] = vtag >> 24;
            _vtag[1] = vtag >> 16;
            _vtag[2] = vtag >> 8;
            _vtag[3] = vtag;

            _checksum[0] = checksum >> 24;
            _checksum[1] = checksum >> 16;
            _checksum[2] = checksum >> 8;
            _checksum[3] = checksum;

            printf(  " *SCTP:\n  *Header Source port %hu\n  *Destination port %hu\n  *Tag 0x%x%x%x%x\n  *Cksum 0x%x%x%x%x\n", ntohs(sctph->source),
                                                                                                                             ntohs(sctph->dest),
                                                                                                                             _vtag[0], _vtag[1], _vtag[2], _vtag[3],
                                                                                                                             _checksum[0], _checksum[1], _checksum[2], _checksum[3]);

            chunkh = (struct sctp_chunkhdr *)(buffer + sizeof(struct sctphdr) + iphdrlen + link_layer_header_size);

            if(chunkh->type == SCTP_CID_SACK)
            {
               chunk_length = ntohs(chunkh->length);

               printf( " *SCTP: Chunk Type (SACK) %d\n  *Flags %u\n  *Chunk Len %u\n", chunkh->type, chunkh->flags, chunk_length);

               printf( " *SCTP Chunk of type SACK, skip it\n");

               padding = chunk_length % 4;

               if(padding != 0)
               {
                  padding = 4 - padding;

                  printf( " Got padding %d\n", padding);

                  chunk_length = chunk_length + padding;
                }

                if((iphdrlen + chunk_length) < buffer_length)
                {
                   //Move along the length to get to the data

                    printf( "further bytes remain\n");
                    chunkh = (struct sctp_chunkhdr *)(buffer + sizeof(struct sctphdr) + iphdrlen + link_layer_header_size + chunk_length );
                }
                else
                {
                    printf( "finished, no further bytes \n");
                    //break;
                }
            }

            if(chunkh->type == SCTP_CID_DATA)
            {
               printf( " *SCTP: Chunk Type DATA \n");

               chunk_length = ntohs(chunkh->length);

               printf( " *SCTP: Chunk Type (DATA) %d\n  *Flags %u\n  *Chunk Len %u\n", chunkh->type, chunkh->flags, chunk_length);

               //Skip one byte to next
               datah = (struct sctp_datahdr *)(chunkh + 1);

               printf( " *SCTP Chunk: TSN %u\n  *Stream ID %hu\n  *Stream Sequence number %hu\n  *Payload ID %u\n", ntohl(datah->tsn),
                                                                                                                   ntohs(datah->stream),
                                                                                                                   ntohs(datah->ssn),
                                                                                                                   ntohl(datah->ppid));

               if(padding != 0)
               {
                  padding = 4 - padding;

                  printf( " Got padding %d\n", padding);

                  chunk_length = chunk_length + padding;
               }
            }
//TODO, review
            if(chunk_length  > 0)
            {
                if(sctph != nullptr && datah != nullptr)
                {
                   ppid        = ntohl(datah->ppid);
                   source_port = ntohs(sctph->source);
                   dest_port   = ntohs(sctph->dest);

                   printf( " *Got PPID of %d, source port %hu, destination port %hu\n", ppid, source_port, dest_port);

                   switch(ppid) //Check the Protocol and do accordingly...
                   {

                       case kDIAMETER_PPID_46:
                       case kDIAMETER_PPID_47:
                       {
                            printf( " *Got PPID %hu for DIAMETER\n", ppid);
                            diameter_decoder->ProcessSCTPPayload(iph, datah, chunk_length, packet_time_stamp);
                            break;
                       }
                       case kPPID_UNSPECIFIED:
                       {
                            if(source_port == kDIAMETER_PORT
                               || dest_port == kDIAMETER_PORT)
                            {
                               printf( " *Got port assigned for DIAMETER\n");
                               diameter_decoder->ProcessSCTPPayload(iph, datah, chunk_length, packet_time_stamp);
                            }

                            break;
                       }
                       default: //not interested
                       {
                            printf( " Skip PPID %hu\n", ppid);
                            break;
                       }
                    }
               }
               else
               {
                  ret_val = chunk_length;
               }
            }

            break;
        }
        case kTCP_PROTOCOL:
        {
             printf( "handle TCP packet \n");

             tcph = (struct tcphdr*)(buffer + iphdrlen + link_layer_header_size);

             printf(  " *TCP:\n  *Header Source port %hu\n  *Destination port %hu\n ", ntohs(tcph->source),
                                                                                       ntohs(tcph->dest));

             uint8_t _seqno[10];

             uint32_t seqno = ntohl(tcph->seq);

             _seqno[0] = seqno >> 24;
             _seqno[1] = seqno >> 16;
             _seqno[2] = seqno >> 8;
             _seqno[3] = seqno;

             printf("sequence number: %u (bytes: %x%x%x%x)\n", seqno, _seqno[0],_seqno[1],_seqno[2],_seqno[3]);

             ack_number = ntohl(tcph->ack_seq);

             printf("acknowledge number %u \n", ack_number);

             tcplen = tcph->doff*4;

             printf("TCP header length %d\n", tcplen);

             urgen_flag  = tcph->urg;
             printf("Urgent Flag: %u\n", urgen_flag);

             ack_flag    = tcph->ack;
             printf("Acknowledgement Flag: %u\n", ack_flag);

             push_flag   = tcph->psh;
             printf("Push Flag: %u\n", push_flag);

             reset_flag  = tcph->rst;
             printf("Reset Flag: %u\n", reset_flag);

             sync_flag   = tcph->syn;
             printf("Synchronise Flag: %u\n", sync_flag);

             finish_flag = tcph->fin;
             printf("Finish Flag: %u\n", finish_flag);

             window = tcph->window;
             printf("Window: %u\n", window);

             payload_length = buffer_length-(link_layer_header_size+iphdrlen+tcplen);

             printf("Calculated TCP payload length %d (buffer length %d - (link layer %d +ip header %d + tcp length %d)) \n", payload_length,
                                                                                                                              buffer_length,
                                                                                                                              link_layer_header_size,
                                                                                                                              iphdrlen,
                                                                                                                              tcplen);

             payload_ptr = (uint8_t *)(buffer + tcplen + iphdrlen + link_layer_header_size);

             std::vector<uint8_t> payload(&payload_ptr[0], &payload_ptr[payload_length]);

             printf("printing bytes ");

             for(const auto& item: payload)
             {
                printf("%x ", item);
             }

             printf("\n");

             //TODO, need to analyse bytes and send to dedicated decoders

             break;
        }

//TODO
/*
        case kGRE_PROTOCOL: //GRE Protocol 0x2f
        {
             printf( "handle ERSPAN encapsulation \n");

             // take into account the Ethernet and IP within GRE

             link_layer_header_size += sizeof(struct ethhdr) + iphdrlen + 4;

             iph = ProcessEthernetFrame(buffer, link_layer_header_size, true);

             // Now handle SCTP.
             // Note, recursive function, as need to go through next transport layer of
             // TODO  if the packet is malformed and the stars align, this could keep going deep and seg fault..
             // option - update makefile to use:
             //      -foptimize-sibling-calls

             chunk_length = ProcessTransportLayer(iph, sctph, datah, header, buffer, buffer_length, link_layer_header_size);

             break;
        }
*/
        case kUDP_PROTOCOL:
        {
            printf( " UDP packet \n");
            break;
        }
        default: //not interested
        {
            printf( " Unknown fro now - %d \n", iph->protocol);
            break;
        }
    }

    return ret_val;
}