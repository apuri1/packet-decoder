#ifndef __PACKET_BUFFER__
#define __PACKET_BUFFER__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sstream>
#include <pcap.h>

#include <boost/circular_buffer.hpp>

#include <mutex>
#include <condition_variable>


const uint32_t kPACKET_CIRCULAR_BUFFER_SIZE = 10000000; // upto 10 million buffered packets


//TODO
// The circular_buffer should not be used for storing pointers to dynamically allocated objects.
// When a circular buffer becomes full, further insertion will overwrite the stored pointers - resulting in a memory leak.
// One recommend alternative is the use of smart pointers, for example Boost Smart pointers.
//
struct BufferedPacket
{
    //TODO consider smart pointer, alleviate mem management if exception occurs before delete
    struct pcap_pkthdr header;
    uint8_t *buffer;
    uint32_t buffer_length;
    uint32_t link_layer_header_size;


    BufferedPacket()
    {
       buffer = nullptr;
    }
};

class PacketBuffer
{
    public:

      PacketBuffer();

      boost::circular_buffer<BufferedPacket> circular_packet_buffer;

      void Buffer(BufferedPacket & packet);

      BufferedPacket ProcessBuffer();

      size_t GetBufferSize();

       std::mutex circ_mutex;
       std::condition_variable circ_condition;

       bool buffered, processed;

    private:


};

#endif