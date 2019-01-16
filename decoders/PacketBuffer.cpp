#include "PacketBuffer.h"

PacketBuffer::PacketBuffer()
{
    circular_packet_buffer.set_capacity(kPACKET_CIRCULAR_BUFFER_SIZE);

    buffered     = false;
    processed    = true;
}

void PacketBuffer::Buffer(BufferedPacket & packet)
{
     std::unique_lock<std::mutex> guard(circ_mutex);

     while(!processed)
     {
        circ_condition.wait(guard);

        printf( "wait for PacketProcessor.....\n");
     }

     processed = false;

     circular_packet_buffer.push_back(packet);

     printf( "buffered..., size now :%d\n", GetBufferSize());

     buffered   = true;

     printf( "notifying PacketProcessor\n");

     guard.unlock();

     circ_condition.notify_all();
}

BufferedPacket PacketBuffer::ProcessBuffer()
{
     BufferedPacket buf;

     buf = circular_packet_buffer.front(); //gives reference to element at front

     circular_packet_buffer.pop_front();

     return buf;
}

size_t PacketBuffer::GetBufferSize()
{
    return circular_packet_buffer.size();
}