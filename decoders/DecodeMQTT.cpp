

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <cstdlib>
#include <fstream>

#include "DecodeMQTT.h"
#include "Config.h"

//#include <curl/curl.h>

#undef MODULE_NAME
#define MODULE_NAME "DECODE MQTT"


void DecodeMQTT::ProcessTCPPayload(std::vector<uint8_t> & payload,
                                   uint32_t payload_length,      //TODO
                                   std::string packet_time_stamp)
{
     int32_t control_packet_type;
     uint32_t msg_len;

     // First get the Control Packet Type from the Header Flags
     // first nibble = high nibble = control packet type value
     control_packet_type = (payload[0] >> 4) & 0x0F;

     printf("Got Control Packet Type %d\n", control_packet_type);

     //DUP, QoS & RETAIN flags in second nibble of the first byte

     int32_t bit_mask;

     //print the bit settings, non-zero means set

     for(int32_t x=0; x<4; x++)
     {
          bit_mask = payload[0] & (1 << x);
          printf("%dth bit setting = %d\n", x, bit_mask);
     }

     //next byte is the Remaining length: Data in the variable header  the payload

     msg_len = uint32_t(payload[1]);

     printf("Msg Len: %d\n", msg_len);
}
