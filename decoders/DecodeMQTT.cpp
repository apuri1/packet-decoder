

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
     //First get the Control Packet Type
     // first nibble = high nibble
     control_packet_type = (payload[0] >> 4) & 0x0F;

     printf("Got Control Packet Type %d\n", control_packet_type);

}
