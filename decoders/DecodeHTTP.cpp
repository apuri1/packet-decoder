

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

#include "DecodeHTTP.h"
#include "Config.h"

//#include <curl/curl.h>

#undef MODULE_NAME
#define MODULE_NAME "DECODE DIAMETER"


void DecodeHTTP::ProcessTCPPayload(std::vector<uint8_t> & payload,
                                   uint32_t payload_length,      //TODO
                                   std::string packet_time_stamp)
{


}
