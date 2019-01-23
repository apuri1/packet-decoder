#ifndef DECODE_HTTP_H_
#define DECODE_HTTP_H_

#include <stdio.h>
#include <vector>
#include <string>

#include <algorithm>
#include <cstdint>

#include "DecodePacket.h"

#include "ContainerMultiIndex.h"

static const int kHTTP_PORT                       = 80;
static const int kHTTPS_PORT                      = 443;

class DecodeHTTP : public DecodePacket
{
  public:
        DecodeHTTP(){};

        ~DecodeHTTP(){};

        void ProcessTCPPayload(std::vector<uint8_t> & payload,
                               uint32_t payload_length,      //TODO
                               std::string packet_time_stamp);

  private:

};
#endif
