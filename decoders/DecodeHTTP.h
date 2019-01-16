#ifndef DECODE_DIAMETER_H_
#define DECODE_DIAMETER_H_

#include <stdio.h>
#include <vector>
#include <string>

#include <algorithm>
#include <cstdint>

#include "DecodePacket.h"

#include "ContainerMultiIndex.h"


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
