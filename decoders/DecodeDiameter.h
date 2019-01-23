#ifndef DECODE_DIAMETER_H_
#define DECODE_DIAMETER_H_

#include <stdio.h>
#include <vector>
#include <string>

#include <algorithm>
#include <cstdint>

#include "DecodePacket.h"

#include "ContainerMultiIndex.h"

static const int kDIAMETER_REQUEST_ANSWER_COMMAND_CODE     = 318;
static const int kS6A_APPLICATION_ID                       = 16777251;
static const int kVENDOR_SPECIFIC_APPLICATION_ID           = 260;
static const int kAVP_CODE_DIAMETER_SESSION_ID             = 263;
static const int kAVP_CODE_ORIGIN_HOST                     = 264;
static const int kAVP_RESULT_CODE                          = 268;
static const int kAVP_AUTH_SESSION_STATE                   = 277;
static const int kAVP_USER_NAME                            = 1;   //IMSI
static const int kAVP_ORIGIN_REALM                         = 296;
static const int kAVP_DESTINATION_REALM                    = 283;
static const int kAVP_DESTINTAION_HOST                     = 293;
static const int kAVP_VISITED_PLMN_ID                      = 1407;
static const int kAVP_REQUESTED_EUTRAN_AUTHENTICATION_INFO = 1408;
static const int kAVP_NUMBER_OF_REQUESTED_VECTORS          = 1410;
static const int kAVP_IMMEDIATE_RESPONSE_PREFERRED         = 1412;
static const int kAVP_AUTHENTCATION_INFO                   = 1413;
static const int kAVP_EUTRAN_VECTOR                        = 1414;
static const int kAVP_CODE_RAND                            = 1447;
static const int kAVP_CODE_XRES                            = 1448;
static const int kAVP_CODE_AUTN                            = 1449;
static const int kAVP_CODE_KASME                           = 1450;
static const int kAVP_VENDOR_ID                            = 10415;
static const int kDIAMETER_PPID_46                         = 46;
static const int kDIAMETER_PPID_47                         = 47;
static const int kDIAMETER_PORT                            = 3868;  //IANA assigned

class DecodeDiameter : public DecodePacket
{
  public:
        DecodeDiameter(){};

        ~DecodeDiameter(){};

        void ProcessSCTPPayload(iphdr *iph,
                                struct sctp_datahdr *datah,
                                uint32_t chunk_length,
                                std::string packet_time_stamp);

  private:

        size_t DecodeAVPs(std::vector<uint8_t> & vec, struct S6A & s6a, int32_t index);

        size_t DecodeKeys(std::vector<uint8_t> & vec, struct S6A & s6a, int32_t index);

        bool ValidateAVPLength(int32_t avp_length);

        int32_t ProcessPadding(int32_t avp_length);

        int32_t HandleVendorFlag(std::vector<uint8_t> & vec, int & index );

        int32_t RetrieveByte(std::vector<uint8_t> & vec, uint8_t & byte, int32_t index);

        int32_t keys_index;
};
#endif
