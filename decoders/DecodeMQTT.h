#ifndef DECODE_MQTT_H_
#define DECODE_MQTT_H_

#include <stdio.h>
#include <vector>
#include <string>

#include <algorithm>
#include <cstdint>

#include "DecodePacket.h"

#include "ContainerMultiIndex.h"

static const int kMQTT_PORT                       = 1883;
static const int kMQTT_SSL_PORT                   = 8883;

static const int kMQTT_CONTROL_PACKET_CONNECT     = 1;
static const int kMQTT_CONTROL_PACKET_CONNACK     = 2;
static const int kMQTT_CONTROL_PACKET_PUBLISH     = 3;
static const int kMQTT_CONTROL_PACKET_PUBACK      = 4;
static const int kMQTT_CONTROL_PACKET_PUBREC      = 5;
static const int kMQTT_CONTROL_PACKET_PUBREL      = 6;
static const int kMQTT_CONTROL_PACKET_PUBCOMP     = 7;
static const int kMQTT_CONTROL_PACKET_SUBSCRIBE   = 8;
static const int kMQTT_CONTROL_PACKET_SUBACK      = 9;
static const int kMQTT_CONTROL_PACKET_UNSUBSCRIBE = 10;
static const int kMQTT_CONTROL_PACKET_UNSUBACK    = 11;
static const int kMQTT_CONTROL_PACKET_PINGREQ     = 12;
static const int kMQTT_CONTROL_PACKET_RESP        = 13;
static const int kMQTT_CONTROL_PACKET_DISCONNECT  = 14;
static const int kMQTT_CONTROL_PACKET_AUTH        = 15;

class DecodeMQTT : public DecodePacket
{
  public:
        DecodeMQTT(){};

        ~DecodeMQTT(){};

        void ProcessTCPPayload(std::vector<uint8_t> & payload,
                               uint32_t payload_length,      //TODO
                               std::string packet_time_stamp);

  private:

};
#endif
