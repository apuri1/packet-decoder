#ifndef __SCTPTX_H__
#define __SCTPTX_H__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ClientConnection.h"

//Don't call bind in the client. random interface & port chosen by OS


class SctpTx : public ClientConnection
{
   public:

    SctpTx(std::string ipaddr);

    int32_t SendMessage(uint8_t *buffer, int32_t len);

   private:

    int32_t sockfd, port, retVal;

    struct sockaddr_in destination_address;

    struct sctp_initmsg   initmsg;
    struct sctp_event_subscribe events;

    std::string m_ipaddr;

};

#endif