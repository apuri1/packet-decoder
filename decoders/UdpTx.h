#ifndef __UDPTX_H__
#define __UDPTX_H__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ClientConnection.h"

//Don't call bind in the client. random interface & port chosen by OS


class UdpTx : public ClientConnection
{
   public:

    UdpTx(std::string ipaddr);

    int32_t SendMessage(uint8_t *buffer, int32_t len);

   private:

    int32_t sockfd, port, retVal;
    struct sockaddr_in server_address, destination_address;

    std::string m_ipaddr;

};

#endif