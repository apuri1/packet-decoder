#ifndef __UDPTX_H__
#define __UDPTX_H__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/types.h>       // For data types
#include <sys/socket.h>      // For socket(), connect(), send(), and recv()
#include <netdb.h>           // For gethostbyname()
#include <arpa/inet.h>       // For inet_addr()
#include <unistd.h>          // For close()
#include <netinet/in.h>      // For sockaddr_in

//Don't call bind in the client. random interface & port chosen by OS


class UdpTx
{
   public:

    UdpTx(std::string ipaddr);

    int32_t SendToRemote(uint8_t *buffer, int32_t len);

   private:

    int32_t sockfd, port, retVal;
    struct sockaddr_in server_address, destination_address;

    std::string m_ipaddr;

};

#endif