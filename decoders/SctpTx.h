#ifndef __SCTPTX_H__
#define __SCTPTX_H__

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
#include <fcntl.h>

#include <netinet/in.h>      // For sockaddr_in
#include <netinet/sctp.h>    // For sctp

//Don't call bind in the client. random interface & port chosen by OS


class SctpTx
{
   public:

    SctpTx(std::string ipaddr);

    int32_t SendToRemote(uint8_t *buffer, int32_t len);

   private:

    int32_t sockfd, port, retVal;

    struct sockaddr_in destination_address;

    struct sctp_initmsg   initmsg;
    struct sctp_event_subscribe events;

    std::string m_ipaddr;

};

#endif