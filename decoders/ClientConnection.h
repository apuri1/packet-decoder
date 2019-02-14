#ifndef __CLIENTCONNECTION_H__
#define __CLIENTCONNECTION_H__

#include <unistd.h>          // For close()
#include <fcntl.h>

#include <netinet/in.h>      // For sockaddr_in

#include <sys/socket.h>
#include <sys/types.h>       // For data types
#include <sys/socket.h>      // For socket(), connect(), send(), and recv()
#include <netdb.h>           // For gethostbyname()
#include <arpa/inet.h>       // For inet_addr()

#include <unistd.h>          // For close()
#include <fcntl.h>

#include <netinet/in.h>      // For sockaddr_in
#include <netinet/sctp.h>    // For sctp

class ClientConnection
{

   public:
      ClientConnection(){retVal = -1;}
      ClientConnection(std::string ipaddr, uint32_t port);

      //int32_t ConstructClient();

      int32_t CreateSocket(int32_t domain, int32_t type, int32_t protocol)
      {
          sockfd = socket(domain, type, protocol);

          if(sockfd < 0)
          {
             printf( "ERROR opening socket");
             return -1;
          }
      };

      int32_t SetSocketOptions(int32_t level, int32_t optname, const void *optval, int32_t optlen)
      {
           retVal = setsockopt(sockfd, level, optname, &optval, optlen);

            if(retVal < 0)
            {
                printf( "ERROR setting socket options \n");
                return retVal;
            }
       };

      virtual int32_t SendMessage(uint8_t *buffer, int32_t len) = 0;

   protected:

      int32_t sockfd, retVal;
      uint32_t m_port;

      struct sockaddr_in server_address, destination_address;

      std::string m_ipaddr;

};

#endif