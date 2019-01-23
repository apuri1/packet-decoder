#ifndef __MAINT_H__
#define __MAINT_H__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cctype>
#include <sstream>
#include <algorithm>
#include <pthread.h>
#include <poll.h>

#include "ContainerMultiIndex.h"

#include "Config.h"

class Maint
{
  public:

    Maint();

    static Maint *Instance();

    int32_t Activate();

    static void* TcpListener(void *data);
    pthread_t TcpListenerThread;

    int32_t OpenTcpListener(const char *ip_addr, int32_t port);
    void AcceptConnection(int32_t listen_sock);

  private:

    static Maint *m_instance;

    std::string ProcessMultiIndexRequest(std::string selection);

    std::string MultiIndexMenu();

   struct StripNonAscii
   {
     bool operator()(int8_t c)
     {
       return !(c>=48 && c <58);
     };
   };
};

#endif