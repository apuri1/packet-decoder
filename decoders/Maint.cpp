#include "Maint.h"

Maint::Maint()
{
    printf( "Maint activated\n");
}


void Maint::TcpListener()
{
    printf( "Maint TcpListener running\n");

    struct pollfd fds[1]; // Just the one incoming connection at any given time from the gnd AMS

    int32_t ret_value_poll;

    int32_t listen_sock = -1;

    //TODO
    std::string ip_address = "127.0.0.1";
    int32_t port = 8020;

    memset(fds, 0, sizeof(fds));

    while(1)
    {
        if(listen_sock < 0)
        {
            listen_sock = OpenTcpListener(ip_address.c_str(), port);

            if(listen_sock < 0)
            {
                printf( "sock open failed\n");
                sleep(1);
            }
            else
            {
                printf( "listening on %s:%d with sock=%d\n", ip_address.c_str(), port, listen_sock);

                fds[0].fd = listen_sock;
                fds[0].events = POLLIN;
            }
        }
        else
        {
            printf( "Waiting on poll()...\n");

            ret_value_poll = poll(fds, 1, -1);

            if(ret_value_poll < 0)
            {
               printf( "poll() failed %s\n", strerror(errno));

               close(listen_sock);

               listen_sock = -1;
            }
            else if(ret_value_poll == 0)
            {
               //poll() timed out
            }
            else
            {
               AcceptConnection(listen_sock);
            }
        }
    }

    /* listener socket will stay open accepting connections until application exits */
}

int32_t Maint::OpenTcpListener(const char *ip_addr, int32_t port)
{
        struct sockaddr_in local_sock;
        int32_t option = 1;
        int32_t sockfd =-1;

        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sockfd < 0)
        {
            return -1;
        }

        /* Bind to the local port */
        memset(&local_sock, 0, sizeof(local_sock));
        local_sock.sin_family = AF_INET;
        local_sock.sin_port = htons(port);

        if(inet_pton(AF_INET, ip_addr, &local_sock.sin_addr) <= 0)
        {
            printf( "Could not convert %s into network address structure, %s\n", ip_addr, strerror(errno));
            close(sockfd);
            sockfd = -1;
        }

        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                                (void*)&option, sizeof(option)) != 0)
        {
            printf( "Could not set socket options, %s\n", strerror(errno));
            close(sockfd);
            sockfd = -1;
        }

        fcntl(sockfd, F_SETFL, O_NONBLOCK);

        if(::bind(sockfd, (struct sockaddr *)&local_sock, sizeof(local_sock)) < 0)
        {
            printf( "Could not bind arguments, %s\n", strerror(errno));
            close(sockfd);
            sockfd = -1;
        }

        if(listen(sockfd, 5) < 0)
        {
            printf( "Could not create a listening socket, %s\n", strerror(errno));
            close(sockfd);
            sockfd = -1;
        }

        return sockfd;
}

void Maint::AcceptConnection(int32_t listen_sock)
{
        int32_t port;
        int32_t sockfd = -1;
        char ipaddr[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        uint32_t sockaddr_len = sizeof(struct sockaddr_in);

        char read_buffer[4096];
        int32_t buff_size = 0;
        int32_t ret_write;
        std::string resp;

        sockfd = accept(listen_sock, (struct sockaddr *)&addr, &sockaddr_len);

        if(sockfd < 0)
        {
           printf( "Accept failed %s \n",strerror(errno));
           return;
        }

        port = ntohs (addr.sin_port);
        inet_ntop(AF_INET, &addr.sin_addr, ipaddr, INET_ADDRSTRLEN);

        printf( "Accepted connection from %s:%d sock=%d\n", ipaddr, port, sockfd);

        if(Config::Instance()->GetInternalMapping() == "MultiIndex")
        {
           resp = MultiIndexMenu();
        }

        if((ret_write = write(sockfd, resp.c_str(), strlen(resp.c_str())))<0)
        {
            printf( "Error writing to fd: %d\n", sockfd);
        }

        memset((char *)read_buffer, 0, buff_size);

        while((buff_size = read(sockfd, read_buffer, sizeof(read_buffer)))>0)
        {
            read_buffer[buff_size] = '\0';

            std::string evt(read_buffer);

            printf( "Received a message of size %d, processing selection: %s\n", buff_size, evt.c_str());

            if(Config::Instance()->GetInternalMapping() == "MultiIndex")
            {
               resp = ProcessMultiIndexRequest(evt);
            }

            if((ret_write = write(sockfd, resp.c_str(), strlen(resp.c_str())))<0)
            {
                printf( "Error writing to fd: %d\n", sockfd);
                close(sockfd);
                printf( "socket %d closed\n", sockfd);
            }
            else
            {
                if(resp == "bye!\n")
                {
                   close(sockfd);
                   printf( "socket %d closed\n", sockfd);
                }
            }

            memset((char *)read_buffer, 0, buff_size);
            buff_size = 0;
        }

        close(sockfd);
        printf( "socket %d closed\n", sockfd);

        return;
}


std::string Maint::ProcessMultiIndexRequest(std::string selection)
{
    uint32_t selection_val = -1;

    std::string ret_string, resp;

    StripNonAscii dross;

    try
    {
       selection.erase(remove_if(selection.begin(),selection.end(), dross), selection.end());
    }
    catch(const std::out_of_range& e)
    {
       printf( "can't format to ascii: %s\n", selection.c_str());

       ret_string = "\nERROR, select an option again\n";

       return ret_string;
    }

    if(strlen(selection.c_str()) == 15 )
    {
       printf( "check if valid IMSI: %s\n", selection.c_str());

       if(std::all_of(selection.begin(), selection.end(), ::isdigit))
       {
          printf( "Valid IMSI, processing\n");

          ret_string = ContainerMultiIndex::Instance()->ShowSubscriberInfo(selection);
       }
    }
    else
    {
        try
        {
           selection_val =  std::stoi(selection);
        }
        catch(...)
        {
            printf( "conversion of %s failed\n", selection.c_str());

            ret_string = "\nERROR, select an option again\n";
        }

        switch(selection_val)
        {
            case 1:
            {
                ret_string = ContainerMultiIndex::Instance()->PrintImsiIndex();

                break;
            }
            case 2:
            {
                ret_string = ContainerMultiIndex::Instance()->PrintSessionIndex();
                break;
            }
            case 3:
            {
                ret_string = ContainerMultiIndex::Instance()->PrintIpaddrIndex();
                break;
            }
            case 4:
            {
                ret_string = "Enter IMSI:\n";
                break;
            }
            case 5:
            {
                ret_string = ContainerMultiIndex::Instance()->LogTimeElapsed();
                break;
            }
            case 6:
            {
                ContainerMultiIndex::Instance()->EraseAll(); //TODO

                ret_string = "Done, check log file\n";
                break;
            }
            case 0:
            {
                ret_string = "bye!\n";
                break;
            }
            default:
            {
                ret_string = "\nERROR, select an option again\n";
                break;
            }
        }
    }

    return ret_string;
}


std::string Maint::MultiIndexMenu()
{
    std::stringstream ss;

    ss << "\n";
    ss << "*********MultiIndex Menu*****************\n";
    ss << "Select one of the following options:\n\n";
    ss << "1. Display all IMSI mappings \n";
    ss << "2. Display all Session ID mappings\n";
    ss << "3. Display all IP Address mappings\n";
    ss << "4. Find Subscriber Info using IMSI\n";
    ss << "5. Log handling of time\n";
    ss << "6. Remove old subs\n";
    ss << "\n";
    ss << "0. Exit\n";

    return ss.str();
}

