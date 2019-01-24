#include "SctpTx.h"

//TODO, make this a seperatate thread.


SctpTx::SctpTx(std::string ipaddr)
{
   m_ipaddr = ipaddr;
}

int32_t SctpTx::SendMessage(uint8_t *buffer, int32_t len)
{
    retVal = -1;

    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if(sockfd < 0)
    {
        printf( "ERROR opening socket\n");
        return retVal;
    }

    int32_t flags;
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    events.sctp_association_event = 1;
    events.sctp_data_io_event = 1;

    retVal = setsockopt(sockfd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events));

    printf( "retVal %d\n", retVal);

    if(retVal < 0)
    {
        printf( "setsockopt SCTP_EVENTS \n");
        return retVal;
    }

    memset(&initmsg, 0, sizeof(struct sctp_initmsg));

    initmsg.sinit_num_ostreams = 5;
    initmsg.sinit_max_instreams = 5;
    initmsg.sinit_max_attempts = 5;

    retVal = setsockopt(sockfd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg));

    printf( "retVal %d\n", retVal);

    if(retVal < 0)
    {
        printf( "setsockopt SCTP_INITMSG \n");

        close(sockfd);

        return retVal;
    }

    memset(&destination_address, 0, sizeof(struct sockaddr_in));
    destination_address.sin_family      = AF_INET;
    destination_address.sin_port        = htons(1234);

    retVal = inet_pton(AF_INET, m_ipaddr.c_str(),&(destination_address.sin_addr));

    printf( "retVal %d\n", retVal);

    if(retVal < 0)
    {
        printf(  "Error converting IP address %s\n", m_ipaddr.c_str());
        return retVal;
    }

    printf( "Attempting connect to %s\n", m_ipaddr.c_str());

    retVal = connect(sockfd, (struct sockaddr *)&destination_address, sizeof(destination_address));

    printf( "retVal %d\n", retVal);

    if(retVal < 0)
    {
        printf( "Cannot connect to %s\n", m_ipaddr.c_str());

        close(sockfd);

        return retVal;
    }

    retVal = sctp_sendmsg(sockfd, (void *) buffer, (size_t) len, NULL, 0, 0, 0, 0, 0, 0);

    printf( "retVal %d\n", retVal);

    if(retVal == -1 )
    {
        printf( "Cannot send message \n");
    }
    else
    {
        printf("Successfully sent %d bytes data to server\n", retVal);
    }

    close(sockfd);

    return retVal;
}




