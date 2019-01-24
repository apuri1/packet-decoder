#include "UdpTx.h"

//Don't call bind in the client. random interface & port chosen by OS

//Just instantiate on the stack


UdpTx::UdpTx(std::string ipaddr)
{
   m_ipaddr = ipaddr;
}

int32_t UdpTx::SendMessage(uint8_t *buffer, int32_t len)
{
    retVal = -1;


    printf( "Prepare sending  with size %d\n", len);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
       printf( "ERROR opening socket");
       return retVal;
    }

    memset((char *) &server_address, 0, sizeof(server_address));
    server_address.sin_family      = AF_INET;
    server_address.sin_port        = htons(0);
    server_address.sin_addr.s_addr = INADDR_ANY;


    if(bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        printf("bind failed\n");
        return 0;
    }

    memset((char *) &destination_address, 0, sizeof(destination_address));
    destination_address.sin_family      = AF_INET;
    destination_address.sin_port        = htons(1234);
    destination_address.sin_addr.s_addr = inet_addr("127.0.0.1");


     /*Send message to server*/
    retVal = sendto(sockfd,buffer,len,0,(struct sockaddr *)&destination_address,sizeof(destination_address));

    if(retVal < 0)
    {
       printf( "ERROR sending");  //retry?
    }
    else
    {
       printf( "sent OK");
    }

    close(sockfd);

    return retVal;
}




