

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <cstdlib>
#include <fstream>

#include "Config.h"
#include "ContainerMultiIndex.h"
#include "PacketReceiver.h"
#include "PcapReader.h"
#include "PacketProcessor.h"
#include "PacketBuffer.h"

#include "Maint.h"

#undef MODULE_NAME
#define MODULE_NAME "PACKET DECODER"

void print_usage();

void print_usage()
{
     printf("Nope! Need arguments...\n");
     printf("Try:\n");
     printf("          ./PacketDecoder -c config.json\n");
     printf("or\n");
     printf("          ./PacketDecoder -c config.json -f somecapturefile.pcap\n");
}

int32_t main(int32_t argc, char *arg[])
{
    int32_t val;
    std::string config_file;
    std::string pcap_file;
    bool config_read = false;

    printf( "STARTING PacketDecoder\n");

    Config::Instance();

    while((val = getopt(argc, arg, "c:f")) != -1)
    {
       switch(val)
       {
          case 'c':
          {
             config_file = arg[2];

             printf( "Reading Configuration file %s \n", config_file.c_str());

             if(config_file.empty())
             {
                printf( "Configuration file not specified\n");
                print_usage();
                exit(0);
             }

             size_t pos = config_file.rfind('.', config_file.length());
             if(pos != std::string::npos)
             {
                std::string ext = config_file.substr(pos, config_file.length() - pos);

                if( ext != ".json")
                {
                  printf( "not a json configuration file, extension %s\n", ext.c_str());
                  print_usage();
                  exit(0);
                }
             }
             else
             {
                  printf( "Configuration file incorrect\n");
                  print_usage();
                  exit(0);
             }

             if(Config::Instance()->ReadConfig(config_file) != 0)
             {
                printf( "Configuration not completed\n");
                exit(0);
             }

             config_read = true;

             break;
          }
          case 'f':
          {
             if(!config_read)
             {
                printf( "Configuration file not specified\n");
                print_usage();
                exit(0);
             }

             pcap_file = arg[4];

             Config::Instance()->SetReadFromPcap(true);

             printf( "Reading from pcap %s \n", pcap_file.c_str());

             break;
          }
          default:
          {
             print_usage();

             break;
          }
       }
    }

    Config::Instance()->PrintConfiguration();

// Determine what container to use that shall store Subscriber related data to facilitate
//

    if(Config::Instance()->GetInternalMapping() == "MultiIndex")
    {
       ContainerMultiIndex::Instance();
    }
    else
    {
       printf( "No container configured.\n");
       exit(0);
    }



    PacketBuffer *packet_buffer = new PacketBuffer();

//This will process all layers of the ethernet frame
//
    if((PacketProcessorThread::Instance()->Activate(packet_buffer)) != 0)
    {
        exit(0);
    };

//Allow one to telnet in realtime and query Subscribers data
//
    Maint::Instance()->Activate();

    if(Config::Instance()->GetReadFromPcap())
    {
       printf( "Reading pcap \n");

        PcapReader::Instance()->Activate(packet_buffer);

        int ret = PcapReader::Instance()->ReadFile(pcap_file);

        if(ret == 0)
        {
           printf( "Done reading from pcap, size of buffer/num of packets read: %d \n", packet_buffer->GetBufferSize());
        }

        // Keep the process running here to allow access to the Maint port
    }
    else
    {
        printf( "Reading in real-time \n");

        // Assume for now that all packets are off of a single interface
        //

        printf( "Dedicating 1 live pcap thread for all traffic\n");

        if(PacketReceiver::Instance()->Activate(packet_buffer, Config::Instance()->GetInterface()) !=0)
        {
           printf( "exiting...");
              exit(0);
        }
    }

    for(;;)
    {
      sleep(1);
    }

    printf( "exiting...");
}








