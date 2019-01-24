#include "Config.h"

#include <fstream>
#include <sstream>

#undef MODULE_NAME
#define MODULE_NAME        "CONFIG"

Config *Config::m_instance = NULL;

Config::Config()
{
   printf( "\n Config Defaults\n");

   process_name          = "";
   mapping_type          = "";
   pcap_flag             = false;
   interface1            = "N/A";
   filter                = "";
   transmission_protocol = "";
}

Config *Config::Instance()
{
        if(m_instance == NULL)
        {
           m_instance = new Config();
        }

        return m_instance;
}

/**
 * Description fullConfig()
 * full configuration
 * Reads in the json parameters and calls setters to initialise parameters
 */

int Config::ReadConfig(std::string configFile)
{
    printf( "Config::fullConfig\n");
    Json::Value value;
    Json::Reader reader;

    std::ifstream in(configFile.c_str(), std::ifstream::binary);

    bool parsingSuccessful = reader.parse(in, value, false);

    if(!parsingSuccessful)
    {
        std::stringstream ss;

        ss << reader.getFormatedErrorMessages();
        printf( "Config::fullConfig() parsing error:  %s\n, using default or exiting!", ss.str().c_str());
        return -1;
    }
    else
    {
        printf( "Reading in config parameters\n");

        SetName(value["Name"].get("name", "default" ).asString());

        SetInternalMapping(value["Mapping"].get("mapping_type", "default" ).asString());
        SetDataExpirationTimeSecs(value["Mapping"].get("data_expiration_seconds", 259200 ).asUInt()); //72 hours

        SetInterface(value["Interfaces"].get("interface1", "default" ).asString());

        SetFilter(value["Filters"].get("filter", "default" ).asString());

        SetTransmissionProtocol(value["Transmission"].get("protocol", "default" ).asString());

        SetMode(value["Mode"].get("test", false ).asBool());

    }

   return 0;
}

void Config::SetName(std::string name)
{
     process_name = name;
}

void Config::SetInternalMapping(std::string mapping)
{
     mapping_type = mapping;
}

void Config::SetDataExpirationTimeSecs(uint32_t val)
{
     expiration_secs = val;
}

void Config::SetInterface(std::string interface)
{
     interface1 = interface;
}

void Config::SetFilter(std::string str)
{
     filter = str;
}

void Config::SetTransmissionProtocol(std::string tx)
{
     transmission_protocol = tx;
}

void Config::SetReadFromPcap(bool flag)
{
     pcap_flag = flag;
}

void Config::SetMode(bool flag)
{
     mode = flag;
}

void Config::PrintConfiguration()
{
     printf( "     \n***** CONFIGURATION*****\n");
     printf( "     Application         : %s\n", process_name.c_str());
     printf( "     Mapping to be used  : %s\n", mapping_type.c_str());
     printf( "     Data Expiration     : %d seconds\n", expiration_secs);
     printf( "     interface 1         : %s\n", interface1.c_str());
     printf( "     filter to apply     : '%s'\n", filter.c_str());
     printf( "     Read from pcap file : %s\n", (pcap_flag ? "true" : "false"));
     printf( "     Test Mode           : %s\n", (mode ? "true" : "false"));
     printf( "     \n***** COMPLETE*****\n");
}