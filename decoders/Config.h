#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdio.h>
#include <string>
#include "json.h"

#define  kLINKTYPE_LINUX_SLL        113
#define  kLINKTYPE_ETHERNET           1
#define  kLINKTYPE_EXTENDED_VLAN 0x8100

static const int kSCTP_PROTOCOL                   = 132;
static const int kTCP_PROTOCOL                    = 6;
static const int kUDP_PROTOCOL                    = 17;
static const int kGRE_PROTOCOL                    = 47;

static const int kPPID_UNSPECIFIED                = 0;

const char* const kERROR = "ERROR";

//This struct is for Map & Multiindex containers:

struct DiameterData
{
       // The following are the indexes(keys) in the MultiIndex
       //  Note: imsi & session_id are always unique, and modified when update occurs.

       std::string imsi;
       std::string session_id;

       std::string modified_datetime;    //Use this as a key to remove old entries
       std::string modified_date;

       // Following are the values accompanying the indexes(keys).
       std::vector<std::tuple<std::string, std::string> > E_UTRAN_Vectors;
       uint32_t authentication_type; // 0- request, 1 answer, 2- don't know //TBD
       std::string air_time_stamp;
       std::string aia_time_stamp;


//Need the following functors to be able to call modify & modify_key)
//
       struct update_session_id
       {
             std::string id;
             update_session_id( std::string _id):id(_id) {}
             void operator()(DiameterData & data)
             {
                  data.session_id = id;
             }
       };

       struct update_eutran_vectors
       {
             std::vector<std::tuple<std::string, std::string> > keys;
             update_eutran_vectors(std::vector<std::tuple<std::string, std::string> > & _keys)
             {
                 keys.reserve(_keys.size());
                 std::copy(_keys.begin(), _keys.end(), back_inserter(keys));
             }

             void operator()(DiameterData & data)
             {
                  data.E_UTRAN_Vectors.swap(keys);
             }
       };

       struct update_air_time_stamp
       {
             std::string air_time;
             update_air_time_stamp( std::string _air_time):air_time(_air_time) {}
             void operator()(DiameterData & data)
             {
                  data.air_time_stamp = air_time;
             }
       };

       struct update_aia_time_stamp
       {
             std::string aia_time;
             update_aia_time_stamp( std::string _aia_time):aia_time(_aia_time) {}
             void operator()(DiameterData & data)
             {
                  data.aia_time_stamp = aia_time;
             }
       };

       struct update_modified_datetime
       {
             std::string modified_datetime;
             update_modified_datetime( std::string _modified_datetime):modified_datetime(_modified_datetime) {}
             void operator()(DiameterData & data)
             {
                  data.modified_datetime = modified_datetime;
             }
       };

       struct update_modified_date
       {
             std::string modified_date;
             update_modified_date( std::string _modified_date):modified_date(_modified_date) {}
             void operator()(DiameterData & data)
             {
                  data.modified_date = modified_date;
             }
       };
};

struct authentication_information_request
{
       std::string user_name;
       std::string plmn;
       uint32_t num_of_requested_vectors;
};

struct authentication_information_answer
{
       uint32_t result_code;
       std::vector<std::tuple<std::string, std::string> > E_UTRAN_Vectors; //TODO
};

struct S6A
{
       std::string session_id; //Session-Id MUST be globally and eternally unique
       std::string origin_host;
       std::string origin_realm;
       std::string dest_realm;
       uint32_t authentication_type; // 0- request, 1 answer, 2- don't know
       authentication_information_request air;
       authentication_information_answer aia;
       std::string server_time_stamp;
       std::string packet_time_stamp;

       S6A()
       {
          session_id ="";
       }
};

class Config
{
  public:
        Config();

        ~Config() {};

        static Config *Instance();

        int ReadConfig(std::string configFile);

        void SetName(std::string name);
        std::string GetName(){return process_name;}

        void SetInternalMapping(std::string mapping);
        std::string GetInternalMapping() {return mapping_type;}

        void SetDataExpirationTimeSecs(uint32_t val);
        uint32_t GetDataExpirationTimeSecs() {return expiration_secs;}

        void SetInterface(std::string interface);
        std::string GetInterface(){return interface1;}

        void SetFilter(std::string str);
        std::string GetFilter(){return filter;}

        void SetTransmissionProtocol(std::string tx);
        std::string GetTransmissionProtocol(){return transmission_protocol;}

        void SetReadFromPcap(bool flag);
        bool GetReadFromPcap() {return pcap_flag;}

        void SetMode(bool flag);
        bool GetMode() {return mode;}

        void PrintConfiguration();

  private:

      static Config *m_instance;
      std::string process_name, mapping_type;
      uint32_t expiration_secs;
      std::string interface1;
      std::string filter, transmission_protocol;
      bool pcap_flag, mode;
};

#endif
