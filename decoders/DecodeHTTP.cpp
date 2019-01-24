

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


//TODO
#include <curl/curl.h>

#define BOOST_ERROR_CODE_HEADER_ONLY
#include <boost/system/error_code.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "DecodeHTTP.h"
#include "Config.h"

//#include <curl/curl.h>

#undef MODULE_NAME
#define MODULE_NAME "DECODE HTTP"


void DecodeHTTP::ProcessTCPPayload(std::vector<uint8_t> & payload,
                                   uint32_t payload_length,      //TODO
                                   std::string packet_time_stamp)
{
   int32_t length;
  //get the full string representative of contents
   std::string contents(payload.begin(), payload.end());

   printf("contents %s", contents.c_str());

   CURL *curl = curl_easy_init();

   if(curl)
   {
      /*Format the http message*/
      char *output = curl_easy_unescape(curl, contents.c_str(), 0, &length);

      if(output)
      {
         printf("process_event obtained\n: %s\n", output);

         printf("string length: %d vs num bytes: %d\n", length, payload_length);

         //pass the num of bytes along.
         //parse_payload_info(output, len);

         curl_free(output);
      }
      else
      {
         printf("Failed\n ");
      }
   }

   curl_easy_cleanup(curl);

}
