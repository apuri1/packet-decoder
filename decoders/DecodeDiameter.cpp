

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

#include "DecodeDiameter.h"
#include "Config.h"

#undef MODULE_NAME
#define MODULE_NAME "DECODE DIAMETER"


void DecodeDiameter::ProcessSCTPPayload(iphdr *iph,
                                        struct sctp_datahdr *datah,
                                        uint32_t chunk_length,
                                        std::string packet_time_stamp)
{
    int32_t diam_length_full, diam_length_payload;
    int32_t diam_command_code;
    int32_t diam_application_id;

    S6A s6a;
    s6a.server_time_stamp = GetCurrentTime();
    s6a.packet_time_stamp  = packet_time_stamp;

    printf( "Packet time stamp %s, Server time stamp %s\n", s6a.packet_time_stamp.c_str(), s6a.server_time_stamp.c_str());

    //get the length

    diam_length_full = int32_t((uint8_t)(datah->payload[1]) << 16 |
                               (uint8_t)(datah->payload[2]) << 8 |
                               (uint8_t)(datah->payload[3]));

    printf( " diameter version: %d, diameter length %d\n", datah->payload[0], diam_length_full);

    //3 bytes of command_code

    diam_command_code = int32_t((uint8_t)(datah->payload[5]) << 16 |
                                (uint8_t)(datah->payload[6]) << 8 |
                                (uint8_t)(datah->payload[7]));

    printf( " diameter command code: %d\n", diam_command_code);

    if(diam_command_code == kDIAMETER_REQUEST_ANSWER_COMMAND_CODE)
    {
       printf( " this must be a AIR or AIA...\n");

       // 4 bytes of ApplicatonId

       diam_application_id = int32_t((uint8_t)(datah->payload[8]) << 24 |
                                     (uint8_t)(datah->payload[9]) << 16 |
                                     (uint8_t)(datah->payload[10]) << 8 |
                                     (uint8_t)(datah->payload[11]));

       printf( " Application ID: %d\n", diam_application_id);

       if(diam_application_id == kS6A_APPLICATION_ID)
       {
          printf( " \n****  3GPP S6a/S6d  **** \n\n");
       }

      //Skip 4 bytes of hop-to-hop and 4 bytes of end-to-end

      //Now decode the payload that contains the AVPs

      diam_length_payload = diam_length_full - 20;

      printf( " diam_length_full %d, compared to chunk length %d\n", diam_length_full, chunk_length);
      printf( " diam_length_payload (minus header) %d\n", diam_length_payload);

      std::vector<uint8_t> diameter_msgs;

      diameter_msgs.reserve(diam_length_full);

      std::copy(&datah->payload[19], &datah->payload[diam_length_full], std::back_inserter(diameter_msgs));

      printf( " sizeof vector %d\n", diameter_msgs.size());

      //auto it = diameter_msgs.begin();

      int32_t avp_length_decoded = 0;

      int32_t index = 0;

//diam_length_full includes headers, so minus those to get the actual payload size
//
      s6a.authentication_type = 2;

      while(diam_length_payload > 0)
      {
            printf( "at index %d\n", index);

            printf( " last avp_length_decoded val %d\n", avp_length_decoded);

            avp_length_decoded = DecodeAVPs(diameter_msgs, s6a, index);  //pass a copy, as opposed to reference. maintain index here.

            printf( " latest decoded avp length (inc. padding) %d\n", avp_length_decoded);

            if(avp_length_decoded <= 0)
            {
               break;
            }

            diam_length_payload = diam_length_payload - avp_length_decoded;

            printf( " remaining diam length  %d\n", diam_length_payload);

            index = index + avp_length_decoded;
      }

      printf( "Done decoding S6a\n");

      if(s6a.authentication_type == 0)
      {
          printf( "S6A Authentication Information Request\n");

          if(Config::Instance()->GetInternalMapping() == "MultiIndex")
          {
             ContainerMultiIndex::Instance()->S6aAirUpdate(s6a);
          }

      }
      else if(s6a.authentication_type == 1)
      {
          printf( "S6A Authentication Information Answer\n");

          if(Config::Instance()->GetInternalMapping() == "MultiIndex")
          {
             ContainerMultiIndex::Instance()->S6aAiaUpdate(s6a);
          }
      }
      else
      {
          printf( "Undetermined S6a Authentication type!\n");
      }

    }
    else
    {
       printf( " Skip as not an Authentication Information Request or Answer..\n");
    }
}

size_t DecodeDiameter::DecodeAVPs(std::vector<uint8_t> & vec, struct S6A & s6a, int32_t index)
{
     int32_t avp_code   = 0;
     int32_t avp_length = 0;
     bool vbit_flag     = false;

     uint8_t avp_byte_one, avp_byte_two, avp_byte_three, avp_byte_four;
     uint8_t flags_byte;

     index++;

     if( RetrieveByte(vec, avp_byte_one,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_two,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_three,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_four,  index) < 0)
      return -1;

     avp_code = int32_t((uint8_t)(avp_byte_one) << 24 |
                        (uint8_t)(avp_byte_two) << 16 |
                        (uint8_t)(avp_byte_three) << 8 |
                        (uint8_t)(avp_byte_four));

     printf( " AVP Code: %d\n", avp_code);

     index += 1;

     //The V-bit, Vendor Specific bit, informs us whether the optional Vendor-ID AVP is present

     if( RetrieveByte(vec, flags_byte,  index) < 0)
      return -1;

     if( (flags_byte & 0x80) )
     {
        printf( " V-bit set\n");
        vbit_flag = true;
     }
     else
     {
        printf( " V-bit not set\n");
     }

     //Skip 1 byte of flags, don't care
     index += 1;

     if( RetrieveByte(vec, avp_byte_one,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_two,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_three,  index) < 0)
      return -1;

     avp_length = int32_t((uint8_t)(avp_byte_one) << 16 |
                          (uint8_t)(avp_byte_two) << 8 |
                          (uint8_t)(avp_byte_three));

     printf( " AVP Length: %d\n", avp_length);

     //if(!ValidateAVPLength(avp_length))
     //{
     //   printf( " AVP Length: %d is not a multiple of 4\n", avp_length);
     //   return -1;
     //}

     index++;

     switch(avp_code)
     {
            case kAVP_CODE_DIAMETER_SESSION_ID:
            {
                printf( " Got length %d of AVP (Session ID)\n", avp_length);

                if(vbit_flag)
                {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                }

                char session_id[avp_length];

                std::copy(vec.begin()+index, vec.begin()+index+avp_length, session_id);

                s6a.session_id = session_id;

                printf( " Session ID: %s\n", s6a.session_id.c_str());

                avp_length += ProcessPadding(avp_length);

                return avp_length;
            }

            case kAVP_CODE_ORIGIN_HOST:
            {
                 printf( " Got length %d of AVP (Origin-Host)\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 char origin_host[avp_length];

                 std::copy(vec.begin()+index, vec.begin()+index+avp_length, origin_host);

                 s6a.origin_host = origin_host;

                 printf( " Origin-Host: %s\n", s6a.origin_host.c_str());

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;

            }
            case kAVP_RESULT_CODE:
            {
                printf( " Got length %d of AVP (Result-Code)\n", avp_length);

                if(vbit_flag)
                {
                   if( HandleVendorFlag(vec, index) < 0) return -1;
                }

                if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                index++;

                if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                index++;

                if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                index++;

                if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                int32_t result_code = int32_t((uint8_t)(avp_byte_one) << 24 |
                                              (uint8_t)(avp_byte_two) << 16 |
                                              (uint8_t)(avp_byte_three) << 8 |
                                              (uint8_t)(avp_byte_four));

                printf( " Result Code: %d \n", result_code);

                avp_length += ProcessPadding(avp_length);

                return avp_length;

            }
            case kAVP_AUTH_SESSION_STATE:
            {
                 printf( " Got length %d of AVP (Auth-Session-State)\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0)
                      return -1;
                 }

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                 int32_t session_state = int32_t((uint8_t)(avp_byte_one) << 24 |
                                                 (uint8_t)(avp_byte_two) << 16 |
                                                 (uint8_t)(avp_byte_three) << 8 |
                                                 (uint8_t)(avp_byte_four));

                 printf( " Auth-Session-State: %d\n", session_state);

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            case kAVP_USER_NAME:
            {
                printf( " Got length %d of AVP (IMSI [User-Name])\n", avp_length);

                if(vbit_flag)
                {
                   if( HandleVendorFlag(vec, index) < 0) return -1;
                }

                char imsi[avp_length];

                std::copy(vec.begin()+index, vec.begin()+index+avp_length, imsi);

                s6a.authentication_type = 0;

                s6a.air.user_name = imsi;

                printf( " IMSI : %s\n", s6a.air.user_name.c_str());

                avp_length += ProcessPadding(avp_length);

                return avp_length;

            }
            case kAVP_ORIGIN_REALM:
            {
                printf( " Got length %d of AVP (Origin-Realm)\n", avp_length);

                if(vbit_flag)
                {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                }

                char origin_realm[avp_length];

                std::copy(vec.begin()+index, vec.begin()+index+avp_length, origin_realm);

                s6a.origin_realm = origin_realm;

                printf( " Origin-Realm: %s\n", s6a.origin_realm.c_str());

                avp_length += ProcessPadding(avp_length);

                return avp_length;
            }
            case kAVP_DESTINATION_REALM:
            {
                printf( " Got length %d of AVP (Destination-Realm])\n", avp_length);

                if(vbit_flag)
                {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                }

                char dest_realm[avp_length];

                std::copy(vec.begin()+index, vec.begin()+index+avp_length, dest_realm);

                s6a.dest_realm = dest_realm;

                printf( " Dest-Realm: %s\n", s6a.dest_realm.c_str());

                avp_length += ProcessPadding(avp_length);

                return avp_length;
            }
            case kAVP_VISITED_PLMN_ID:
            {
                 printf( " Got length %d of AVP (Visited PLMN id])\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }

            case kAVP_REQUESTED_EUTRAN_AUTHENTICATION_INFO:
            {
                 int32_t avp_length_tmp = 0;

                 printf( " Got length %d of AVP (Requested-EUTRAN-Authentication-Info)\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                 avp_code = int32_t((uint8_t)(avp_byte_one) << 24 |
                                    (uint8_t)(avp_byte_two) << 16 |
                                    (uint8_t)(avp_byte_three) << 8 |
                                    (uint8_t)(avp_byte_four));

                 printf( " Next AVP Code: %d\n", avp_code);

                 index += 1;

                 if( RetrieveByte(vec, flags_byte,  index) < 0)
                  return -1;

                 if( (flags_byte & 0x80) )
                 {
                    printf( " V-bit set\n");
                    vbit_flag = true;
                 }
                 else
                 {
                    printf( " V-bit not set\n");
                    vbit_flag = false;
                 }

                 index += 1;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 avp_length_tmp = int32_t((uint8_t)(avp_byte_one) << 16 |
                                          (uint8_t)(avp_byte_two) << 8 |
                                          (uint8_t)(avp_byte_three));

                 printf( " Next AVP length: %d\n", avp_length_tmp);

                 index++;

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                 int32_t num_of_requested_vectors = int32_t((uint8_t)(avp_byte_one) << 24 |
                                                            (uint8_t)(avp_byte_two) << 16 |
                                                            (uint8_t)(avp_byte_three) << 8 |
                                                            (uint8_t)(avp_byte_four));

                 s6a.air.num_of_requested_vectors = num_of_requested_vectors;

                 printf( " num_of_requested_vectors: %d\n", s6a.air.num_of_requested_vectors);

                 avp_length += ProcessPadding(avp_length);

//Immediate-Response-Preferred
                 index++;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 //next_avp_byte_one = vec.at(index);
                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                 avp_code = int32_t((uint8_t)(avp_byte_one) << 24 |
                                    (uint8_t)(avp_byte_two) << 16 |
                                    (uint8_t)(avp_byte_three) << 8 |
                                    (uint8_t)(avp_byte_four));

                 printf( " Next AVP Code: %d\n", avp_code);

                 index += 1;

                 flags_byte = vec.at(index);

                 if( (flags_byte & 0x80) )
                 {
                    printf( " V-bit set\n");
                    vbit_flag = true;
                 }
                 else
                 {
                    printf( " V-bit not set\n");
                    vbit_flag = false;
                 }

                 index += 1;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 avp_length_tmp = int((uint8_t)(avp_byte_one) << 16 |
                                      (uint8_t)(avp_byte_two) << 8 |
                                      (uint8_t)(avp_byte_three));

                 index++;

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index += 1;

                 if( RetrieveByte(vec, avp_byte_one,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_two,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_three,  index) < 0)
                  return -1;

                 index++;

                 if( RetrieveByte(vec, avp_byte_four,  index) < 0)
                  return -1;

                 int32_t immediate_response_preferred = int32_t((uint8_t)(avp_byte_one) << 24 |
                                                                (uint8_t)(avp_byte_two) << 16 |
                                                                (uint8_t)(avp_byte_three) << 8 |
                                                                (uint8_t)(avp_byte_four));

                 printf( " immediate_response_preferred: %d\n", immediate_response_preferred);

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            case kAVP_AUTHENTCATION_INFO:
            {
                 uint8_t avp_eutran_vector_byte_one, avp_eutran_vector_byte_two, avp_eutran_vector_byte_three, avp_eutran_vector_byte_four;
                 uint8_t avp_eutran_vector_len_byte_one, avp_eutran_vector_len_byte_two, avp_eutran_vector_len_byte_three, avp_eutran_vector_len_byte_four;
                 uint8_t vendor_id_byte_one, vendor_id_byte_two, vendor_id_byte_three, vendor_id_byte_four;

                 printf( " Got length %d of AVP (kAVP_AUTHENTCATION_INFO AIA)\n", avp_length);

                 uint32_t total_length_of_vectors = avp_length;

                 printf( "* Got total length %d of all vector AVPs (kAVP_AUTHENTCATION_INFO + all kAVP_EUTRAN_VECTOR )\n", total_length_of_vectors);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index += 1;

                 int32_t padding = ProcessPadding(avp_length);

                 avp_length += padding;

                 index = index + padding;

                 total_length_of_vectors = total_length_of_vectors - 12; //don't include the header fields

                 while(total_length_of_vectors > 0)
                 {
                   if( RetrieveByte(vec, avp_eutran_vector_byte_one,  index) < 0)
                    return -1;

                   index++;

                   if( RetrieveByte(vec, avp_eutran_vector_byte_two,  index) < 0)
                    return -1;

                   index++;

                   if( RetrieveByte(vec, avp_eutran_vector_byte_three,  index) < 0)
                    return -1;

                   index++;

                   if( RetrieveByte(vec, avp_eutran_vector_byte_four,  index) < 0)
                    return -1;

                   avp_code = int32_t((uint8_t)(avp_eutran_vector_byte_one) << 24 |
                                      (uint8_t)(avp_eutran_vector_byte_two) << 16 |
                                      (uint8_t)(avp_eutran_vector_byte_three) << 8 |
                                      (uint8_t)(avp_eutran_vector_byte_four));

                   printf( " Next AVP Code: %d\n", avp_code);

                   if(avp_code == kAVP_EUTRAN_VECTOR)
                   {
                       index +=2; //skip the 1 byte flag

                       if( RetrieveByte(vec, avp_eutran_vector_len_byte_one,  index) < 0)
                        return -1;

                       index++;

                       if( RetrieveByte(vec, avp_eutran_vector_len_byte_two,  index) < 0)
                        return -1;

                       index++;

                       if( RetrieveByte(vec, avp_eutran_vector_len_byte_three,  index) < 0)
                        return -1;

                       int32_t avp_vector_full_length = int32_t((uint8_t)(avp_eutran_vector_len_byte_one) << 16 |
                                                                (uint8_t)(avp_eutran_vector_len_byte_two) << 8 |
                                                                (uint8_t)(avp_eutran_vector_len_byte_three));

                       printf( "* length %d of this vector (kAVP_EUTRAN_VECTOR )\n", avp_vector_full_length);

                       total_length_of_vectors = total_length_of_vectors - avp_vector_full_length;

                       printf( "Remaining total_length_of_vectors %d\n", total_length_of_vectors);

                       index++;

                       if(vbit_flag)
                       {
                          if( RetrieveByte(vec, vendor_id_byte_one,  index) < 0)
                           return -1;

                          index++;

                          if( RetrieveByte(vec, vendor_id_byte_two,  index) < 0)
                           return -1;

                          index++;

                          if( RetrieveByte(vec, vendor_id_byte_three,  index) < 0)
                           return -1;

                          index++;

                          if( RetrieveByte(vec, vendor_id_byte_four,  index) < 0)
                           return -1;

                          int32_t vendor_id = int32_t((uint8_t)(vendor_id_byte_one) << 24 |
                                                      (uint8_t)(vendor_id_byte_two) << 16 |
                                                      (uint8_t)(vendor_id_byte_three) << 8 |
                                                      (uint8_t)(vendor_id_byte_four));

                          if(vendor_id == kAVP_VENDOR_ID)
                          {
                             printf( " Vendor ID: %d\n", vendor_id);
                          }
                       }

                       index++;

                       avp_length += ProcessPadding(avp_length);

                       int32_t avp_length_decoded;

                       avp_vector_full_length = avp_vector_full_length - 12; //don't include the header fields

                       s6a.authentication_type = 1;

                       while(avp_vector_full_length > 0)
                       {
                         printf( "at index %d\n", index);

                         avp_length_decoded = DecodeKeys(vec, s6a, index);

                         printf( " last decoded avp length (inc. padding) %d\n", avp_length_decoded);

                         avp_vector_full_length = avp_vector_full_length - avp_length_decoded;

                         printf( " remaining avp_vector_full_length  %d\n", avp_vector_full_length);

                         if(avp_vector_full_length <= 0)
                         {
                            break;
                         }

                         avp_length = avp_length + avp_length_decoded;

                         index = index + avp_length_decoded;
                       }
                   }
                   else
                   {
                      break;
                   }
                }

                printf( "Done decoding\n");

                return avp_length;
            }

            default:
            {
               printf( " Unrecognised AVP code, skipping %d\n", avp_code);

               avp_length += ProcessPadding(avp_length);

               return avp_length;
            }
      }
}

size_t DecodeDiameter::DecodeKeys(std::vector<uint8_t> & vec, struct S6A & s6a, int32_t index)
{
     int32_t avp_code   = 0;
     int32_t avp_length = 0;
     bool vbit_flag     = false;

     uint8_t avp_byte_one, avp_byte_two, avp_byte_three, avp_byte_four;
     uint8_t flags_byte;

     if( RetrieveByte(vec, avp_byte_one,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_two,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_three,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_four,  index) < 0)
      return -1;


     avp_code = int32_t((uint8_t)(avp_byte_one) << 24 |
                        (uint8_t)(avp_byte_two) << 16 |
                        (uint8_t)(avp_byte_three) << 8 |
                        (uint8_t)(avp_byte_four));

     printf( " AVP Code: %d\n", avp_code);

 //Skip 1 byte of flags, don't care
     index += 1;

     if( RetrieveByte(vec, flags_byte,  index) < 0)
      return -1;

     if( (flags_byte & 0x80) )
     {
        printf( " V-bit set\n");
        vbit_flag = true;
     }
     else
     {
        printf( " V-bit not set\n");
     }

     index += 1;

     if( RetrieveByte(vec, avp_byte_one,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_two,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, avp_byte_three,  index) < 0)
      return -1;


     avp_length = int((uint8_t)(avp_byte_one) << 16 |
                      (uint8_t)(avp_byte_two) << 8 |
                      (uint8_t)(avp_byte_three));

     printf( " AVP Length: %d\n", avp_length);

     index++;

     switch(avp_code)
     {
            case kAVP_CODE_RAND:
            {
                printf( " Got length %d of AVP RAND\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 char rand[avp_length];

                 std::copy(vec.begin()+index, vec.begin()+index+avp_length, rand);

                 printf( " RAND sIzE: %d\n", sizeof(rand));

                 std::string rand_str;
                 for(int32_t i = 0; i < avp_length-12; i++)  ///subtract to not include the header
                 {
                     char buff[4];
                     sprintf(buff, "%02x", (uint8_t)rand[i]) ;
                     rand_str = rand_str + buff ;
                 }

                 printf( " RAND: %s\n", rand_str.c_str());

                 s6a.aia.E_UTRAN_Vectors.push_back(std::make_tuple("RAND", rand_str));

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            case kAVP_CODE_XRES:
            {
                 printf( " Got length %d of AVP XRES\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 char xres[avp_length];

                 std::copy(vec.begin()+index, vec.begin()+index+avp_length, xres);

                 std::string xres_str;
                 for(int32_t i = 0; i < avp_length -12; i++)  ///subtract to not include the header
                 {
                     char buff[4];
                     sprintf(buff, "%02x", (uint8_t)xres[i]) ;
                     xres_str = xres_str + buff ;
                 }

                 printf( " XRES: %s\n", xres_str.c_str());

                 s6a.aia.E_UTRAN_Vectors.push_back(std::make_tuple("XRES", xres_str));

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            case kAVP_CODE_AUTN:
            {
                 printf( " Got length %d of AVP AUTN\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 char autn[avp_length];

                 std::copy(vec.begin()+index, vec.begin()+index+avp_length, autn);

                 std::string autn_str;
                 for(int32_t i = 0; i < avp_length-12; i++)  ///subtract to not include the header
                 {
                     char buff[4];
                     sprintf(buff, "%02x", (uint8_t)autn[i]) ;
                     autn_str = autn_str + buff ;
                 }

                 printf( " AUTN: %s\n", autn_str.c_str());

                 s6a.aia.E_UTRAN_Vectors.push_back(std::make_tuple("AUTN", autn_str));

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            case kAVP_CODE_KASME:
            {
                 printf( " Got length %d of AVP KASME\n", avp_length);

                 if(vbit_flag)
                 {
                    if( HandleVendorFlag(vec, index) < 0) return -1;
                 }

                 index++;

                 char kasme[avp_length];

                 std::copy(vec.begin()+index, vec.begin()+index+avp_length, kasme);

                 std::string kasme_str;
                 for(int32_t i = 0; i < avp_length -12; i++) ///subtract to not include the header
                 {
                     char buff[4];
                     sprintf(buff, "%02x", (uint8_t)kasme[i]) ;
                     kasme_str = kasme_str + buff ;
                 }

                 printf( " KASME: %s\n", kasme_str.c_str());

                 s6a.aia.E_UTRAN_Vectors.push_back(std::make_tuple("KASME", kasme_str));

                 avp_length += ProcessPadding(avp_length);

                 return avp_length;
            }
            default:
            {
               printf( " Unrecognised AVP code, skipping %d\n", avp_code);

               avp_length += ProcessPadding(avp_length);

               return avp_length;
            }
    }
}

bool DecodeDiameter::ValidateAVPLength(int32_t avp_length)
{
     if(avp_length % 4)
     {
        return true;
     }

     return false;
}

int32_t DecodeDiameter::ProcessPadding(int32_t avp_length)
{
     // Note: The length of the padding is not reflected in the AVP Length field
     //
     int32_t padding = 0;

     padding = avp_length % 4;

     if(padding != 0)
     {
          padding = 4 - padding;

          printf( " Got padding %d\n", padding);
     }

     return padding;
}

int32_t DecodeDiameter::HandleVendorFlag(std::vector<uint8_t> & vec, int & index)
{
     uint8_t vendor_id_byte_one, vendor_id_byte_two, vendor_id_byte_three, vendor_id_byte_four;

     if( RetrieveByte(vec, vendor_id_byte_one,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, vendor_id_byte_two,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, vendor_id_byte_three,  index) < 0)
      return -1;

     index++;

     if( RetrieveByte(vec, vendor_id_byte_four,  index) < 0)
      return -1;

     int32_t vendor_id = int32_t((uint8_t)(vendor_id_byte_one) << 24 |
                                 (uint8_t)(vendor_id_byte_two) << 16 |
                                 (uint8_t)(vendor_id_byte_three) << 8 |
                                 (uint8_t)(vendor_id_byte_four));

     if(vendor_id == kAVP_VENDOR_ID)
     {
        printf( " Vendor ID: %d\n", vendor_id);
     }

     return 0;

}


int32_t DecodeDiameter::RetrieveByte(std::vector<uint8_t> & vec,
                                     uint8_t & byte,
                                     int32_t index)
{
     try
     {
        byte = vec.at(index);
     }
     catch(const std::out_of_range& e)
     {
        printf( "Cannot access next diameter element\n %s \n", e.what());

        return -1;
     }

     return 0;
}