#include "DecodePacket.h"

DecodePacket::DecodePacket()
{}


std::string DecodePacket::GetCurrentTime()
{
     char buffer[80];

     time_t tv;
     struct tm timeStamp = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous

     time (&tv);
     localtime_r(&tv, &timeStamp);

     strftime (buffer,80,"%Y-%m-%d %H:%M:%S", &timeStamp);

     return buffer;
}
