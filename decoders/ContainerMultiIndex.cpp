#include "json.h"
#include "ContainerMultiIndex.h"

ContainerMultiIndex *ContainerMultiIndex::m_instance = nullptr;

std::mutex ContainerMultiIndex::mutex_multi_index;

ContainerMultiIndex *ContainerMultiIndex::Instance()
{
    if(m_instance == nullptr)
    {
       printf( "Creating new instance of ContainerMultiIndex\n");
       m_instance = new ContainerMultiIndex();
    }

    return m_instance;
}

void ContainerMultiIndex::S6aAirUpdate(S6A & s6a)
{
    std::unique_lock<std::mutex> lock(mutex_multi_index);

    DiameterContainer::index<IndexByImsi>::type& by_imsi = diameter_container.get<IndexByImsi>();

    printf( "S6a AIR: checking if IMSI %s exists\n", s6a.air.user_name.c_str());

    auto it1 = by_imsi.find(s6a.air.user_name);

    if (it1 != by_imsi.end())
    {
       printf( "S6a AIR: imsi %s found, update the session ID!\n", s6a.air.user_name.c_str());

        //TODO guard this call with mutex!
        by_imsi.modify(it1, DiameterData::update_session_id(s6a.session_id));
        by_imsi.modify(it1, DiameterData::update_modified_datetime(s6a.packet_time_stamp));
        by_imsi.modify(it1, DiameterData::update_modified_date( GetDate(s6a.packet_time_stamp) ));
    }
    else
    {
        printf( "S6a AIR: imsi %s not found, entering...\n", s6a.air.user_name.c_str());

        DiameterData subs;
        subs.imsi           = s6a.air.user_name;
        subs.session_id     = s6a.session_id;
        subs.air_time_stamp = s6a.packet_time_stamp;
        subs.modified_datetime  = s6a.packet_time_stamp;
        subs.modified_date  = GetDate(s6a.packet_time_stamp);

        printf( "->(S6a AIR:) inserting %s, %s and %s [%s]!\n", subs.imsi.c_str(),
                                                                 subs.session_id .c_str(),
                                                                 subs.modified_datetime.c_str(),
                                                                 subs.modified_date.c_str());

        diameter_container.insert(subs);

      //Now lets see if that last update worked:

        DiameterContainer::index<IndexBySessionid>::type& by_sessionid = diameter_container.get<IndexBySessionid>();

        auto it2 = by_sessionid.find(subs.session_id);

        if(it2 != by_sessionid.end())
        {
           printf( "session id %s found!\n", it2->session_id.c_str());
        }
    }
}

void ContainerMultiIndex::S6aAiaUpdate(S6A & s6a)
{
    std::unique_lock<std::mutex> lock(mutex_multi_index);

    DiameterData subs;
    subs.session_id     = s6a.session_id;
    subs.E_UTRAN_Vectors.reserve(s6a.aia.E_UTRAN_Vectors.size());
    std::copy(s6a.aia.E_UTRAN_Vectors.begin(), s6a.aia.E_UTRAN_Vectors.end(), back_inserter(subs.E_UTRAN_Vectors));
    subs.aia_time_stamp = s6a.packet_time_stamp;
    subs.modified_datetime  = s6a.packet_time_stamp;
    subs.modified_date  = GetDate(s6a.packet_time_stamp);

    printf( "S6a AIA: checking if  %s exists\n", s6a.session_id.c_str());

    DiameterContainer::index<IndexBySessionid>::type& by_sessionid = diameter_container.get<IndexBySessionid>();

    auto it = by_sessionid.find(subs.session_id);

    if(it != by_sessionid.end())
    {
        printf( "S6a AIA: session id %s found, updating with keys\n", it->session_id.c_str());

        by_sessionid.modify(it, DiameterData::update_eutran_vectors(subs.E_UTRAN_Vectors));
        by_sessionid.modify(it, DiameterData::update_aia_time_stamp(subs.aia_time_stamp));
        by_sessionid.modify(it, DiameterData::update_modified_datetime(subs.modified_datetime));
        by_sessionid.modify(it, DiameterData::update_modified_date( GetDate(subs.modified_datetime) ));

    }
    else
    {
       printf( "S6a AIA: session id %s not found, cannot push auth vectors\n", s6a.session_id.c_str());
    }
}

std::string ContainerMultiIndex::PrintImsiIndex()
{
     std::unique_lock<std::mutex> lock(mutex_multi_index);

     std::stringstream ss;

     printf( "\n");

     printf( "Printing .....\n");

    for(auto it = diameter_container.get<IndexByImsi>().begin(); it != diameter_container.get<IndexByImsi>().end(); it++)
    {
        ss << "\nIMSI: \n";
        ss << "   ";
        ss << it->imsi;
        ss << "\n";
        ss << "Session ID: \n";
        ss << "   ";
        ss << it->session_id;
        ss << "\n";
        ss << "Authentication Vectors: \n";

        for(auto keys_it = it->E_UTRAN_Vectors.begin();
            keys_it != it->E_UTRAN_Vectors.end();
            keys_it++)
        {
            ss << "   ";
            ss << std::get<0>(*keys_it);
            ss << ": ";
            ss << std::get<1>(*keys_it);
            ss << "\n";
        }

        ss << "Modified Time: \n";
        ss << "   ";
        ss << it->modified_datetime;
        ss << "\n\n";
    }

    printf( "\n");

    printf( "%s\n\n", ss.str().c_str());

    return ss.str();
}

std::string ContainerMultiIndex::PrintSessionIndex()
{
     std::unique_lock<std::mutex> lock(mutex_multi_index);

     std::stringstream ss;

     printf( "\n");

     printf( "Printing .....\n");

    for(auto it = diameter_container.get<IndexBySessionid>().begin(); it != diameter_container.get<IndexBySessionid>().end(); it++)
    {
        ss << "\nSession ID: \n";
        ss << "   ";
        ss << it->session_id;
        ss << "\n";
        ss << "IMSI: \n";
        ss << "   ";
        ss << it->imsi;
        ss << "\n";
        ss << "Authentication Vectors: \n";

        for(auto keys_it = it->E_UTRAN_Vectors.begin();
            keys_it != it->E_UTRAN_Vectors.end();
            keys_it++)
        {
            ss << "   ";
            ss << std::get<0>(*keys_it);
            ss << ": ";
            ss << std::get<1>(*keys_it);
            ss << "\n";
        }

        ss << "Modified Time: \n";
        ss << "   ";
        ss << it->modified_datetime;
        ss << "\n\n";
    }

    printf( "\n");

    printf( "%s\n\n", ss.str().c_str());

    return ss.str();
}

std::string ContainerMultiIndex::PrintIpaddrIndex()
{
     std::unique_lock<std::mutex> lock(mutex_multi_index);

     std::stringstream ss;

     printf( "\n");

     printf( "Printing .....\n");

    for(auto it = diameter_container.get<IndexByImsi>().begin(); it != diameter_container.get<IndexByImsi>().end(); it++)
    {
        ss << "IMSI: \n";
        ss << "   ";
        ss << it->imsi;
        ss << "\n";
        ss << "Session ID: \n";
        ss << "   ";
        ss << it->session_id;
        ss << "\n";
        ss << "Authentication Vectors: \n";

        for(auto keys_it = it->E_UTRAN_Vectors.begin();
            keys_it != it->E_UTRAN_Vectors.end();
            keys_it++)
        {
            ss << "   ";
            ss << std::get<0>(*keys_it);
            ss << ": ";
            ss << std::get<1>(*keys_it);
            ss << "\n";
        }

        ss << "Modified Time: \n";
        ss << "   ";
        ss << it->modified_datetime;
        ss << "\n\n";
    }

    printf( "\n");

    printf( "%s\n\n", ss.str().c_str());

    //TODO, temp
    ManageMultiIndex();

    return ss.str();
}

std::string ContainerMultiIndex::ShowSubscriberInfo(std::string imsi)
{
     std::unique_lock<std::mutex> lock(mutex_multi_index);

     std::stringstream ss;
     std::string sessionid;

     printf( "\n");

     printf( "Retrieving data for IMSI %s\n", imsi.c_str());

     ss << "Retrieving Data for IMSI \n";
     ss <<  imsi;
     ss << "\n";

     DiameterContainer::index<IndexByImsi>::type& by_imsi = diameter_container.get<IndexByImsi>();

     auto it1 = by_imsi.find(imsi);

     if(it1 != by_imsi.end())
     {
        ss << "\nIMSI: \n";
        ss << "   ";
        ss << it1->imsi;
        ss << "\n";
        ss << "Session ID: \n";
        ss << "   ";
        ss << it1->session_id;
        ss << "\n";
        ss << "Authentication Vectors: \n";

        for(auto keys_it = it1->E_UTRAN_Vectors.begin();
            keys_it != it1->E_UTRAN_Vectors.end();
            keys_it++)
        {
            ss << "   ";
            ss << std::get<0>(*keys_it);
            ss << ": ";
            ss << std::get<1>(*keys_it);
            ss << "\n";
        }

        ss << "Modified Time: \n";
        ss << "   ";
        ss << it1->modified_datetime;
        ss << "\n\n";

        printf( "%s\n\n", ss.str().c_str());
     }
     else
     {
        printf( "IMSI %s data not found \n",imsi.c_str());

        ss << "...not found\n\n";
     }

     return ss.str();
}


std::string ContainerMultiIndex::LogTimeElapsed()
{
   std::unique_lock<std::mutex> lock(mutex_multi_index);

   std::stringstream ss;
   DiameterContainer::index<IndexByTime>::type& by_time = diameter_container.get<IndexByTime>();

   std::string current_time = GetCurrentTime();

   printf( "Current time to use : %s\n", current_time.c_str());

   for(auto it = by_time.begin(); it != by_time.end(); it++)
   {

       printf( "IMSI      : %s\n", it->imsi.c_str());
       printf( "Session ID: %s\n", it->session_id.c_str());
       printf( "Authentication Vectors: \n");

       for(auto keys_it = it->E_UTRAN_Vectors.begin();
            keys_it != it->E_UTRAN_Vectors.end();
            keys_it++)
       {
            printf( "%s      : %s\n",std::get<0>(*keys_it).c_str(), std::get<1>(*keys_it).c_str());

       }

       printf( "Modified Time:       %s\n", it->modified_datetime.c_str());


//boost::posix_time requires the library; the intention is to use header-only boost.
//
       //boost::posix_time::ptime t1(boost::posix_time::time_from_string(it->modified_datetime));
       //boost::posix_time::ptime t2(boost::posix_time::time_from_string(GetCurrentTime()));
       //boost::posix_time::time_duration delta = t2 - t1;
       //printf( "Time elapsed for this Subscriber : %d\n", delta.total_seconds());

       double time_delta = EvaluateTimeDelta(current_time, it->modified_datetime);

       if(time_delta < 0)
       {
          printf( "Could not determine time delta for IMSI %s\n", it->imsi.c_str());

          ss << "Could not determine time delta for IMSI ";
          ss << it->imsi;
          ss << "\n";
       }
       else
       {
          printf( "%f seconds/ %f days elapsed for Subscriber with IMSI %s\n", time_delta, time_delta/(24*60*60), it->imsi.c_str());

          ss << time_delta;
          ss << " seconds / ";
          ss << time_delta/(24*60*60);
          ss << " days elapsed for Subscriber with IMSI ";
          ss << it->imsi;
          ss << "\n";
          ss << "Current time      : ";
          ss << current_time;
          ss << "\n";
          ss << "Last modified Time: ";
          ss << it->modified_datetime;
          ss << "\n";
       }
   }

   return ss.str();
}

//TODO
//- call this every time an insertion occurs ?
//- call after X mins have expire
//

void ContainerMultiIndex::ManageMultiIndex()
{
    std::string previous_date = GetMonthOld();

    printf("previous dates to remove: %s\n", previous_date.c_str());

    DiameterContainer::index<IndexByTime>::type& by_time = diameter_container.get<IndexByTime>();

    //TODO for now, hard code
    //auto subset = diameter_container.get<IndexByTime>().equal_range(previous_date);
    auto subset = by_time.equal_range("2015-06-08");

    for (auto it = subset.first; it != subset.second; ++it)
    {
        printf("Erasing older entries: %s ", (it->imsi).c_str());
        printf("                     : %s ", (it->modified_datetime).c_str());
        printf("                     : %s ", (it->modified_date).c_str());

        //it = by_time.erase(it);
    }
}

void ContainerMultiIndex::EraseAll()
{
     printf("erasing all \n");

     DiameterContainer::index<IndexByTime>::type& by_time = diameter_container.get<IndexByTime>();

     int64_t i = 0;
     //erase everything
     for(auto it = by_time.begin(); it != by_time.end();)
     {
         i++;

         printf("deleting IMSI %s Modified time %s at index: %d \n",it->imsi.c_str(), it->modified_datetime.c_str(), i);

         it = by_time.erase(it);
     }
}

std::string ContainerMultiIndex::GetCurrentTime()
{
     char buffer[100];

     time_t tv;
     struct tm time_stamp = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous

     memset(buffer, 0, sizeof(buffer));

     time(&tv);
     localtime_r(&tv, &time_stamp);

     strftime(buffer,100,"%Y-%m-%d %H:%M:%S", &time_stamp);

     return buffer;
}


//TODO this can be made more flexible - for now, go back in time by one month
std::string ContainerMultiIndex::GetMonthOld()
{
     char buffer[100];

     time_t tv;
     struct tm time_stamp = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous

     memset(buffer, 0, sizeof(buffer));

     time(&tv);
     localtime_r(&tv, &time_stamp);

     if(time_stamp.tm_mday < 29)
     {
         if(time_stamp.tm_mon == 0)
         {
            time_stamp.tm_mon = 11;
         }
         else
         {
            time_stamp.tm_mon = time_stamp.tm_mon - 1;
         }
     }

     strftime(buffer,100,"%Y-%m-%d", &time_stamp);

     return buffer;
}

std::string ContainerMultiIndex::GetDate(std::string datetime)
{
    std::string date;

    try
    {
       date = datetime.substr(0,10);
    }
    catch(const std::out_of_range& e)
    {
       printf( "can't process this: %s\n", date.c_str());
       date = kERROR;
    }

    return date;

}

double ContainerMultiIndex::EvaluateTimeDelta(std::string time_check1, std::string time_check2)
{
    int retVal = -1;
    time_t current;
    struct tm time1 = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous
    struct tm time2 = {0,0,0,0,0,0,0,0,0,0,nullptr}; //initialise each member to get rid of warnings - ridiculous

    printf( "Getting time delta between %s and %s\n : %d\n", time_check1.c_str(), time_check2.c_str());

    time(&current);

    if((strptime(time_check1.c_str(), "%Y-%m-%d %H:%M", &time1)) == NULL)
    {
      printf( "Invalid time format 1 \n");
      return retVal;
    }

    if((strptime(time_check2.c_str(), "%Y-%m-%d %H:%M", &time2)) == NULL)
    {
      printf( "Invalid time format 2 \n");
      return retVal;
    }

    return difftime(mktime(&time1), mktime(&time2));
}
