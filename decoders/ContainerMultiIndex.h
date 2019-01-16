#ifndef __SUBSCRIBERS_H__
#define __SUBSCRIBERS_H__

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>

#include <mutex>
#include <condition_variable>

#include <boost/unordered_map.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/composite_key.hpp>

//#include <boost/range.hpp>

#include <boost/range/algorithm.hpp>

#include "Config.h"

/********************************************
*
* Implements a single, MultiIndex Container
*
*********************************************/

//using namespace ::boost;
//using namespace ::boost::multi_index;


//Tags for multi_index_container, otherwise have to use nits, which is not very descriptive
struct IndexByImsi{};
struct IndexBySessionid{};
struct IndexByTime{};

class ContainerMultiIndex
{
    public:

       ContainerMultiIndex(){};

       static ContainerMultiIndex *Instance();

       //Access Data using different keys from one solitary container.

//NOTE: despite declaring the boost namespaces, omitting the scopes below causes compilation errors, so retained.
//
// use hashed_unique to prevent duplicate entries of a subscriber imsi.
//
      typedef boost::multi_index_container<
        DiameterData, // the data type stored
        boost::multi_index::indexed_by< // list of indexes
          boost::multi_index::hashed_unique<           //fast retrieval of imsi
            boost::multi_index::tag<IndexByImsi>,      // an index
            boost::multi_index::member<DiameterData, std::string, &DiameterData::imsi>
          >,
          boost::multi_index::hashed_unique<           //fast retrieval of session id
            boost::multi_index::tag<IndexBySessionid>, // another index one can key off
            boost::multi_index::member<DiameterData, std::string, &DiameterData::session_id>
          >,
          boost::multi_index::random_access<>,        //keeps insertion order
          boost::multi_index::ordered_non_unique<     //order by time
            boost::multi_index::tag<IndexByTime>, // another index one can key off
             boost::multi_index::composite_key<   //composite key required for managing the size of container
              DiameterData,
              boost::multi_index::member<DiameterData, std::string, &DiameterData::modified_date>,  //partial searches without specifying the first keys are not allowed, so make this first
              boost::multi_index::member<DiameterData, std::string, &DiameterData::modified_datetime>
            >
          >
        >
      > DiameterContainer;

      void S6aAirUpdate(S6A & s6a);

      void S6aAiaUpdate(S6A & s6a);

      std::string ShowSubscriberInfo(std::string imsi);

      std::string PrintImsiIndex();
      std::string PrintSessionIndex();
      std::string PrintIpaddrIndex();

      std::string LogTimeElapsed();

      void ManageMultiIndex();

      void EraseAll();

      static std::mutex mutex_multi_index;

   private:

      static ContainerMultiIndex *m_instance;

      DiameterContainer diameter_container;

      std::string GetCurrentTime();
      std::string GetMonthOld();
      std::string GetDate(std::string datetime);

      double EvaluateTimeDelta(std::string time_check1, std::string time_check2);
};

#endif
