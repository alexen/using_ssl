///
/// logger.cpp
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#include <common/logger.h>

#include <syslog.h>
#include <stdexcept>
#include <type_traits>
#include <boost/throw_exception.hpp>
#include <boost/lexical_cast.hpp>

namespace report {

namespace {
namespace aux {

inline int toSyslogSeverity( Severity severity )
{
     switch( severity )
     {
          case Severity::Emergency:     return LOG_EMERG;
          case Severity::Alert:         return LOG_ALERT;
          case Severity::Critical:      return LOG_CRIT;
          case Severity::Error:         return LOG_ERR;
          case Severity::Warning:       return LOG_WARNING;
          case Severity::Notice:        return LOG_NOTICE;
          case Severity::Info:          return LOG_INFO;
          case Severity::Debug:         return LOG_DEBUG;
     }

     BOOST_THROW_EXCEPTION(
          std::runtime_error( "bad severity type with code "
          + boost::lexical_cast< std::string >(
               static_cast< typename std::underlying_type< Severity >::type >( severity ) ) ) );
     return -1;
}

} // namespace aux
} // namespace {unnamed}


Logger::Logger( Severity severity )
     : severity_( aux::toSyslogSeverity( severity ) )
{
}


Logger::~Logger()
{
     syslog( severity_, "%s", ostr_.str().c_str() );
}

} // namespace report
