///
/// logger.h
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#pragma once

#include <sstream>

namespace report {

enum class Severity : int
{
     Emergency,
     Alert,
     Critical,
     Error,
     Warning,
     Notice,
     Info,
     Debug
};

class Logger
{
public:
     explicit Logger( Severity severity );
     virtual ~Logger();

     Logger( const Logger& ) = delete;
     Logger& operator=( const Logger& ) = delete;

     template< typename T >
     Logger& operator<<( const T& param )
     {
          ostr_ << param;
          return *this;
     }

private:
     const int severity_;
     std::ostringstream ostr_;
};

} // namespace report
