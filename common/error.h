///
/// error.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <sstream>

#define ERROR_INTERRUPT( stream ) \
     do{ \
          std::ostringstream ostr; \
          ostr << stream; \
          ::openssl::error_interrupt( __FILE__, __LINE__, ostr.str().c_str() ); \
     } \
     while( false )


namespace openssl {

void error_interrupt( const char* filename, int line, const char* msg );

} // namespace openssl
