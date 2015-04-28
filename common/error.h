///
/// error.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <sstream>
#include <openssl/err.h>

inline void error_interrupt( const char* filename, int line, const char* msg )
{
     fprintf( stderr, "SSL ERROR: [%s:%d]: %s\n", filename, line, msg );
     ERR_print_errors_fp( stderr );
     exit( -1 );
}


#define ERROR_INTERRUPT( stream ) \
     do{ \
          std::ostringstream ostr; \
          ostr << stream; \
          error_interrupt( __FILE__, __LINE__, ostr.str().c_str() ); \
     } \
     while( false )
