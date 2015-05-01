///
/// error.cpp
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#include <common/error.h>

#include <openssl/err.h>
#include <common/logger.h>

namespace openssl {

void error_interrupt( const char* filename, int line, const char* msg )
{
     report::Logger( report::Severity::Error ) << "SSL error [" << filename << ":" << line << "]: " << msg;

     fprintf( stderr, "SSL ERROR: [%s:%d]: %s\n", filename, line, msg );
     ERR_print_errors_fp( stderr );
     exit( -1 );
}

} // namespace openssl
