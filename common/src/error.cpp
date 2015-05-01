///
/// error.cpp
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#include <common/error.h>

#include <openssl/err.h>

namespace openssl {

void error_interrupt( const char* filename, int line, const char* msg )
{
     fprintf( stderr, "SSL ERROR: [%s:%d]: %s\n", filename, line, msg );
     ERR_print_errors_fp( stderr );
     exit( -1 );
}

} // namespace openssl
