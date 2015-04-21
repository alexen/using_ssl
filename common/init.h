///
/// ssl_init.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <openssl/ssl.h>

namespace openssl {

static void init()
{
     if( !SSL_library_init() )
     {
          fprintf( stderr, "SSL ERROR: openssl initialization failed\n" );
          exit( -1 );
     }

     SSL_load_error_strings();
}

} // namespace openssl
