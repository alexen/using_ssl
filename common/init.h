///
/// ssl_init.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "error.h"

namespace openssl {

static void seed_prng( int bytes = 4098 )
{
     if( !RAND_load_file( "/dev/urandom", bytes ) )
     {
          ERROR_INTERRUPT( "cannot read " << bytes << " bytes from \"/dev/urandom\"" );
     }
}


static void init()
{
     if( !SSL_library_init() )
     {
          ERROR_INTERRUPT( "cannot initialize SSL library" );
     }

     SSL_load_error_strings();

     seed_prng();
}

} // namespace openssl
