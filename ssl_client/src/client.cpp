///
/// client.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "client.h"

#include <cstring>
#include <openssl/ssl.h>

#include <common/error.h>

namespace openssl {

SSL_CTX* setup_client_ctx()
{
     static const char* const CERTFILE = "client.pem";

     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );

     if( SSL_CTX_use_certificate_chain_file( ctx, CERTFILE ) != 1 )
     {
          ERROR_INTERRUPT( "cannot load certificate chain from file " << CERTFILE );
     }

     if( SSL_CTX_use_PrivateKey_file( ctx, CERTFILE, SSL_FILETYPE_PEM ) != 1 )
     {
          ERROR_INTERRUPT( "cannot load private key from file " << CERTFILE );
     }

     return ctx;
}


int do_client_loop( SSL* ssl )
{
     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     while( true )
     {
          if( !fgets( buff, buff_size, stdin ) )
               break;

          for( int total_written = 0, written = 0; total_written < buff_size; total_written += written )
          {
               written = SSL_write( ssl, buff + total_written, strlen( buff ) - total_written );

               if( written <= 0 )
                    return 0;
          }
     }

     return 1;
}

} // namespace openssl
