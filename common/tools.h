///
/// tools.h
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#pragma once
#include <openssl/ossl_typ.h>

namespace openssl {

static int verification_callback( int ok, X509_STORE_CTX* store )
{
     if( !ok )
     {
          X509* cert = X509_STORE_CTX_get_current_cert( store );
          const int depth = X509_STORE_CTX_get_error_depth( store );
          const int err = X509_STORE_CTX_get_error( store );

          char data[ 256 ] = { 0 };

          fprintf( stderr, "error with certificate at depth: %d\n", depth );
          X509_NAME_oneline( X509_get_issuer_name( cert ), data, sizeof( data ) );
          fprintf( stderr, "\tissuer: %s\n", data );
          X509_NAME_oneline( X509_get_subject_name( cert ), data, sizeof( data ) );
          fprintf( stderr,"\tsubject: %s\n", data );
          fprintf( stderr, "\terr: %d:%s\n", err, X509_verify_cert_error_string( err ) );
     }

     return ok;
}

} // namespace openssl
