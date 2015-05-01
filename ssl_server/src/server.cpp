///
/// server.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "server.h"

#include <iostream>
#include <openssl/err.h>
#include <common/error.h>
#include <common/tools.h>

namespace openssl {

SSL_CTX* get_server_ctx( const boost::filesystem::path& cert, const boost::filesystem::path& caFile )
{
     static constexpr int SUCCESS = 1;

     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );

     if( !ctx )
          ERROR_INTERRUPT( "cannot create SSL context" );

     if( SSL_CTX_load_verify_locations( ctx, caFile.c_str(), nullptr ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load CA file " << caFile );

     if( SSL_CTX_set_default_verify_paths( ctx ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load default CA paths" );

     if( SSL_CTX_use_certificate_chain_file( ctx, cert.c_str() ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load certificate from file " << cert );

     if( SSL_CTX_use_PrivateKey_file( ctx, cert.c_str(), SSL_FILETYPE_PEM ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load private key from file " << cert );

     SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, openssl::verification_callback );
     SSL_CTX_set_verify_depth( ctx, 4 );

     return ctx;
}


int do_server_loop( SSL* ssl )
{
     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     int read = 0;

     do
     {
          for( int total_read = 0, read = 0; total_read < buff_size; total_read += read )
          {
               read = SSL_read( ssl, buff + total_read, buff_size - total_read );

               if( read <= 0 )
                    break;
          }

          fwrite( buff, 1, buff_size, stdout );
     }
     while( read > 0 );

     return ( SSL_get_shutdown( ssl ) & SSL_RECEIVED_SHUTDOWN ) ? 1 : 0;
}


void server_thread( SSL* ssl, const std::string& clientHostname )
{
     if( SSL_accept( ssl ) <= 0 )
          ERROR_INTERRUPT( "cannot accept SSL connection" );

     const long err = post_connection_check( ssl, clientHostname.c_str() );

     if( err != X509_V_OK )
          ERROR_INTERRUPT( "error checking SSL object after connection: "
               << X509_verify_cert_error_string( err ) );

     std::cout << "SSL connection opened" << std::endl;

     if( do_server_loop( ssl ) )
     {
          SSL_shutdown( ssl );
     }
     else
     {
          SSL_clear( ssl );
     }

     std::cout << "SSL connection closed" << std::endl;

     SSL_free( ssl );

     ERR_remove_state( 0 );
}

} // namespace openssl

