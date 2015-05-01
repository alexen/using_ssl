///
/// server.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "server.h"

#include <iostream>
#include <boost/thread.hpp>
#include <openssl/err.h>
#include <common/error.h>
#include <common/tools.h>
#include <common/logger.h>

namespace openssl {

SSL_CTX* get_server_ctx( const boost::filesystem::path& cert, const boost::filesystem::path& caFile )
{
     using namespace report;

     static constexpr int SUCCESS = 1;

     Logger( Severity::Info ) << "initializing SSL context";

     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );

     if( !ctx )
          ERROR_INTERRUPT( "cannot create SSL context" );

     Logger( Severity::Debug ) << "loading SSL verify locations with file " << caFile;

     if( SSL_CTX_load_verify_locations( ctx, caFile.c_str(), nullptr ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load CA file " << caFile );

     Logger( Severity::Debug ) << "loading SSL default verify paths";

     if( SSL_CTX_set_default_verify_paths( ctx ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load default CA paths" );

     Logger( Severity::Debug ) << "setting certificate chain file " << cert;

     if( SSL_CTX_use_certificate_chain_file( ctx, cert.c_str() ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load certificate from file " << cert );

     Logger( Severity::Debug ) << "loading private key from file" << cert;

     if( SSL_CTX_use_PrivateKey_file( ctx, cert.c_str(), SSL_FILETYPE_PEM ) != SUCCESS )
          ERROR_INTERRUPT( "cannot load private key from file " << cert );

     Logger( Severity::Debug ) << "setting verification parameters, verification callback and verification depth";

     SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, openssl::verification_callback );
     SSL_CTX_set_verify_depth( ctx, 4 );

     Logger( Severity::Info ) << "SSL context successfully initialized";

     return ctx;
}


int do_server_loop( SSL* ssl )
{
     using namespace report;

     Logger( Severity::Info ) << "[thread: " << boost::this_thread::get_id() << "] " << "running server main loop";

     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     int read = 0;

     do
     {
          for( int total_read = 0, read = 0; total_read < buff_size; total_read += read )
          {
               Logger( Severity::Debug )
                    << "[thread: " << boost::this_thread::get_id() << "] "
                    << "read from SSL connection, total read " << total_read << " bytes";

               read = SSL_read( ssl, buff + total_read, buff_size - total_read );

               Logger( Severity::Debug )
                    << "[thread: " << boost::this_thread::get_id() << "] "
                    << "read " << read << " bytes";

               if( read <= 0 )
                    break;
          }

          Logger( Severity::Debug )
               << "[thread: " << boost::this_thread::get_id() << "] "
               << "writing buffer to stdout";

          fwrite( buff, 1, buff_size, stdout );
     }
     while( read > 0 );

     Logger( Severity::Info ) << "[thread: " << boost::this_thread::get_id() << "] " << "server loop finished";

     return ( SSL_get_shutdown( ssl ) & SSL_RECEIVED_SHUTDOWN ) ? 1 : 0;
}


void server_thread( SSL* ssl, const std::string& clientHostname )
{
     using namespace report;

     Logger( Severity::Info ) << "[thread: " << boost::this_thread::get_id() << "] " << "starting server thread";

     if( SSL_accept( ssl ) <= 0 )
          ERROR_INTERRUPT( "cannot accept SSL connection" );

     Logger( Severity::Debug ) << "[thread: " << boost::this_thread::get_id() << "] " << "performing post connection check";

     const long err = post_connection_check( ssl, clientHostname.c_str() );

     if( err != X509_V_OK )
          ERROR_INTERRUPT( "error checking SSL object after connection: "
               << X509_verify_cert_error_string( err ) );

     std::cout << "SSL connection opened" << std::endl;

     if( do_server_loop( ssl ) )
     {
          Logger( Severity::Debug ) << "[thread: " << boost::this_thread::get_id() << "] " << "shutdown SSL connection";
          SSL_shutdown( ssl );
     }
     else
     {
          Logger( Severity::Debug ) << "[thread: " << boost::this_thread::get_id() << "] " << "clearing SSL connection";
          SSL_clear( ssl );
     }

     std::cout << "SSL connection closed" << std::endl;

     SSL_free( ssl );

     ERR_remove_state( 0 );

     Logger( Severity::Info ) << "[thread: " << boost::this_thread::get_id() << "] " << "server thread finshed";
}

} // namespace openssl

