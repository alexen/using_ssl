///
/// client.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "client.h"

#include <cstring>
#include <boost/thread.hpp>
#include <common/error.h>
#include <common/tools.h>
#include <common/logger.h>

namespace openssl {

SSL_CTX* get_client_ctx( const boost::filesystem::path& cert, const boost::filesystem::path& caFile )
{
     using namespace report;

     static constexpr int SUCCESS = 1;

     Logger( Severity::Info ) << "initializing SSL context";

     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );

     if( !ctx )
          ERROR_INTERRUPT( "cannot initialize SSL context" );

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

     SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, verification_callback );
     SSL_CTX_set_verify_depth( ctx, 4 );

     Logger( Severity::Info ) << "SSL context successfully initialized";

     return ctx;
}


int do_client_loop( SSL* ssl )
{
     using namespace report;

     Logger( Severity::Info ) << "running client main loop";

     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     while( true )
     {
          if( !fgets( buff, buff_size, stdin ) )
               break;

          for( int total_written = 0, written = 0; total_written < buff_size; total_written += written )
          {
               Logger( Severity::Debug )
                    << "write to SSL connection, total written " << total_written << " bytes";

               written = SSL_write( ssl, buff + total_written, strlen( buff ) - total_written );

               Logger( Severity::Debug )
                    << "written " << written << " bytes";

               if( written <= 0 )
               {
                    Logger( Severity::Info ) << "client loop finished";
                    return 0;
               }
          }
     }

     Logger( Severity::Info ) << "client loop finished";

     return 1;
}

} // namespace openssl
