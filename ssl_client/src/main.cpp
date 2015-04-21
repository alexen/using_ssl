///
/// main.cpp
///
/// Created on: 18 апр. 2015 г.
///     Author: alexen
///

#include <iostream>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>

#include "client.h"

int main()
{
     static const char* const HOST_PORT = "localhost:6001";

     try
     {
          openssl::init();

          SSL_CTX* ctx = openssl::setup_client_ctx();

          BIO* connection = BIO_new_connect( const_cast< char* >( HOST_PORT ) );

          if( !connection )
               ERROR_INTERRUPT( "cannot craete BIO connection" );

          if( BIO_do_connect( connection ) <= 0 )
               ERROR_INTERRUPT( "cannot connect to remote host " << HOST_PORT << "\n" );

          SSL* ssl = SSL_new( ctx );

          if( !ssl )
          {
               ERROR_INTERRUPT( "cannot create SSL context" );
          }

          SSL_set_bio( ssl, connection, connection );

          if( SSL_connect( ssl ) <= 0 )
          {
               ERROR_INTERRUPT( "cannot connecting SSL object" );
          }

          std::cout << "SSL connection opened\n";

          if( openssl::do_client_loop( ssl ) )
          {
               SSL_shutdown( ssl );
          }
          else
          {
               SSL_clear( ssl );
          }

          std::cout << "SSL connection closed\n";

          SSL_free( ssl );
          SSL_CTX_free( ctx );
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
     }

     return 0;
}
