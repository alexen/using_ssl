///
/// main.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include <iostream>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>
#include <common/error.h>

#include "server.h"

int main()
{
     pthread_t tid;

     try
     {
          const char* const PORT = "6001";

          openssl::init();

          BIO* accept = BIO_new_accept( const_cast< char* >( PORT ) );

          if( !accept )
               ERROR_INTERRUPT( "error while creating server socket on port " << PORT );

          if( BIO_do_accept( accept ) <= 0 )
               ERROR_INTERRUPT( "error binding server socket" );

          while( true )
          {
               if( BIO_do_accept( accept ) <= 0 )
                    ERROR_INTERRUPT( "error accepting connection" );

               BIO* client = BIO_pop( accept );
               pthread_create( &tid, nullptr, openssl::server_thread, client );
          }

          BIO_free( accept );
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
     }
}

