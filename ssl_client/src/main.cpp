///
/// main.cpp
///
/// Created on: 18 апр. 2015 г.
///     Author: alexen
///

#include <iostream>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>
#include <common/error.h>

#include "client.h"

int main()
{
     const char* const HOST_PORT = "localhost:6001";

     try
     {
          openssl::init();

          BIO* connection = BIO_new_connect( const_cast< char* >( HOST_PORT ) );

          if( !connection )
               ERROR_INTERRUPT( "cannot craete BIO connection" );

          if( BIO_do_connect( connection ) <= 0 )
               ERROR_INTERRUPT( "cannot connect to remote host " << HOST_PORT << "\n" );

          std::cout << "connection established\n";

          openssl::do_client_loop( connection );

          std::cout << "connection closed\n";

          BIO_free( connection );
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
     }

     return 0;
}
