///
/// main.cpp
///
/// Created on: 18 апр. 2015 г.
///     Author: alexen
///

#include <unistd.h>
#include <iostream>
#include <boost/filesystem/path.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>

#include "client.h"


const boost::filesystem::path getCertFileName( int argc, char** argv )
{
     const boost::filesystem::path certFileName =
          argc > 1 ? argv[ 1 ] : getenv( "CLIENT_CERT_FILE" );

     if( certFileName.empty() )
     {
          ERROR_INTERRUPT( "no client's cert file set" );
     }
     else if( access( certFileName.c_str(), R_OK ) != 0 )
     {
          ERROR_INTERRUPT( "client's cert file \"" << certFileName << "\" can't be read" );
     }

     return certFileName;
}


int main( int argc, char** argv )
{
     try
     {
          static const char* const HOST_PORT = "localhost:6001";
          static const auto CERT_FILE = getCertFileName( argc, argv );

          openssl::init();

          BIO* connection = BIO_new_connect( const_cast< char* >( HOST_PORT ) );

          if( !connection )
          {
               ERROR_INTERRUPT( "cannot craete BIO connection" );
          }

          if( BIO_do_connect( connection ) <= 0 )
          {
               BIO_free( connection );
               ERROR_INTERRUPT( "cannot connect to remote host " << HOST_PORT << "\n" );
          }

          std::cout << "connection opened\n";

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
