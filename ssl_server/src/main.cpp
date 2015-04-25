///
/// main.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include <unistd.h>
#include <iostream>
#include <boost/thread.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>
#include <common/error.h>

#include "server.h"


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
          const char* const PORT = "6001";
          const auto certFile = getCertFileName( argc, argv );

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

               boost::thread( boost::bind( openssl::server_thread, client ) ).detach();
          }
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
     }
}

