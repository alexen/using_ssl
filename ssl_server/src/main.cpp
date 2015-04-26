///
/// main.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <boost/thread.hpp>
#include <boost/filesystem/path.hpp>

#include <common/init.h>

#include "server.h"

static bool stop = false;

void interruptSignalHandler( int signum )
{
     if( signum == SIGINT || signum == SIGTERM )
     {
          stop = true;
     }
}


const boost::filesystem::path getCertFileName( int argc, char** argv )
{
     const boost::filesystem::path certFileName =
          argc > 1 ? argv[ 1 ] : getenv( "SERVER_CERT_FILE" );

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
     signal( SIGINT, interruptSignalHandler );
     signal( SIGTERM, interruptSignalHandler );

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

          do
          {
               if( BIO_do_accept( accept ) <= 0 )
                    ERROR_INTERRUPT( "error accepting connection" );

               BIO* client = BIO_pop( accept );

               boost::thread( boost::bind( openssl::server_thread, client ) ).detach();
          }
          while( !stop );

          BIO_free( accept );
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
     }

     return 0;
}
