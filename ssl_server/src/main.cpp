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
#include <boost/program_options.hpp>

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


struct Options
{
     Options() : port( 0 ) {}

     int port;
};


Options parseCommandLine( int argc, char** argv )
{
     namespace po = boost::program_options;

     Options opts;

     po::options_description desc( "Allowed options" );
     desc.add_options()
          ( "help", "show this help" )
          ( "port,p", po::value( &opts.port )->default_value( 6001 ), "listening port" );

     po::variables_map vm;
     po::store( po::parse_command_line( argc, argv, desc ), vm );
     po::notify( vm );

     if( vm.count( "help" ) )
     {
          std::cout << desc << '\n';
          exit( 0 );
     }

     return opts;
}


int main( int argc, char** argv )
{
     const auto options = parseCommandLine( argc, argv );

     signal( SIGINT, interruptSignalHandler );
     signal( SIGTERM, interruptSignalHandler );

     try
     {
          openssl::init();

          BIO* accept =
               BIO_new_accept( const_cast< char* >( boost::lexical_cast< std::string >( options.port ).c_str() ) );

          if( !accept )
               ERROR_INTERRUPT( "error while creating server socket on port " << options.port );

          if( BIO_do_accept( accept ) <= 0 )
          {
               BIO_free( accept );
               ERROR_INTERRUPT( "error binding server socket" );
          }

          do
          {
               if( BIO_do_accept( accept ) <= 0 )
               {
                    BIO_free( accept );
                    ERROR_INTERRUPT( "error accepting connection" );
               }

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
