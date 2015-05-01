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
#include <boost/program_options.hpp>

#include <common/init.h>
#include <common/error.h>

#include "client.h"


struct Options
{
     Options() : port( 0 ) {}

     std::string host;
     int port;
     boost::filesystem::path cert;
};


Options parseCommandLine( int argc, char** argv )
{
     namespace po = boost::program_options;

     Options opts;

     po::options_description desc( "Allowed options" );
     desc.add_options()
          ( "help", "show this help" )
          ( "host,h", po::value( &opts.host )->default_value( "localhost" ), "server host" )
          ( "port,p", po::value( &opts.port )->default_value( 6001 ), "server port" )
          ( "certificate,c", po::value( &opts.cert ), "client certificate and private key file in PEM format" );

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
     try
     {
          const auto options = parseCommandLine( argc, argv );
          const auto hostPort = options.host + ":" + boost::lexical_cast< std::string >( options.port );

          openssl::init();

          BIO* connection = BIO_new_connect( const_cast< char* >( hostPort.c_str() ) );

          if( !connection )
          {
               ERROR_INTERRUPT( "cannot craete BIO connection" );
          }

          if( BIO_do_connect( connection ) <= 0 )
          {
               BIO_free( connection );
               ERROR_INTERRUPT( "cannot connect to remote host " << hostPort << "\n" );
          }

          SSL_CTX* ctx = openssl::get_client_ctx( options.cert );
          SSL* ssl = SSL_new( ctx );

          if( !ssl )
          {
               BIO_free( connection );
               SSL_CTX_free( ctx );
               ERROR_INTERRUPT( "cannot create SSL on context" );
          }

          SSL_set_bio( ssl, connection, connection );

          if( SSL_connect( ssl ) <= 0 )
          {
               SSL_free( ssl );
               SSL_CTX_free( ctx );
               ERROR_INTERRUPT( "cannot connect to SSL" );
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
