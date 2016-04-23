///
/// main.cpp
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#include <cstdlib>
#include <stdexcept>
#include <iostream>

#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <common/init.h>
#include <common/types.h>
#include <common/bio_tools.h>
#include <common/ssl_tools.h>


struct Options
{
     std::string pop3Url;
     std::string smtpUrl;
     std::string login;
     std::string password;

     using Validator = boost::function< void( const Options& ) >;

     static Options parse( int argc, char** argv, Validator&& validate );
};


Options Options::parse( int argc, char** argv, Validator&& validate )
{
     namespace po = boost::program_options;

     Options opts;

     po::options_description desc( "Allowed options" );
     desc.add_options()
          ( "help", "show this help" )
          ( "pop3", po::value< std::string >( &opts.pop3Url ), "POP-server address (HOST:PORT)" )
          ( "smtp", po::value< std::string >( &opts.smtpUrl ), "SMTP-server address (HOST:PORT)" )
          ( "login", po::value<>( &opts.login ), "mailbox auth login" )
          ( "password", po::value<>( &opts.password ), "mailbox auth password" )
     ;

     po::variables_map vm;
     po::store( po::parse_command_line( argc, argv, desc ), vm );
     po::notify( vm );

     if( vm.count( "help" ) )
     {
          std::cout << desc << '\n';
          exit( EXIT_SUCCESS );
     }

     validate( opts );

     return opts;
}


std::string sendCommand( const common::openssl::BioUptr& connection, const common::openssl::BioUptr& readSocket, const std::string& command )
{
     if( BIO_puts( connection.get(), command.c_str() ) <= 0 )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot write command " + command ) );

     char response[ 1024 ] = { 0 };

     const auto ret = BIO_gets( readSocket.get(), response, sizeof( response ) );

     if( ret <= 0 )
     {
          std::cout << "RET: " << ret << "; RESP: " << response << '\n';
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot read command response " + command ) );
     }

     return std::string( response );
}


void getMail( const std::string& pop3Url, const std::string& login, const std::string& password )
{
     auto connection = common::openssl::makeBioConnection( pop3Url );

     if( BIO_do_connect( connection.get() ) <= 0 )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot connect to remote host " + pop3Url ) );

     auto sslCtx = common::openssl::makeSslCtx();
     auto ssl = common::openssl::makeSsl( sslCtx );

     auto readSock = common::openssl::makeBioSocket();
     BIO_do_connect( readSock.get() );

     SSL_set_bio( ssl.get(), readSock.get(), connection.get() );

     auto response = sendCommand( connection, readSock, "user " + login );

     std::cout << "RESP: " << response << '\n';

     response = sendCommand( connection, readSock, "pass " + password );

     std::cout << "RESP: " << response << '\n';
}


int main( int argc, char** argv )
{
     try
     {
          const auto inputValidator =
               []( const Options& opts )
               {
                    if( opts.pop3Url.empty() && opts.smtpUrl.empty() )
                         BOOST_THROW_EXCEPTION( std::runtime_error( "pop3 or smtp connections parameters required" ) );

                    if( opts.login.empty() )
                         BOOST_THROW_EXCEPTION( std::runtime_error( "login required" ) );

                    if( opts.password.empty() )
                         BOOST_THROW_EXCEPTION( std::runtime_error( "password required" ) );
               };

          const auto opts = Options::parse( argc, argv, inputValidator );

          openssl::init();

          if( !opts.pop3Url.empty() )
               getMail( opts.pop3Url, opts.login, opts.password );
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << boost::diagnostic_information( e ) << '\n';
          return 1;
     }

     return 0;
}
