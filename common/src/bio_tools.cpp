///
/// bio_tools.cpp
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#include <common/bio_tools.h>

#include <boost/throw_exception.hpp>

namespace common {
namespace openssl {


BioUptr makeBioConnection( const std::string& hostPort )
{
     auto conn = BIO_new_connect( const_cast< char* >( hostPort.c_str() ) );

     if( !conn )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot create connection to " + hostPort ) );

     return BioUptr( conn, BIO_free );
}


BioUptr makeBioSocket()
{
     auto sock = BIO_new( BIO_s_socket() );
     if( !sock )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot create BIO socket" ) );
     return BioUptr( sock, BIO_free );
}


} // namespace openssl
} // namespace common
