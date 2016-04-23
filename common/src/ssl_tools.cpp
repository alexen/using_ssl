///
/// ssl_tools.cpp
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#include <common/ssl_tools.h>

#include <boost/throw_exception.hpp>

namespace common {
namespace openssl {

SslCtxUptr makeSslCtx( const SSL_METHOD *method )
{
     auto ctx = SSL_CTX_new( method );

     if( !ctx )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot create SSL context" ) );

     return SslCtxUptr( ctx, SSL_CTX_free );
}


SslUptr makeSsl( const SslCtxUptr& sslCtx )
{
     auto ssl = SSL_new( sslCtx.get() );

     if( !ssl )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot create SSL" ) );

     return SslUptr( ssl, SSL_free );
}


} // namespace openssl
} // namespace common
