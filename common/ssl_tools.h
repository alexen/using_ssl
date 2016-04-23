///
/// ssl_tools.h
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#pragma once

#include <common/types.h>
#include <openssl/ssl.h>


namespace common {
namespace openssl {


using SslCtxUptr = common::autoclean_unique_ptr< SSL_CTX >;
using SslUptr = common::autoclean_unique_ptr< SSL >;


SslCtxUptr makeSslCtx( const SSL_METHOD *method = SSLv23_method() );

SslUptr makeSsl( const SslCtxUptr& sslCtx );


} // namespace openssl
} // namespace common
