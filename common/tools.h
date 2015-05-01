///
/// tools.h
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#pragma once

#include <openssl/ossl_typ.h>

namespace openssl {

int verification_callback( int ok, X509_STORE_CTX* store );
long post_connection_check( SSL* ssl, const char* host );

} // namespace openssl
