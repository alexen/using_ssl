///
/// client.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <openssl/ssl.h>

namespace openssl {

SSL_CTX* setup_client_ctx();
int do_client_loop( SSL* ssl );

} // namespace openssl
