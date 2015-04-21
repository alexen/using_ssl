///
/// client.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <openssl/bio.h>

namespace openssl {

void do_client_loop( BIO* connection );

} // namespace openssl
