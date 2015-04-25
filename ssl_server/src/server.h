///
/// server.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <boost/filesystem/path.hpp>
#include <openssl/ssl.h>

namespace openssl {

void do_server_loop( BIO* connection );
void server_thread( BIO* client );

} // namespace openssl
