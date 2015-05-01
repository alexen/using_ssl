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

SSL_CTX* get_server_ctx( const boost::filesystem::path& cert, const boost::filesystem::path& caFile );
int do_server_loop( SSL* ssl );
void server_thread( SSL* ssl, const std::string& clientHostname );

} // namespace openssl
