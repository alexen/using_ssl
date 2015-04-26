///
/// client.h
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#pragma once

#include <boost/filesystem/path.hpp>
#include <openssl/ssl.h>

namespace openssl {

SSL_CTX* get_client_ctx( const boost::filesystem::path& cert );
int do_client_loop( SSL* ssl );

} // namespace openssl
