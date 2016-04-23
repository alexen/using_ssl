///
/// bio_tools.h
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#pragma once

#include <common/types.h>
#include <openssl/bio.h>


namespace common {
namespace openssl {


using BioUptr = autoclean_unique_ptr< BIO, int >;


BioUptr makeBioConnection( const std::string& hostPort );
BioUptr makeBioSocket();


} // namespace openssl
} // namespace common
