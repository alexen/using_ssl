///
/// main.cpp
///
/// Created on: 21 марта 2015 г.
///     Author: alexen
///

#include <stdexcept>
#include <iostream>
#include <memory>

#include <boost/assert.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/tokenizer.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "certificate.h"

std::string toHex( const char* data, const std::size_t size )
{
     static const char* const arr = "0123456789abcdef";

     std::string ret( size * 2, '\0' );

     for( std::size_t i = 0, j = 0; i < size; ++i, j += 2 )
     {
          ret[ j ] = arr[ ( data[ i ] & 0xf0 ) >> 4 ];
          ret[ j+1 ] = arr[ data[ i ] & 0x0f ];
     }

     return ret;
}


std::string toHex( const Buffer& buff )
{
     return toHex( buff.data(), buff.size() );
}


bool isEven( unsigned n )
{
     return ( n % 2 ) == 0;
}


std::string prettyViewHex( const std::string& hex )
{
     std::string pvh( hex.length() + hex.length() / 2 - 1, '\0' );

     for( unsigned srcIdx = 0, dstIdx = 0; srcIdx < hex.length(); ++srcIdx, ++dstIdx )
     {
          pvh[ dstIdx ] = hex[ srcIdx ];

          if( isEven( srcIdx + 1 ) )
          {
               pvh[ ++dstIdx ] = ':';
          }
     }

     return pvh;
}


std::pair< std::string, std::string > split( const std::string& token )
{
     const auto index = token.find( '=' );

     if( index == std::string::npos )
          return std::make_pair( token, "" );

     return std::make_pair( token.substr( 0, index ), token.substr( index + 1, token.length() - index - 1 ) );
}


std::map< std::string, std::string > parse( const std::string& str )
{
     using tokenizer = boost::tokenizer< boost::char_separator< char > >;
     boost::char_separator< char > sep( "/" );

     tokenizer tokens( str, sep );

     std::map< std::string, std::string > res;

     for( tokenizer::const_iterator tok = tokens.begin(); tok != tokens.end(); ++tok )
          res.insert( split( *tok ) );

     return res;
}


void printParams( const std::map< std::string, std::string >& params )
{
     for( const auto& each: params )
          std::cout << each.first << " = " << each.second << '\n';
}


int main()
{
     try
     {
//          openssl::Certificate cert( "/home/alexen/gulaev.pem", openssl::Certificate::Format::Pem );
          openssl::Certificate cert( "/home/alexen/volopaev_fp_cert.pem", openssl::Certificate::Format::Pem );

          std::cout
               << "Subject: " << cert.subject() << '\n'
               << "Issuer: " << cert.issuer() << '\n'
               << "Serial: " << prettyViewHex( toHex( cert.serial() ) ) << '\n'
               << "Fingerprints:\n"
               << "\tSHA256: " << prettyViewHex( toHex( cert.fingerprint( openssl::Certificate::FingerprintType::SHA256 ) ) ) << '\n'
               << "\tSHA1: " << prettyViewHex( toHex( cert.fingerprint( openssl::Certificate::FingerprintType::SHA1 ) ) ) << '\n'
               << "\tMD5: " << prettyViewHex( toHex( cert.fingerprint( openssl::Certificate::FingerprintType::MD5 ) ) ) << '\n'
               << "Valid:\n"
               << "\tnot before: " << cert.validNotBefore() << '\n'
               << "\tnot after: " << cert.validNotAfter() << '\n'
               ;
     }
     catch( const std::exception& e )
     {
          std::cerr << "exception: " << e.what() << '\n';
          return 1;
     }

     return 0;
}
