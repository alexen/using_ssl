///
/// certificate.cpp
///
/// Created on: 22 марта 2015 г.
///     Author: alexen
///

#include "certificate.h"

#include <boost/assert.hpp>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

namespace openssl {

namespace {
namespace aux {

autoclean_unique_ptr< X509 > make_x509( X509* cert )
{
     auto ptr = autoclean_unique_ptr< X509 >( cert, X509_free );

     BOOST_ASSERT( !!ptr );

     return ptr;
}


autoclean_unique_ptr< X509 > make_x509_from_der( const char* data, std::size_t len )
{
     return make_x509( d2i_X509( nullptr, (const unsigned char **) &data, len ) );
}


autoclean_unique_ptr< X509 > make_x509_from_pem( const char* data, std::size_t len )
{
     autoclean_unique_ptr< BIO, int > certBio( BIO_new( BIO_s_mem() ), BIO_free );

     BIO_write( certBio.get(), data, len );

     return make_x509( PEM_read_bio_X509( certBio.get(), nullptr, nullptr, nullptr ) );
}


autoclean_unique_ptr< FILE, int > getFileStream( const boost::filesystem::path& filePath, const std::string& openMode )
{
     auto ptr = autoclean_unique_ptr< FILE, int >( fopen( filePath.c_str(), openMode.c_str() ), fclose );

     if( !ptr )
          BOOST_THROW_EXCEPTION( std::runtime_error( "cannot open file '" + filePath.string() + "'" ) );

     return ptr;
}


autoclean_unique_ptr< X509 > make_x509_from_pem_file( const boost::filesystem::path& filePath )
{
     return make_x509( PEM_read_X509( getFileStream( filePath.c_str(), "r" ).get(), nullptr, nullptr, nullptr ) );
}


std::pair< const EVP_MD*, int > getAppropriateDigest( const Certificate::FingerprintType fp )
{
     switch( fp )
     {
          case Certificate::FingerprintType::SHA1:
               return std::make_pair( EVP_sha1(), SHA_DIGEST_LENGTH );

          case Certificate::FingerprintType::SHA256:
               return std::make_pair( EVP_sha256(), SHA256_DIGEST_LENGTH );

          case Certificate::FingerprintType::MD5:
               return std::make_pair( EVP_md5(), MD5_DIGEST_LENGTH );

          default:
               /* unreachable code */;
     }

     BOOST_THROW_EXCEPTION( std::runtime_error( "unreachable code" ) );
     return std::make_pair( nullptr, 0 );
}

} // namespace aux
} // namespace {unnamed}


Certificate::Format::Pem_t Certificate::Format::Pem;
Certificate::Format::Der_t Certificate::Format::Der;


Certificate::Certificate( const boost::filesystem::path& certFile, const Format::Pem_t& )
     : certificate_( aux::make_x509_from_pem_file( certFile ) )
{}


Certificate::Certificate( const Buffer& buffer, const Format::Pem_t& format )
     : Certificate( buffer.data(), buffer.size(), format )
{}


Certificate::Certificate( const Buffer& buffer, const Format::Der_t& format )
     : Certificate( buffer.data(), buffer.size(), format )
{}


Certificate::Certificate( const char* data, std::size_t len, const Format::Pem_t& )
     : certificate_( aux::make_x509_from_pem( data, len ) )
{}


Certificate::Certificate( const char* data, std::size_t len, const Format::Der_t& )
     : certificate_( aux::make_x509_from_der( data, len ) )
{}


std::string Certificate::subject() const
{
     autoclean_unique_ptr< char, void, void* > subj(
          X509_NAME_oneline( X509_get_subject_name( certificate_.get() ), nullptr, 0 ),
          CRYPTO_free
     );

     return std::string( subj.get() );
}


std::string Certificate::issuer() const
{
     autoclean_unique_ptr< char, void, void* > iss(
          X509_NAME_oneline( X509_get_issuer_name( certificate_.get() ), nullptr, 0 ),
          CRYPTO_free
     );

     return std::string( iss.get() );
}


Buffer Certificate::serial() const
{
     auto serialBn =
          autoclean_unique_ptr< BIGNUM >( ASN1_INTEGER_to_BN( X509_get_serialNumber( certificate_.get() ), nullptr ), BN_free );

     unsigned char buffer[ 128 ] = { 0 };

     const auto size = BN_bn2bin( serialBn.get(), buffer );

     return Buffer( buffer, buffer + size );
}


Buffer Certificate::fingerprint( const FingerprintType fp ) const
{
     const auto data = aux::getAppropriateDigest( fp );

     Buffer buff( data.second );

     unsigned len = 0;

     const int rc = X509_digest( certificate_.get(), data.first, ( unsigned char *) &buff[ 0 ], &len );

     if( rc == 0 || len != buff.size() )
          BOOST_THROW_EXCEPTION( std::runtime_error( "X509_digest failed" ) );

     return buff;
}


int toInt( const char c )
{
     BOOST_ASSERT( std::isdigit( c ) );
     return c - '0';
}


template< typename Iterator >
int toInt( Iterator first, Iterator last )
{
     int res = 0;

     while( first != last )
          res = res * 10 + toInt( *first++ );

     return res;
}


int toIntWithStep( const char** curr, std::size_t offset )
{
     const int val = toInt( *curr, *curr + offset );

     *curr += offset;

     return val;
}


boost::posix_time::ptime toPtime( ASN1_TIME* time )
{
     const char* data = ( const char* ) time->data;
     const std::size_t size = time->length;

     const int year = toIntWithStep( &data, ( size == 13 ? 2 : 4 ) ) + ( size == 13 ? 2000 : 0 );
     const int month = toIntWithStep( &data, 2 );
     const int day = toIntWithStep( &data, 2 );

     const int hour = toIntWithStep( &data, 2 );
     const int min = toIntWithStep( &data, 2 );
     const int sec = toIntWithStep( &data, 2 );

     boost::gregorian::date d( year, month, day );
     boost::posix_time::time_duration td( hour, sec, min );

     return boost::posix_time::ptime( d, td );
}


boost::posix_time::ptime Certificate::validNotBefore() const
{
     return toPtime( X509_get_notBefore( certificate_.get() ) );
}


boost::posix_time::ptime Certificate::validNotAfter() const
{
     return toPtime( X509_get_notAfter( certificate_.get() ) );
}

} // namespace openssl
