///
/// certificate.h
///
/// Created on: 22 марта 2015 г.
///     Author: alexen
///

#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

#include <vector>
#include <memory>

#include <boost/filesystem/path.hpp>
#include <boost/date_time/posix_time/ptime.hpp>

#include <openssl/x509.h>

using Buffer = std::vector< char >;

template< typename T, typename RetT, typename ArgT >
using deleter_of = RetT(*)( ArgT );

template< typename T, typename DeleterRetT = void, typename DeleterArgT = T* >
using autoclean_unique_ptr = std::unique_ptr< T, deleter_of< T, DeleterRetT, DeleterArgT > >;

namespace openssl {

class Certificate
{
     struct PemFormat_t {};
     struct DerFormat_t {};

public:
     struct Format
     {
          struct Pem_t {};
          struct Der_t {};

          static Pem_t Pem;
          static Der_t Der;
     };

     enum class FingerprintType
     {
          SHA1, SHA256, MD5
     };

     static PemFormat_t Pem;
     static DerFormat_t Der;

     Certificate( const boost::filesystem::path& certFile, const Format::Pem_t& );

     Certificate( const Buffer& buffer, const Format::Pem_t& );
     Certificate( const Buffer& buffer, const Format::Der_t& );

     Certificate( const char* data, std::size_t len, const Format::Pem_t& );
     Certificate( const char* data, std::size_t len, const Format::Der_t& );

     Certificate( const Certificate& ) = delete;
     Certificate& operator=( const Certificate& ) = delete;

     Certificate( Certificate&& ) = default;
     Certificate& operator=( Certificate&& ) = default;

     std::string subject() const;
     std::string issuer() const;

     Buffer serial() const;
     Buffer fingerprint( const FingerprintType ) const;

     boost::posix_time::ptime validNotBefore() const;
     boost::posix_time::ptime validNotAfter() const;

private:
     autoclean_unique_ptr< X509 > certificate_;
};

} // namespace openssl

#endif // CERTIFICATE_H_
