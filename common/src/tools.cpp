///
/// tools.cpp
///
/// Created on: 01 мая 2015 г.
///     Author: alexen
///

#include <common/tools.h>

#include <cstring>
#include <string>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

namespace openssl {

namespace {
namespace consts {

static constexpr int ERROR = 0;
static constexpr int SUCCESS = 1;

} // namespace val
} // namespace {unnamed}

int verification_callback( int ok, X509_STORE_CTX* store )
{
     if( !ok )
     {
          X509* cert = X509_STORE_CTX_get_current_cert( store );
          const int depth = X509_STORE_CTX_get_error_depth( store );
          const int err = X509_STORE_CTX_get_error( store );

          char data[ 256 ] = { 0 };

          fprintf( stderr, "error with certificate at depth: %d\n", depth );
          X509_NAME_oneline( X509_get_issuer_name( cert ), data, sizeof( data ) );
          fprintf( stderr, "\tissuer: %s\n", data );
          X509_NAME_oneline( X509_get_subject_name( cert ), data, sizeof( data ) );
          fprintf( stderr, "\tsubject: %s\n", data );
          fprintf( stderr, "\terr: %d:%s\n", err, X509_verify_cert_error_string( err ) );
     }

     return ok;
}


static long free_and_return( X509* cert, const long retCode = X509_V_ERR_APPLICATION_VERIFICATION )
{
     if( cert )
          X509_free( cert );

     return retCode;
}


static int checkParameter( const STACK_OF( CONF_VALUE )* val, const std::string& host )
{
     for( int j = 0; j < sk_CONF_VALUE_num( val ); ++j )
     {
          CONF_VALUE* nval = sk_CONF_VALUE_value( val, j );

          if( std::string( nval->name ) == "DNS" && std::string( nval->value ) == host )
          {
               return consts::SUCCESS;
          }
     }

     return consts::ERROR;
}


static STACK_OF( CONF_VALUE )* getParameter( X509_EXTENSION* ext )
{
     const std::string extstr = OBJ_nid2sn( OBJ_obj2nid( X509_EXTENSION_get_object( ext ) ) );

     if( extstr != "subjectAltName" )
          return nullptr;

     const X509V3_EXT_METHOD *meth = X509V3_EXT_get( ext );

     if( !meth )
          return nullptr;

     const unsigned char* data = ext->value->data;

     STACK_OF( CONF_VALUE )* val =
          meth->i2v(
               meth,
               meth->d2i( nullptr, &data, ext->value->length ),
               nullptr
          );

     return val;
}


static int verifyCertificateExtensions( X509* cert, const std::string& host )
{
     const int extcount = X509_get_ext_count( cert );

     if( extcount > 0 )
     {
          for( int i = 0; i < extcount; ++i )
          {
               STACK_OF( CONF_VALUE )* val = getParameter( X509_get_ext( cert, i ) );

               if( !val )
                    continue;

               if( checkParameter( val, host ) == consts::SUCCESS )
                    return consts::SUCCESS;
          }
     }

     return consts::ERROR;
}


long post_connection_check( SSL* ssl, const char* host )
{
     X509* cert = SSL_get_peer_certificate( ssl );

     if( !cert || !host )
          return free_and_return( cert );

     const int ok = verifyCertificateExtensions( cert, host );

     X509_NAME* subj = X509_get_subject_name( cert );

     char data[ 256 ] = { 0 };

     if( !ok && subj && X509_NAME_get_text_by_NID( subj, NID_commonName, data, sizeof( data ) ) )
     {
          data[ sizeof( data ) - 1 ] = 0;

          if( strcasecmp( data, host ) != 0 )
               return free_and_return( cert );
     }

     return free_and_return( cert, SSL_get_verify_result( ssl ) );
}

} // namespace openssl
