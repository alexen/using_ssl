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
#include <common/logger.h>

namespace openssl {

namespace {
namespace consts {

static constexpr int ERROR = 0;
static constexpr int SUCCESS = 1;

} // namespace val
} // namespace {unnamed}

int verification_callback( int ok, X509_STORE_CTX* store )
{
     using namespace report;

     Logger( Severity::Debug ) << "verification callback called with success code " << ok;

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
     using namespace report;

     Logger( Severity::Debug ) << "finishing check with ret code " << retCode;

     if( cert )
          X509_free( cert );

     return retCode;
}


static int checkParameter( const STACK_OF( CONF_VALUE )* val, const std::string& host )
{
     using namespace report;

     Logger( Severity::Debug ) << "checking another extension";

     for( int j = 0; j < sk_CONF_VALUE_num( val ); ++j )
     {
          CONF_VALUE* nval = sk_CONF_VALUE_value( val, j );

          Logger( Severity::Debug ) << "processing value with name \"" << nval->name << "\" and value \"" << nval->value << "\"";

          if( std::string( nval->name ) == "DNS" && std::string( nval->value ) == host )
          {
               Logger( Severity::Debug ) << "successfully found";
               return consts::SUCCESS;
          }
     }

     Logger( Severity::Debug ) << "finished with error at this time";
     return consts::ERROR;
}


static STACK_OF( CONF_VALUE )* getParameter( X509_EXTENSION* ext )
{
     using namespace report;

     Logger( Severity::Debug ) << "getting parameter looking for \"subjectAltName\"";

     const std::string extstr = OBJ_nid2sn( OBJ_obj2nid( X509_EXTENSION_get_object( ext ) ) );

     Logger( Severity::Debug ) << "now we have parameter named \"" << extstr << "\"";

     if( extstr != "subjectAltName" )
     {
          Logger( Severity::Debug ) << "returning with error";
          return nullptr;
     }

     Logger( Severity::Debug ) << "getting x509v3 extension method";

     const X509V3_EXT_METHOD *meth = X509V3_EXT_get( ext );

     if( !meth )
     {
          Logger( Severity::Debug ) << "returning with error";
          return nullptr;
     }

     const unsigned char* data = ext->value->data;

     STACK_OF( CONF_VALUE )* val =
          meth->i2v(
               meth,
               meth->d2i( nullptr, &data, ext->value->length ),
               nullptr
          );

     Logger( Severity::Debug ) << "returning with parameter";

     return val;
}


static int verifyCertificateExtensions( X509* cert, const std::string& host )
{
     using namespace report;

     Logger( Severity::Debug ) << "verifying certificate with extensions";

     const int extcount = X509_get_ext_count( cert );

     if( extcount > 0 )
     {
          Logger( Severity::Debug ) << "found extensions: " << extcount;

          for( int i = 0; i < extcount; ++i )
          {
               STACK_OF( CONF_VALUE )* val = getParameter( X509_get_ext( cert, i ) );

               if( !val )
                    continue;

               if( checkParameter( val, host ) == consts::SUCCESS )
                    return consts::SUCCESS;
          }
     }

     Logger( Severity::Debug ) << "exit with error; sorry...";

     return consts::ERROR;
}


long post_connection_check( SSL* ssl, const char* host )
{
     using namespace report;

     Logger( Severity::Info ) << "perfoming post connection check";

     Logger( Severity::Debug ) << "getting peer certificate";

     X509* cert = SSL_get_peer_certificate( ssl );

     if( !cert || !host )
     {
          Logger( Severity::Debug ) << "no peer cert found or host is set to nullptr";
          return free_and_return( cert );
     }

     const int ok = verifyCertificateExtensions( cert, host );

     X509_NAME* subj = X509_get_subject_name( cert );

     char data[ 256 ] = { 0 };

     if( !ok && subj && X509_NAME_get_text_by_NID( subj, NID_commonName, data, sizeof( data ) ) )
     {
          Logger( Severity::Debug ) << "trying get hostname from common name certificate section";

          data[ sizeof( data ) - 1 ] = 0;

          Logger( Severity::Debug ) << "common name section has value \"" << data << "\"";

          if( strcasecmp( data, host ) != 0 )
          {
               Logger( Severity::Debug ) << "returning with nothing, sorry...";
               return free_and_return( cert );
          }
     }

     Logger( Severity::Debug ) << "there must bee success";

     return free_and_return( cert, SSL_get_verify_result( ssl ) );
}

} // namespace openssl
