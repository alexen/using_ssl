///
/// client.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "client.h"

#include <cstring>

namespace openssl {

void do_client_loop( BIO* connection )
{
     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     while( true )
     {
          if( !fgets( buff, buff_size, stdin ) )
               break;

          for( int total_written = 0, written = 0; total_written < buff_size; total_written += written )
          {
               written = BIO_write( connection, buff + total_written, strlen( buff ) - total_written );

               if( written <= 0 )
                    return;
          }
     }
}

} // namespace openssl
