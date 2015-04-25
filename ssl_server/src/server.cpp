///
/// server.cpp
///
/// Created on: 19 апр. 2015 г.
///     Author: alexen
///

#include "server.h"

#include <iostream>
#include <openssl/err.h>
#include <common/error.h>

namespace openssl {

void do_server_loop( BIO* connection )
{
     const int buff_size = 80;
     char buff[ buff_size ] = { 0 };

     int read = 0;

     do
     {
          for( int total_read = 0, read = 0; total_read < buff_size; total_read += read )
          {
               read = BIO_read( connection, buff + total_read, buff_size - total_read );

               if( read <= 0 )
                    break;
          }

          fwrite( buff, 1, buff_size, stdout );
     }
     while( read > 0 );
}


void server_thread( BIO* client )
{
     std::cout << "connection opened" << std::endl;

     do_server_loop( client );

     std::cout << "connection closed" << std::endl;

     ERR_remove_state( 0 );
}

} // namespace openssl

