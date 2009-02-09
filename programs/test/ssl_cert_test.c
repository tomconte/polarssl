/*
 *  SSL certificate functionality tests
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/certs.h"
#include "polarssl/x509.h"

#define MAX_CLIENT_CERTS	6

char *client_certificates[MAX_CLIENT_CERTS] =
{
	"client1.crt",
	"client2.crt",
	"cert_sha224.crt",
	"cert_sha256.crt",
	"cert_sha384.crt",
	"cert_sha512.crt"
};

int main( void )
{
    int ret, i;
    x509_cert cacert, clicert;

    /*
     * 1.1. Load the trusted CA
     */
    printf( "\n  . Loading the CA root certificate ..." );
    fflush( stdout );

    memset( &cacert, 0, sizeof( x509_cert ) );

    /*
     * Alternatively, you may load the CA certificates from a .pem or
     * .crt file by calling x509parse_crtfile( &cacert, "myca.crt" ).
     */
    ret = x509parse_crtfile( &cacert, "ssl/test-ca/test-ca.crt" );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crtfile returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    for( i = 0; i < MAX_CLIENT_CERTS; i++ )
    {
        /*
         * 1.2. Load own certificate and private key
         */
	char	name[512];
	snprintf(name, 512, "ssl/test-ca/%s", client_certificates[i]);

        printf( "  . Loading the client certificatei %s...", name );
        fflush( stdout );

        memset( &clicert, 0, sizeof( x509_cert ) );

        ret = x509parse_crtfile( &clicert, name );
	if( ret != 0 )
	{
		printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
		goto exit;
	}

	printf( " ok\n" );

	/*
	 * 1.3. Verify certificate validity
	 */
	printf( "  . Verify the client certificate..." );
	fflush( stdout );

	int flags;

	ret = x509parse_verify( &clicert, &cacert, NULL, &flags );
	if( ret != 0 )
	{
		printf( " failed\n  !  x509parse_verify returned %d\n\n", ret );
		goto exit;
	}

	printf( " ok\n" );
    }

exit:
    x509_free( &clicert );
    x509_free( &cacert );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}