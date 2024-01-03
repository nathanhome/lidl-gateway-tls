#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#include "serial.h"

#define SERVER_IP "0.0.0.0"         // Change this to your server's IP
#define SERVER_PORT 8888            // Change this to your server's port
#define SERIAL_DEVICE "/dev/ttyS1"  // Change this to your serial device

void cleanup() {
    // Clean up and close resources in the reverse order of initialization

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&srvkey);
    mbedtls_x509_crt_free(&clientcert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (serial_fd != -1) {
        close_serial(serial_fd);
    }
}

int main() {
    int serial_fd = setup_serial(SERIAL_DEVICE);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt clientcert;
    mbedtls_pk_context srvkey;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&clientcert);
    mbedtls_pk_init(&srvkey);

    // Load your server certificate and private key
    mbedtls_x509_crt_parse_file(&srvcert, "/etc/tls/server.crt");
    mbedtls_pk_parse_keyfile(&srvkey, "/etc/tls/server.key");

    // Load your client certificate for mutual authentication
    mbedtls_x509_crt_parse_file(&clientcert, "/etc/tls/client.crt");

    // Initialize the SSL configuration
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey);
    mbedtls_ssl_conf_ca_chain(&conf, &clientcert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // assure that minimum TLS 1.2 is used
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    // After initializing the SSL configuration, set verification options
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    
    atexit(cleanup);

    // Set up the listening socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    while (1) {
        printf("Waiting for a connection...\n");
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        printf("Client connected\n");

        mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        // Perform the TLS handshake
        while (1) {
            int ret = mbedtls_ssl_handshake(&ssl);
            if (ret == 0) {
                printf("TLS handshake successful\n");
                break;
            } else if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                printf("Client certificate verification failed\n");
                mbedtls_ssl_close_notify(&ssl);
                close(client_fd);
                break;
            }  else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                printf("TLS handshake failed with error: %d\n", ret);
                mbedtls_ssl_close_notify(&ssl);
                close(client_fd);
                break;
            }
        }

        printf("TLS established\n");
        char buffer[256];

        while (1) {
            // Read data from the TLS connection
            int len = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, sizeof(buffer));
            if (len <= 0) {
                break;
            }

            // Write the received data to the serial device
            write(serial_fd, buffer, len);

            // Read data from the serial device and send it over TLS
            len = read(serial_fd, buffer, sizeof(buffer));
            if (len > 0) {
                mbedtls_ssl_write(&ssl, (unsigned char *)buffer, len);
            }
        }

        // Close the client connection
        mbedtls_ssl_close_notify(&ssl);
        close(client_fd);
        printf("Client disconnected\n");
    }

    return 0;
}
