#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>

#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "serial.h"
#include "util.h"

#define SERVER_IP "0.0.0.0"         // Change this to your server's IP
#define SERVER_PORT 8889            // Change this to your server's port
#define SERIAL_DEVICE "/dev/ttyS1"  // Change this to your serial device
#define BUF_SIZE 1024

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;

mbedtls_x509_crt srvcert;
mbedtls_pk_context srvkey;
mbedtls_x509_crt clientcert;

// small ringbuffer structure
mbedtls_ssl_context ssl1, ssl2;
mbedtls_ssl_context* p_ssl = &ssl1; 
mbedtls_ssl_context* p_newssl = &ssl2; 
int client_fd = -1;
int new_client_fd = -1;
int serial_fd = -1;
int server_fd = -1;

/**
 * @brief Simple max function for fd handling
 * 
 * @param a 
 * @param b 
 * @return int 
 */
int max(int a, int b) {
    return (a > b) ? a : b;
}

/**
 * @brief Configure tls connection with mandatory mutual authentication
 */
void config_tls() {

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Initialize the SSL configuration
    mbedtls_ssl_config_init(&conf);
    int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        error_exit(ret, "Problem initializing SSL configuration.");
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Load mtls keys and certificates
    mbedtls_pk_init(&srvkey);
    int result = mbedtls_pk_parse_keyfile(&srvkey, "/tuya/tls/gwserver.key", NULL, 
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
    if (result < 0) {
        error_exit(result, "  Failed to parse server key /tuya/tls/gwserver.key");
    }

    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_parse_file(&srvcert, "/tuya/tls/gwserver.crt");
    if (result < 0) {
        mbedtls_pk_free(&srvkey);
        error_exit(result, "  Failed to parse server cert /tuya/tls/gwserver.crt");
    }

    result = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey);
    if (result < 0) {
        mbedtls_pk_free(&srvkey);
        mbedtls_x509_crt_free(&srvcert);
        error_exit(result, "  Problem with TLS key,cert configuration.");
    }

    // assure that minimum TLS 1.2 is used
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    // After initializing the SSL configuration, set mandatory client auth
    mbedtls_x509_crt_init(&clientcert);
    result = mbedtls_x509_crt_parse_file(&clientcert, "/tuya/tls/trust.pem");
    if (result < 0) {
        mbedtls_pk_free(&srvkey);
        mbedtls_x509_crt_free(&clientcert);
        mbedtls_x509_crt_free(&srvcert);
        error_exit(result, "  Failed to parse trusted client(s) /tuya/tls/trust.pem");
    }

    mbedtls_ssl_conf_ca_chain(&conf, &clientcert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}

/**
 * @brief Reliable, complete cleanup on error or server shutdown
 */
void cleanup_tls() {

    if (serial_fd != -1) {
        close_serial(serial_fd);
    }

    if (client_fd != -1) {
        // Close the client connection
        close(client_fd);
        mbedtls_ssl_close_notify(p_ssl);
        client_fd = -1;
    }
    mbedtls_ssl_free(p_ssl);

    if (new_client_fd != -1) {
        // Close the client connection
        close(new_client_fd);
        mbedtls_ssl_close_notify(p_newssl);
        new_client_fd = -1;
    }
    mbedtls_ssl_free(p_newssl);

    // TODO: close other fd?

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&srvkey);
    mbedtls_x509_crt_free(&clientcert);
    mbedtls_ssl_config_free(&conf);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


int main() {
    serial_fd = setup_serial(SERIAL_DEVICE);
    config_tls();    
    atexit(cleanup_tls);

    // Set up the listening socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    // TODO: add a timeout to fall back if connection is lost

    while (1) {
        // add both file descriptors as possible read sources
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        if (client_fd >= 0) {
            // add serial fd only if client is connected
            FD_SET(client_fd, &read_fds);
            FD_SET(serial_fd, &read_fds);
        }

        int max_fd = max(server_fd, max(client_fd, serial_fd));

        // select an active file descriptor (if any)
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ret < 0) {
            error_exit(ret, " file descriptor select failed");
        }

        if (FD_ISSET(server_fd, &read_fds)) {
            // (re)-connect
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            new_client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
            printf("Client connected\n");

            mbedtls_ssl_init(p_newssl);
            mbedtls_ssl_set_bio(p_newssl, &new_client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
            int ret = 0;
            do {       
                ret = mbedtls_ssl_handshake(p_newssl);
            } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                     ret == MBEDTLS_ERR_SSL_WANT_WRITE);
            if (ret == 0) {
                printf(" tls handshake successful, switch context\n");
                /* switch current ssl context */
                mbedtls_ssl_context* p_tmpssl = p_ssl;
                p_ssl = p_newssl; 
                p_newssl = p_tmpssl;

                int tmp_fd = client_fd;
                client_fd = new_client_fd;     
                new_client_fd = tmp_fd;
            } else if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                printf(" client certificate verification failed\n");
            }  else {
                printf(" tls handshake failed with error: %d\n", ret);
            }

            /* close old (switched) connecton if successful authorized,
             * new connection on failure
             */
            close(new_client_fd);
            mbedtls_ssl_close_notify(p_newssl);
            mbedtls_ssl_free(p_newssl);
        }

        if (FD_ISSET(client_fd, &read_fds)) {
            // write to zigbee gateway device
            char writebuffer[BUF_SIZE];
            ssize_t ret = 0;
            do {       
                ret = mbedtls_ssl_read(p_ssl, (unsigned char *)writebuffer, BUF_SIZE);
            } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                     ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                     ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS);

            if (ret <= 0) {
                switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    close(client_fd);
                    mbedtls_ssl_close_notify(p_ssl);
                    client_fd=-1;
                    break;
                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    mbedtls_ssl_session_reset(p_ssl);
                    break;
                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret);
                    mbedtls_ssl_session_reset(p_ssl);
                    break;
                }
                continue;
            }

            // Write the received data to the serial device
            ssize_t written = write_serial(serial_fd, writebuffer, ret);
            if (written < 0) {
                mbedtls_printf(" serial write error -0x%x\n", (unsigned int) -written);
            }
        }

        if (FD_ISSET(serial_fd, &read_fds)) {
            // read zigbee gateway device
            char readbuffer[BUF_SIZE];
            ssize_t read = read_serial(serial_fd, readbuffer, BUF_SIZE);

            if (read <= 0) {
                // transfer finished by serial connection
                mbedtls_printf(" serial read error -0x%x\n", (unsigned int) -read);
                continue;
            }
            ssize_t ret = 0;
            do {       
                ret = mbedtls_ssl_write(p_ssl, (unsigned char *)readbuffer, read);
            } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                     ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                     ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS);

            if (ret <= 0) {
                switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    close(client_fd);
                    mbedtls_ssl_close_notify(p_ssl);
                    client_fd=-1;
                    break;
                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    mbedtls_ssl_session_reset(p_ssl);
                    break;
                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret);
                    mbedtls_ssl_session_reset(p_ssl);
                    break;
                }
            }
        }

        printf("Client disconnected\n");
    }

    return 0;
}
