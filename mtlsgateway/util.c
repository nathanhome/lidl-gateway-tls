#include "util.h"

#include <fcntl.h>
#include <unistd.h>

#include <mbedtls/platform.h>
#include <mbedtls/error.h>

void led_status(bool is_on) {
    int fd = open("/proc/led1", O_WRONLY);
    if (fd < 0) {
        return;
    }
    write(fd, (is_on) ? "1\n" : "0\n", 2);
    close(fd);
}

void error_exit(int code, const char* msg) {
    print_error(code, msg);
    exit(EXIT_FAILURE);
}

void print_error(int code, const char* msg) {
    char error_buf[100];
    mbedtls_strerror(code, error_buf, 100);
    mbedtls_printf("Code %d: %s\n%s\n", code, error_buf, msg);
}
