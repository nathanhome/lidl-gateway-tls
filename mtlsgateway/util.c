#include "util.h"

#include <fcntl.h>

void led_status(bool is_on)
{
    int fd = open("/proc/led1", O_WRONLY);
    if (fd < 0) {
        return;
    }
    write(fd, (is_on) ? "1\n" : "0\n", 2);
    close(fd);
}

static void error_exit(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}