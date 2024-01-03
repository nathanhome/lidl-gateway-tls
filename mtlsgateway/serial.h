#ifndef SERIAL_H
#define SERIAL_H

#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

int setup_serial(bool is_hw_flow_control);
void close_serial(int serial_fd);
ssize_t read_serial(int serial_fd, void *buf, size_t count);
ssize_t write_serial(int serial_fd, const void *buf, size_t count);

#endif /* SERIAL_H */
