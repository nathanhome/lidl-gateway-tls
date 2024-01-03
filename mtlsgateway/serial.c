#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>

#include "serial.h"

#define SERIAL_DEVICE "/dev/ttyS1"  // Change this to your serial device

int setup_serial(bool is_hw_flow_control) {
    int serial_fd = open(SERIAL_DEVICE, O_RDWR | O_NOCTTY | O_NDELAY);
    if (serial_fd == -1) {
        perror("Failed to open serial port");
        exit(1);
    }

    struct termios options;
    tcgetattr(serial_fd, &ptions);
    cfsetispeed(&options, B115200); // Set the baud rate (adjust as needed)
    cfsetospeed(&options, B115200); // Set the baud rate (adjust as needed)
    options.c_cflag |= (CLOCAL | CREAD);

    // 8N1, hardware flow control
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    if (is_hw_flow_control) {
        options.c_cflag |= CRTSCTS;
    }

    // Raw input and output
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    // No input or output processing
    options.c_iflag &= ~(IGNBRK | BRKINT | IGNPAR | PARMRK | INPCK | ISTRIP |
                         INLCR | IGNCR | ICRNL | IXON | IXOFF | IUCLC | IXANY |
                         IMAXBEL);
    tcsetattr(serial_fd, TCSANOW, &options);
    return serial_fd;
}

void close_serial(int serial_fd) {
    close(serial_fd);
}

ssize_t read_serial(int serial_fd, unsigned char *buf, size_t count) {
    return read(serial_fd, buf, count);
}

ssize_t write_serial(int serial_fd, unsigned char *buf, size_t count) {
    return write(serial_fd, buf, count);
}
