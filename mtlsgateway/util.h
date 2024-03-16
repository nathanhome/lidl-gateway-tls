#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void led_status(bool is_on);
void error_exit(int code, const char* msg);
void print_error(int code, const char* msg);
#endif /* UTIL_H */

