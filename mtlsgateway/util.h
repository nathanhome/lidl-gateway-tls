#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef DEBUG
#define LOG_DEBUG(format, ...) fprintf(stderr, format "\n", __VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#endif

#define LOG_ERROR(format, ...) fprintf(stderr, format "\n", __VA_ARGS__)

void led_status(bool is_on);
void error_exit(const char* msg);

#endif /* UTIL_H */

