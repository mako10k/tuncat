#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define PACKAGE "tuncat"
#define VERSION "0.1"
#define PACKAGE_STRING PACKAGE " " VERSION
#endif

#include <stdio.h>

#define IF_MAX_FRAME_SIZE_DEF 65535
#define IF_MAX_FRAME_SIZE_MIN 128
#define IF_MAX_FRAME_SIZE_MAX 65535

#define IF_BUFFER_SIZE_MIN 128
#define IF_BUFFER_SIZE_MAX 16777216

#define TR_BUFFER_SIZE_MIN IF_BUFFER_SIZE_MIN
#define TR_BUFFER_SIZE_MAX IF_BUFFER_SIZE_MAX

#define IF_FRAME_SIZE_LEN 2

void print_usage(FILE *);
