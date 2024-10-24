#ifndef __TUNCAT_H__
#define __TUNCAT_H__

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

enum ifmode {
  IFMODE_UNSPEC = 0,
  IFMODE_L3 = 1,
  IFMODE_L2 = 2,
  IFMODE_DEFAULT = IFMODE_L3,
};

#define IFMODE_L3_OPT "l3"
#define IFMODE_L2_OPT "l2"
#define IFMODE_DEFAULT_OPT IFMODE_L3_OPT

enum trmode {
  TRMODE_UNSPEC = 0,
  TRMODE_STDIO = 1,
  TRMODE_SERVER = 2,
  TRMODE_CLIENT = 3,
  TRMODE_DEFAULT = TRMODE_STDIO,
};

#define TRMODE_STDIO_OPT "stdio"
#define TRMODE_SERVER_OPT "server"
#define TRMODE_CLIENT_OPT "client"
#define TRMODE_DEFAULT_OPT TRMODE_STDIO_OPT

enum ipmode {
  IPMODE_UNSPEC = 0,
  IPMODE_IPV4 = 4,
  IPMODE_IPV6 = 6,
};

#define PORT_DEFAULT "19876"

enum compflag {
  COMPFLAG_UNSPEC = 0,
  COMPFLAG_NONE = 1,
  COMPFLAG_COMPRESS = 2,
};

struct tuncat_commandline_options {
  enum ifmode ifmode;
  char *ifname;
  char *addr;
  char *brname;
  char *braddifname;
  enum trmode trmode;
  char *node;
  char *port;
  enum ipmode ipmode;
  enum compflag compflag;
  size_t max_frame_size;
  size_t ifbuffer_size;
  size_t trbuffer_size;
};

void print_usage(FILE *, int, char *const[]);

#endif
