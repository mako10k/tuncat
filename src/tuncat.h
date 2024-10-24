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

#define IF_BUFFER_SIZE 65536
#define TR_BUFFER_SIZE(siz) (snappy_max_compressed_length(siz) + 2)

enum {
  IFMODE_TUN = 1,
  IFMODE_TAP = 2,
  IFMODE_DEFAULT = IFMODE_TUN,
};

#define IFMODE_TUN_OPT "tun"
#define IFMODE_TAP_OPT "tap"
#define IFMODE_DEFAULT_OPT IFMODE_TUN_OPT

enum {
  TRMODE_STDIO = 1,
  TRMODE_SERVER = 2,
  TRMODE_CLIENT = 3,
  TRMODE_DEFAULT = TRMODE_STDIO,
};

#define TRMODE_STDIO_OPT "stdio"
#define TRMODE_SERVER_OPT "server"
#define TRMODE_CLIENT_OPT "client"
#define TRMODE_DEFAULT_OPT TRMODE_STDIO_OPT

enum {
  IPMODE_IPV4 = 4,
  IPMODE_IPV6 = 6,
};

#define PORT_DEFAULT "19876"

#define COMPFLAG_COMPRESS 1

struct tuncat_commandline_options {
  int ifmode;
  char *ifname;
  char *addr;
  char *brname;
  char *braddifname;
  int trmode;
  char *node;
  char *port;
  int ipmode;
  int compflag;
};

void print_usage(FILE *, int, char *const[]);

#endif
