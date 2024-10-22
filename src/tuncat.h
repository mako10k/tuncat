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

#define IFMODE_TUN 1
#define IFMODE_TAP 2
#define IFMODE_DEFAULT IFMODE_TUN

#define IFMODE_TUN_OPT "tun"
#define IFMODE_TAP_OPT "tap"
#define IFMODE_DEFAULT_OPT IFMODE_TUN_OPT

#define TRMODE_STDIO 1
#define TRMODE_SERVER 2
#define TRMODE_CLIENT 3
#define TRMODE_DEFAULT TRMODE_STDIO

#define TRMODE_STDIO_OPT "stdio"
#define TRMODE_SERVER_OPT "server"
#define TRMODE_CLIENT_OPT "client"
#define TRMODE_DEFAULT_OPT TRMODE_STDIO_OPT

#define IPMODE_IPV4 4
#define IPMODE_IPV6 6

#define PORT_DEFAULT "19876"

#define COMPFLAG_COMPRESS 1

struct tuncat_opts {
  int ifmode;
  char *ifname;
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
