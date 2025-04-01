#pragma once
#include "tuncat.h"

/** interface mode */
enum ifmode {
  /** interface mode is unspecified */
  IFMODE_UNSPEC = 0,
  /** L3 mode */
  IFMODE_L3 = 1,
  /** L2 mode */
  IFMODE_L2 = 2,
  /** default mode */
  IFMODE_DEFAULT = IFMODE_L3,
};

#define IFMODE_L3_OPT "l3"
#define IFMODE_L2_OPT "l2"
#define IFMODE_DEFAULT_OPT IFMODE_L3_OPT

/** transfer mode */
enum trmode {
  /** transfer mode is unspecified */
  TRMODE_UNSPEC = 0,
  /** transfer mode is stdio */
  TRMODE_STDIO = 1,
  /** transfer mode is server */
  TRMODE_SERVER = 2,
  /** transfer mode is client */
  TRMODE_CLIENT = 3,
  /** default transfer mode */
  TRMODE_DEFAULT = TRMODE_STDIO,
};

#define TRMODE_STDIO_OPT "stdio"
#define TRMODE_SERVER_OPT "server"
#define TRMODE_CLIENT_OPT "client"
#define TRMODE_DEFAULT_OPT TRMODE_STDIO_OPT

/** IP mode */
enum ipmode {
  /** IP mode is unspecified */
  IPMODE_UNSPEC = 0,
  /** IP mode is IPv4 */
  IPMODE_IPV4 = 4,
  /** IP mode is IPv6 */
  IPMODE_IPV6 = 6,
};

#define PORT_DEFAULT "19876"

/** compression flag */
enum compflag {
  /** compression flag is unspecified */
  COMPFLAG_UNSPEC = 0,
  /** no compression */
  COMPFLAG_NONE = 1,
  /** compression */
  COMPFLAG_COMPRESS = 2,
};

/** commandline options */
struct tuncat_commandline_options {
  /** interface mode */
  enum ifmode ifmode;
  /** interface name */
  char *ifname;
  /** interface address */
  char *addr;
  /** bridge interface name */
  char *brname;
  /** default bridge member */
  char *braddifname;
  /** transfer mode */
  enum trmode trmode;
  /** destination address for client, or listen address for server */
  char *node;
  /** destination port for client, or listen port for server */
  char *port;
  /** ip mode for virtual interface */
  enum ipmode ipmode;
  /** use mptcp when this is not zero */
  int mptcp;
  /** compression mode */
  enum compflag compflag;
  /** max frame size for transfer */
  size_t max_frame_size;
  /** interface buffer size */
  size_t ifbuffer_size;
  /** transfer buffer size */
  size_t trbuffer_size;
};

/**
 * @brief parse options
 * @param popts pointer to commandline options
 * @param argc argument count
 * @param argv argument vector
 * @return 0 on success, -1 on error
 */
int tuncat_parse_opts(struct tuncat_commandline_options *popts, int argc,
                      char *const argv[]);
/**
 * @brief check options
 * @param opts pointer to commandline options
 * @return 0 on success, -1 on error
 */
int tuncat_check_opt(struct tuncat_commandline_options opts);
