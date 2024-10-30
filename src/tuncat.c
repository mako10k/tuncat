#include "tuncat.h"
#include "tuncat_if.h"
#include "tuncat_net.h"

#include <net/if.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * **print_usage** : print usage
 *
 * @param fp    file pointer
 * @param argc  argument count
 * @param argv  argument vector
 */
static void print_usage(FILE *fp, int argc, char *const argv[]) {
  (void)argc;

#define ISDEFS(DEF, VAR) (VAR), (strcmp((DEF), (VAR)) == 0 ? "  (default)" : "")

  fprintf(fp, "\n");
  fprintf(fp, "Usage:\n");
  fprintf(fp, "  %s [options]\n", argv[0]);
  fprintf(fp, "\n");
  fprintf(fp, "Options:\n");
  fprintf(fp, "  -n,--ifname=<name>          Interface name\n");
  fprintf(fp,
          "  -a,--ifaddress=<addr>       Interface address (only with -n)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L3 payload mode%s\n",
          ISDEFS(IFMODE_DEFAULT_OPT, IFMODE_L3_OPT));
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L2 payload mode%s\n",
          ISDEFS(IFMODE_DEFAULT_OPT, IFMODE_L2_OPT));
  fprintf(fp, "\n");
  fprintf(fp, "  -b,--bridge-name=<name>     Bridge interface (L2 payload)\n");
  fprintf(fp, "  -i,--bridge-members=<ifname>[,<if_name>...]\n");
  fprintf(
      fp,
      "                              Bridge members   (only with bridge)\n");
  fprintf(fp, "  -a,--ifaddress=<addr>       Bridge interface address (only "
              "with -b)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -t,--transfer-mode=%-6s   Stdio mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_STDIO_OPT));
  fprintf(fp, "  -t,--transfer-mode=%-6s   TCP server mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_SERVER_OPT));
  fprintf(fp, "  -t,--transfer-mode=%-6s   TCP client mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_CLIENT_OPT));
  fprintf(fp, "  -l,--address=<addr>         Listen Address   (default: any) "
              "  (TCP server)\n");
  fprintf(fp,
          "  -p,--port=<port>            Listen port      (default: %5s) (TCP "
          "server)\n",
          PORT_DEFAULT);
  fprintf(fp, "  -l,--address=<addr>         Connect Address  (required)       "
              "(TCP client)\n");
  fprintf(fp,
          "  -p,--port=<port>            Connect Port     (default: %5s) (TCP "
          "client)\n",
          PORT_DEFAULT);
  fprintf(fp, "  -4,--ipv4                   Force ipv4       (TCP server or "
              "TCP client)\n");
  fprintf(fp, "  -6,--ipv6                   Force ipv6       (TCP server or "
              "TCP client)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -c,--compress               Compress mode\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -v,--version                Print version\n");
  fprintf(fp, "  -h,--help                   Print this usage\n");
  fprintf(fp, "\n");
}

static int cmp_addr(int family, const void *addr1, const void *addr2) {
  if (family == AF_INET) {
    return memcmp(addr1, addr2, sizeof(struct in_addr));
  } else if (family == AF_INET6) {
    return memcmp(addr1, addr2, sizeof(struct in6_addr));
  } else {
    assert("Invalid family" == NULL);
  }
}

static int convert_nworkaddr(const void *addr, int bits, void *broadcastaddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *networkaddr4 = (struct in_addr *)broadcastaddr;
  uint32_t mask = htonl(~((1 << (32 - bits)) - 1));
  networkaddr4->s_addr = addr4->s_addr & mask;
  return 0;
}

static int convert_bcastaddr(const void *addr, int bits, void *broadcastaddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *bcastaddr4 = (struct in_addr *)broadcastaddr;
  uint32_t mask = htonl(~((1 << (32 - bits)) - 1));
  bcastaddr4->s_addr = (addr4->s_addr & mask) | ~mask;
  return 0;
}

static int convert_bits_to_netmask(int family, int bits, void *mask) {
  if (family == AF_INET) {
    if (bits < 0 || bits > 32) {
      return -1;
    }
    struct in_addr *mask4 = mask;
    mask4->s_addr = htonl(~((1 << (32 - bits)) - 1));
  } else if (family == AF_INET6) {
    if (bits < 0 || bits > 128) {
      return -1;
    }
    struct in6_addr *mask6 = mask;
    int i;
    for (i = 0; i < 16; i++) {
      if (bits >= 8) {
        mask6->s6_addr[i] = 0xff;
        bits -= 8;
      } else if (bits > 0) {
        mask6->s6_addr[i] = 0xff << (8 - bits);
        bits = 0;
      } else {
        mask6->s6_addr[i] = 0;
      }
    }
  } else {
    return -1;
  }

  return 0;
}

static int set_ifaddr6(int sock6, const char *ifname, const char *addrstr) {
  struct in6_ifreq ifr6;
  struct in6_addr addr6;

  memset(&addr6, 0, sizeof(addr6));
  int masksize = inet_net_pton(AF_INET6, addrstr, &addr6, sizeof(addr6));
  if (masksize < 0) {
    fprintf(stderr, "Invalid address\n");
    return -1;
  }

  int ifindex = get_ifindex(sock6, ifname);
  if (ifindex == 0) {
    fprintf(stderr, "Cannot get interface index\n");
    return -1;
  }

  memset(&ifr6, 0, sizeof(ifr6));
  ifr6.ifr6_ifindex = ifindex;
  memcpy(&ifr6.ifr6_addr, &addr6, sizeof(addr6));
  ifr6.ifr6_prefixlen = masksize;
  if (ioctl(sock6, SIOCSIFADDR, (void *)&ifr6) < 0) {
    perror("Cannot set interface address");
    return -1;
  }

  return 0;
}

static int set_ifaddr(int sock, const char *ifname, const char *addrstr) {
  struct ifreq ifr;
  struct sockaddr_in addr, mask, nwork, bcast;

  do {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    int masklen =
        inet_net_pton(AF_INET, addrstr, &addr.sin_addr, sizeof(addr.sin_addr));
    if (masklen < 0) {
      break;
    }

    memset(&mask, 0, sizeof(mask));
    mask.sin_family = AF_INET;
    mask.sin_port = 0;
    if (convert_bits_to_netmask(AF_INET, masklen, &mask.sin_addr) < 0) {
      break;
    }

    memset(&nwork, 0, sizeof(nwork));
    nwork.sin_family = AF_INET;
    nwork.sin_port = 0;
    if (convert_nworkaddr(&addr.sin_addr, masklen, &nwork.sin_addr) < 0) {
      break;
    }

    memset(&bcast, 0, sizeof(bcast));
    bcast.sin_family = AF_INET;
    bcast.sin_port = 0;
    if (convert_bcastaddr(&addr.sin_addr, masklen, &bcast.sin_addr) < 0) {
      break;
    }

    if (masklen < 31) {
      // check except netmask is /31 or /31, see RFC 3021
      if (cmp_addr(AF_INET, &addr.sin_addr, &nwork.sin_addr) == 0) {
        fprintf(stderr, "Cannot set address as network address\n");
        break;
      }
      if (cmp_addr(AF_INET, &addr.sin_addr, &bcast.sin_addr) == 0) {
        fprintf(stderr, "Cannot set address as broadcast addr\n");
        break;
      }
    } else if (masklen == 32) {
      fprintf(stderr, "WARNING: /32 address is not recommended\n");
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(sock, SIOCSIFADDR, (void *)&ifr) < 0) {
      perror("Cannot set interface address");
      return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, &mask, sizeof(mask));
    if (ioctl(sock, SIOCSIFNETMASK, (void *)&ifr) < 0) {
      perror("Cannot set interface netmask");
      return -1;
    }

    if (masklen > 31) {
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
      memcpy(&ifr.ifr_addr, &bcast, sizeof(bcast));
      if (ioctl(sock, SIOCSIFBRDADDR, (void *)&ifr) < 0) {
        perror("Cannot set interface broadcast address");
        return -1;
      }
      if (change_ifflags(sock, ifname, 0, IFF_BROADCAST) < 0) {
        return -1;
      }
    } else {
      // IFC-3012 Compliance (/31, /32 address)
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
      bcast.sin_addr.s_addr = htonl(INADDR_NONE);
      memcpy(&ifr.ifr_addr, &bcast, sizeof(bcast));
      if (ioctl(sock, SIOCSIFBRDADDR, (void *)&ifr) < 0) {
        perror("Cannot set interface broadcast address");
        return -1;
      }
      if (change_ifflags(sock, ifname, IFF_BROADCAST, 0) < 0) {
        return -1;
      }
    }

    return 0;
  } while (0);

  int sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock6 < 0) {
    perror("socket");
    return -1;
  }
  if (set_ifaddr6(sock6, ifname, addrstr) < 0) {
    close(sock6);
    return -1;
  }
  close(sock6);

  return 0;
}

static int init_if(struct tuncat_commandline_options *optsp) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("socket");
    return EXIT_FAILURE;
  }

  const char *tunname = optsp->ifname;
  char ifname[] = "tun999";

  if (tunname == NULL) {
    for (unsigned int i = 0; i < 1000; i++) {
      if (optsp->ifmode == IFMODE_L2)
        sprintf(ifname, "tap%d", i++);
      else
        sprintf(ifname, "tun%d", i++);
      if (get_ifindex(sock, ifname) == 0) {
        if (i < 999)
          break;
        fprintf(stderr, "Cannot get interface index\n");
      }
    }
    tunname = ifname;
  }

  int tunfd = create_tunif(sock, tunname, optsp->ifmode);
  if (tunfd == -1) {
    return EXIT_FAILURE;
  }

  if (optsp->brname == NULL) {
    if (optsp->addr != NULL) {
      if (set_ifaddr(sock, tunname, optsp->addr) < 0) {
        return EXIT_FAILURE;
      }
    }

  } else {
    int brindex;

    brindex = get_ifindex(sock, optsp->brname);
    if (brindex == 0) {
      brindex = create_bridge(sock, optsp->brname);
      if (brindex == -1) {
        return EXIT_FAILURE;
      }
      on_exit(cleanbr, optsp->brname);
      struct sigaction sa;
      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = cleanbr_sig;
      sigaction(SIGINT, &sa, NULL);
      sigaction(SIGTERM, &sa, NULL);
    }

    if (change_ifflags(sock, optsp->brname, 0, IFF_UP | IFF_RUNNING) < 0) {
      return EXIT_FAILURE;
    }

    if (optsp->addr != NULL) {
      if (set_ifaddr(sock, optsp->brname, optsp->addr) < 0) {
        return EXIT_FAILURE;
      }
    }

    if (add_bridge_member(sock, optsp->brname, tunname) < 0) {
      return EXIT_FAILURE;
    }

    if (optsp->braddifname) {
      int len = strlen(optsp->braddifname);
      char *braddifname = alloca(len + 1);
      char *ifname, *ifn;

      ifname = strcpy(braddifname, optsp->braddifname);
      for (;;) {
        if ((ifn = strchr(ifname, ','))) {
          *ifn = '\0';
        }
        if (add_bridge_member(sock, remove_brname(), ifname) < 0) {
          return EXIT_FAILURE;
        }
        if (!ifn) {
          break;
        }
        ifname = ifn + 1;
      }
    }

    close(sock);
  }

  return tunfd;
}

#define FRAME_LEN_MAX 65536
#define FRAME_LEN_SIZE 2

static int tuncat_if_to_tr(int ifrfd, int trsfd) {
  assert(ifrfd >= 0);
  assert(trsfd >= 0);
  char buf[FRAME_LEN_MAX + FRAME_LEN_SIZE];

  while (1) {
    ssize_t frsz = read(ifrfd, buf + FRAME_LEN_SIZE, FRAME_LEN_MAX);
    if (frsz == -1) {
      if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
          errno == EINPROGRESS) {
        continue;
      }
      perror("read from interface");
      return -1;
    }
    assert(frsz >= FRAME_LEN_SIZE);
    (*(uint16_t *)buf) = htons(frsz);
    const size_t trssz_expect = frsz + FRAME_LEN_SIZE;
    size_t trssz_sent = 0;
    while (trssz_sent < trssz_expect) {
      ssize_t trssz = write(trsfd, buf + trssz_sent, trssz_expect - trssz_sent);
      if (trssz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write to transfer");
        return -1;
      }
      trssz_sent += trssz;
    }
    if (frsz == 0) {
      return 0;
    }
  }
}

static int tuncat_tr_to_if(int trrfd, int ifwfd) {
  assert(trrfd >= 0);
  assert(ifwfd >= 0);
  char buf[FRAME_LEN_MAX + FRAME_LEN_SIZE];

  size_t trrsz_received = 0;
  while (1) {
    while (trrsz_received < FRAME_LEN_SIZE) {
      ssize_t trrsz =
          read(trrfd, buf + trrsz_received, sizeof(buf) - trrsz_received);
      if (trrsz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read from transfer");
        return -1;
      }
      if (trrsz == 0) {
        return 0;
      }
      trrsz_received += trrsz;
    }
    assert(trrsz_received >= 2);
    const size_t frsz = ntohs(*(uint16_t *)buf);
    if (frsz == 0) {
      return 0;
    }
    while (trrsz_received < frsz + 2) {
      ssize_t trrsz =
          read(trrfd, buf + trrsz_received, sizeof(buf) - trrsz_received);
      if (trrsz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read from transfer");
        return -1;
      }
      trrsz_received += trrsz;
    }
    ssize_t ifwsz = write(ifwfd, buf + FRAME_LEN_SIZE, frsz);
    if (ifwsz == -1) {
      if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
          errno == EINPROGRESS) {
        continue;
      }
      perror("write to interface");
      return -1;
    }
    if ((size_t)ifwsz < frsz) {
      // TODO: inform short write?
    }
    memmove(buf, buf + frsz + 2, trrsz_received - (frsz + 2));
    trrsz_received -= frsz + 2;
  }
}

static void *tuncat_if_to_tr_thread(void *arg) {
  int *fds = arg;
  int ifrfd = fds[0];
  int trsfd = fds[1];
  return (void *)(intptr_t)tuncat_if_to_tr(ifrfd, trsfd);
}

static void *tuncat_tr_to_if_thread(void *arg) {
  int *fds = arg;
  int trrfd = fds[0];
  int ifwfd = fds[1];
  return (void *)(intptr_t)tuncat_tr_to_if(trrfd, ifwfd);
}

static int forward_packets(int tunfd, int tr_ifd, int tr_ofd) {
  pthread_t th_if_to_tr, th_tr_to_if;

  int fds_if_to_tr[2] = {tunfd, tr_ofd};
  int fds_tr_to_if[2] = {tr_ifd, tunfd};

  if (pthread_create(&th_if_to_tr, NULL, tuncat_if_to_tr_thread,
                     fds_if_to_tr) != 0) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  if (pthread_create(&th_tr_to_if, NULL, tuncat_tr_to_if_thread,
                     fds_tr_to_if) != 0) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  void *ret_if_to_tr, *ret_tr_to_if;
  if (pthread_join(th_if_to_tr, &ret_if_to_tr) != 0) {
    perror("pthread_join");
    return EXIT_FAILURE;
  }
  if (pthread_join(th_tr_to_if, &ret_tr_to_if) != 0) {
    perror("pthread_join");
    return EXIT_FAILURE;
  }

  return (intptr_t)ret_if_to_tr == 0 && (intptr_t)ret_tr_to_if == 0
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}

int main(int argc, char *const argv[]) {
  int sock;

  int opt;
  struct tuncat_commandline_options opts;
  struct option longopts[] = {
      {"ifname", required_argument, NULL, 'n'},
      {"ifaddress", required_argument, NULL, 'a'},
      {"tunnel-mode", required_argument, NULL, 'm'},
      {"bridge-name", required_argument, NULL, 'b'},
      {"bridge-members", required_argument, NULL, 'i'},
      {"transfer-mode", required_argument, NULL, 't'},
      {"address", required_argument, NULL, 'l'},
      {"port", required_argument, NULL, 'p'},
      {"ipv4", no_argument, NULL, '4'},
      {"ipv6", no_argument, NULL, '6'},
      {"compress", no_argument, NULL, 'c'},
      {"version", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  memset(&opts, 0, sizeof(opts));

  int optindex = 0;
  while ((opt = getopt_long(argc, argv, "m:n:b:i:a:t:l:p:46cvh", longopts,
                            &optindex)) != -1) {
    switch (opt) {
    case 'm':
      if (opts.ifmode != IFMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -m\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcasecmp(optarg, IFMODE_L2_OPT) == 0) {
        opts.ifmode = IFMODE_L2;
      } else if (strcasecmp(optarg, IFMODE_L3_OPT) == 0) {
        opts.ifmode = IFMODE_L3;
      } else {
        fprintf(stderr, "Invalid tunnel interface mode \"%s\"\n", optarg);
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      break;
    case 'n':
      if (opts.ifname != NULL) {
        fprintf(stderr, "Duplicated option -n\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ifname = optarg;
      break;
    case 'a':
      if (opts.addr != NULL) {
        fprintf(stderr, "Duplicated option -a\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.addr = optarg;
      break;
    case 'b':
      if (opts.brname != NULL) {
        fprintf(stderr, "Duplicated option -b\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.brname = optarg;
      break;
    case 'i':
      if (opts.braddifname != NULL) {
        fprintf(stderr, "Duplicated option -i\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.braddifname = optarg;
      break;
    case 't':
      if (opts.trmode != TRMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -t\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcmp(optarg, TRMODE_STDIO_OPT) == 0) {
        opts.trmode = TRMODE_STDIO;
      } else if (strcmp(optarg, TRMODE_SERVER_OPT) == 0) {
        opts.trmode = TRMODE_SERVER;
      } else if (strcmp(optarg, TRMODE_CLIENT_OPT) == 0) {
        opts.trmode = TRMODE_CLIENT;
      } else {
        fprintf(stderr, "Invalid transfer mode \"%s\"\n", optarg);
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      break;
    case 'l':
      if (opts.node != NULL) {
        fprintf(stderr, "Duplicated option -l\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.node = optarg;
      break;
    case 'p':
      if (opts.port != NULL) {
        fprintf(stderr, "Duplicated option -p\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.port = optarg;
      break;
    case '4':
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV4;
      break;
    case '6':
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV6;
      break;
    case 'c':
      if (opts.compflag != COMPFLAG_UNSPEC) {
        fprintf(stderr, "Duplicated option -c\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.compflag = COMPFLAG_COMPRESS;
      break;
    case 'v':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      return EXIT_SUCCESS;
    case 'h':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      print_usage(stdout, argc, argv);
      return EXIT_SUCCESS;
    default:
      fprintf(stderr, "Invalid option -%c\n", optopt);
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
  }

  if (opts.ifmode == IFMODE_UNSPEC) {
    opts.ifmode = IFMODE_DEFAULT;
  }

  if (opts.brname != NULL && opts.ifmode == IFMODE_L3) {
    fprintf(stderr, "-b is not supported for L3 mode\n");
    print_usage(stderr, argc, argv);
    return EXIT_FAILURE;
  }

  switch (opts.trmode) {

  case TRMODE_UNSPEC:
    opts.trmode = TRMODE_DEFAULT;
    break;

  case TRMODE_STDIO:
    if (opts.node != NULL) {
      fprintf(stderr, "-l is not supported for stdio mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    if (opts.port != NULL) {
      fprintf(stderr, "-p is not supported for stdio mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    if (opts.ipmode != 0) {
      fprintf(stderr, "-4 or -6 is not supported for stdio mode\n");
    }
    break;

  case TRMODE_SERVER:
    break;

  case TRMODE_CLIENT:
    if (opts.node == NULL) {
      fprintf(stderr, "-l is required for client mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    break;
  }

  if (opts.port == NULL) {
    opts.port = PORT_DEFAULT;
  }

  if (opts.braddifname != NULL && opts.brname == NULL) {
    fprintf(stderr, "-i is not supported without -b\n");
    print_usage(stderr, argc, argv);
    return EXIT_FAILURE;
  }

  if (opts.trmode == TRMODE_STDIO) {
    int tunfd = init_if(&opts);
    if (tunfd == -1) {
      return EXIT_FAILURE;
    }
    return forward_packets(tunfd, STDIN_FILENO, STDOUT_FILENO);
  }

  {
    struct addrinfo aih, *airp, *rp;
    int s;

    memset(&aih, 0, sizeof(aih));
    switch (opts.ipmode) {
    case IPMODE_UNSPEC:
      aih.ai_family = AF_UNSPEC;
      break;
    case IPMODE_IPV4:
      aih.ai_family = AF_INET;
      break;
    case IPMODE_IPV6:
      aih.ai_family = AF_INET6;
      break;
    }
    if (opts.trmode == TRMODE_SERVER)
      aih.ai_flags = AI_PASSIVE;
    aih.ai_socktype = SOCK_STREAM;
    aih.ai_protocol = 0;
    aih.ai_canonname = NULL;
    aih.ai_addr = NULL;
    aih.ai_next = NULL;

    if ((s = getaddrinfo(opts.node, opts.port, &aih, &airp))) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      return EXIT_FAILURE;
    }

    for (rp = airp; rp; rp = rp->ai_next) {
      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == -1)
        continue;
      if (opts.trmode == TRMODE_SERVER) {
        int optval = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
                       sizeof(optval)) == -1) {
          perror("setsockopt");
          close(sock);
          return EXIT_FAILURE;
        }
        if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
          break;
      } else {
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
          break;
      }
      close(sock);
    }

    if (rp == NULL) {
      fprintf(stderr, "Invalid host or port address\n");
      return EXIT_FAILURE;
    }

    freeaddrinfo(airp);
  }

  int tunfd = init_if(&opts);
  if (tunfd == -1) {
    return EXIT_FAILURE;
  }

  if (opts.trmode == TRMODE_SERVER) {

    if (listen(sock, 5) == -1) {
      perror("listen");
      close(sock);
      return EXIT_FAILURE;
    }

    for (;;) {
      int csock;
      struct sockaddr caddr;
      socklen_t clen;
      pid_t pid;

      waitpid(-1, NULL, WNOHANG);

      clen = sizeof(caddr);
      csock = accept(sock, &caddr, &clen);
      if (csock == -1) {
        perror("accept");
        return EXIT_FAILURE;
      }

      pid = fork();
      if (pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
      }

      if (pid == 0) {
        close(sock);
        return forward_packets(tunfd, csock, csock);
      }

      close(csock);
    }
  } else {
    return forward_packets(tunfd, sock, sock);
  }
}
