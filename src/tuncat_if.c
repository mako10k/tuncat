#include "tuncat_if.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int inet6_net_pton(int af, const char *cp, void *buf, size_t len) {
  if (af != AF_INET6) {
    errno = EAFNOSUPPORT;
    return -1;
  }
  if (cp == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (len < sizeof(struct in6_addr)) {
    errno = ENOSPC;
    return -1;
  }

  char _buf[INET6_ADDRSTRLEN + sizeof("/128")];
  strncpy(_buf, cp, sizeof(_buf) - 1);
  char *sep = strchr(_buf, '/');
  if (sep != NULL) {
    *sep++ = '\0';
  }
  struct in6_addr addr6;
  if (inet_pton(af, _buf, &addr6) != 1) {
    errno = ENOENT;
    return -1;
  }

  long bits = 128;
  if (sep == NULL) {
    goto end;
  }

  char *p;
  bits = strtol(sep, &p, 10);
  if (*p != '\0' || bits < 0 || bits > 128) {
    errno = EINVAL;
    return -1;
  }
end:
  memcpy(buf, &addr6, len < sizeof(addr6) ? len : sizeof(addr6));
  return (int)bits;
}

int inet_net_pton_orig(int af, const char *cp, void *buf, size_t len) {
  if (af == AF_INET)
    return inet_net_pton(af, cp, buf, len);
  if (af == AF_INET6)
    return inet6_net_pton(af, cp, buf, len);
  errno = EAFNOSUPPORT;
  return -1;
}

int change_ifflags(int sock, const char *ifname, int flags_clear,
                   int flags_set) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    perror("Cannot get interface flags");
    return -1;
  }
  short flags_new = (short)((ifr.ifr_flags & ~flags_clear) | flags_set);
  if (flags_new != ifr.ifr_flags) {
    ifr.ifr_flags = flags_new;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
      perror("Cannot set interface flags");
      return -1;
    }
  }

  return 0;
}

int create_tunif(int sock, char *ifname, enum ifmode ifmode) {
  int fd;
  struct ifreq ifr;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("open");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = 0;
  switch (ifmode) {
  case IFMODE_L2:
    ifr.ifr_flags |= IFF_TAP;
    break;
  case IFMODE_UNSPEC:
  case IFMODE_L3:
    ifr.ifr_flags |= IFF_TUN;
    break;
  }

#ifndef IFF_NO_PI
#error "IFF_NO_PI is not defined (require kernel >= 2.6.27)"
#endif
  ifr.ifr_flags |= IFF_NO_PI;

  if (0 < strlen(ifname) && strlen(ifname) < IFNAMSIZ) {
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  }
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("Error while creating tunnel interface");
    return -1;
  }
  strncpy(ifname, ifr.ifr_name, IFNAMSIZ);

  if (change_ifflags(sock, ifr.ifr_name, 0, IFF_UP | IFF_RUNNING) < 0) {
    return -1;
  }

  return fd;
}

int get_ifindex(int sock, const char ifname[IFNAMSIZ]) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    return 0;
  }

  return ifr.ifr_ifindex;
}

int create_bridge(int sock, char brname[IFNAMSIZ]) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  if (ioctl(sock, SIOCBRADDBR, &ifr) < 0) {
    perror("Cannot create bridge device");
    return -1;
  }

  return 0;
}

int delete_bridge(int sock, char *brname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  if (ioctl(sock, SIOCBRDELBR, &ifr) < 0) {
    perror("Cannot delete bridge device");
    return -1;
  }

  return 0;
}

int add_bridge_member(int sock, const char *brname, const char *ifname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  ifr.ifr_ifindex = get_ifindex(sock, ifname);
  if (ifr.ifr_ifindex == 0) {
    fprintf(stderr, "Cannot get interface index\n");
    return -1;
  }
  if (ioctl(sock, SIOCBRADDIF, &ifr) < 0) {
    perror("Cannot append interface to bridge device");
    return -1;
  }

  return 0;
}

char *brname = NULL;

void cleanbr(void) {
  if (brname) {
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket");
      return;
    }
    change_ifflags(sock, brname, IFF_UP, 0);
    delete_bridge(sock, brname);
    close(sock);
  }
}

void cleanbr_sig(int sig) {
  (void)sig;
  cleanbr();
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

static in_addr_t convert_mask4(int bits) {
  return (in_addr_t)htonl((uint32_t)(~0U << (32 - bits)));
}

static in_addr_t apply_mask4(in_addr_t net, in_addr_t addr, in_addr_t mask) {
  return (net & mask) | (addr & ~mask);
}

static int convert_nworkaddr(const void *addr, int bits, void *broadcastaddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *networkaddr4 = (struct in_addr *)broadcastaddr;
  in_addr_t mask = convert_mask4(bits);
  networkaddr4->s_addr = apply_mask4(addr4->s_addr, 0U, mask);
  return 0;
}

static int convert_bcastaddr(const void *addr, int bits, void *broadcastaddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *bcastaddr4 = (struct in_addr *)broadcastaddr;
  uint32_t mask = convert_mask4(bits);
  bcastaddr4->s_addr = apply_mask4(addr4->s_addr, ~0U, mask);
  return 0;
}

int convert_bits_to_netmask(int family, int bits, void *mask) {
  if (family == AF_INET) {
    if (bits < 0 || bits > 32) {
      return -1;
    }
    struct in_addr *mask4 = mask;
    mask4->s_addr = convert_mask4(bits);
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
        mask6->s6_addr[i] = (0xff << (8 - bits)) & 0xff;
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

int set_ifaddr6(int sock6, const char *ifname, const char *addrstr) {
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
  ifr6.ifr6_prefixlen = masksize & 0xff;
  if (ioctl(sock6, SIOCSIFADDR, (void *)&ifr6) < 0) {
    perror("Cannot set interface address");
    return -1;
  }

  return 0;
}

int set_ifaddr(int sock, const char *ifname, const char *addrstr) {
  assert(sock >= 0);
  assert(ifname != NULL);
  assert(addrstr != NULL);
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

int init_if(struct tuncat_commandline_options *optsp) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("socket");
    return EXIT_FAILURE;
  }

  char tunname[IFNAMSIZ];
  if (optsp->ifname != NULL) {
    strncpy(tunname, optsp->ifname, IFNAMSIZ - 1);
    tunname[IFNAMSIZ - 1] = '\0';
  }
  int tunfd = create_tunif(sock, tunname, optsp->ifmode);
  if (tunfd == -1) {
    return EXIT_FAILURE;
  }

  if (optsp->brname == NULL) {
    if (optsp->addr != NULL) {
      if (set_ifaddr(sock, optsp->ifname, optsp->addr) < 0) {
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
      brname = optsp->brname;
      atexit(cleanbr);
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
      size_t len = strlen(optsp->braddifname);
      char *braddifname = alloca(len + 1);
      char *ifname, *ifn;

      ifname = strncpy(braddifname, optsp->braddifname, IFNAMSIZ - 1);
      braddifname[IFNAMSIZ - 1] = '\0';
      for (;;) {
        if ((ifn = strchr(ifname, ','))) {
          *ifn = '\0';
        }
        if (add_bridge_member(sock, brname, ifname) < 0) {
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
