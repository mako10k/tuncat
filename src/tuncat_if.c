#include "tuncat_if.h"
#include "tuncat_net.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <net/if.h> // must be before <linux/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sockios.h>
#include <signal.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int tuncat_if_change_flags(int sock, const char *ifname, int flags_clear,
                           int flags_set) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    perror("Cannot get interface flags");
    return -1;
  }
  typeof(ifr.ifr_flags) flags_new = (ifr.ifr_flags & ~flags_clear) | flags_set;
  if (flags_new != ifr.ifr_flags) {
    ifr.ifr_flags = flags_new;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
      perror("Cannot set interface flags");
      return -1;
    }
  }

  return 0;
}

int tuncat_if_create_tun_interface(int sock, const char *ifname,
                                   enum ifmode ifmode) {
  int fd;
  struct ifreq ifr;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("open");
    return -1;
  }
  if (getuid() != geteuid()) {
    if (ioctl(fd, TUNSETOWNER, getuid()) < 0) {
      perror("Error while setting tunnel owner");
      return -1;
    }
  }
  if (getgid() != getegid()) {
    if (ioctl(fd, TUNSETGROUP, getgid()) < 0) {
      perror("Error while setting tunnel group");
      return -1;
    }
    if (setgid(getgid()) < 0) {
      perror("Error while setting group id");
      return -1;
    }
  }
  if (getuid() != geteuid()) {
    if (setuid(getuid()) < 0) {
      perror("Error while setting user id");
      return -1;
    }
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

#ifdef IFF_NO_PI
  ifr.ifr_flags |= IFF_NO_PI;
#endif

  if (ifname) {
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  }
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("Error while creating tunnel interface");
    return -1;
  }

  if (tuncat_if_change_flags(sock, ifr.ifr_name, 0, IFF_UP | IFF_RUNNING) < 0) {
    return -1;
  }

  return fd;
}

int tuncat_if_get_index(int sock, const char *ifname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    return 0;
  }

  return ifr.ifr_ifindex;
}

int tuncat_if_create_bridge(int sock, const char *brname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  if (ioctl(sock, SIOCBRADDBR, &ifr) < 0) {
    perror("Cannot create bridge device");
    return -1;
  }

  return 0;
}

int tuncat_if_delete_bridge(int sock, const char *brname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  if (ioctl(sock, SIOCBRDELBR, &ifr) < 0) {
    perror("Cannot delete bridge device");
    return -1;
  }

  return 0;
}

int tuncat_if_add_bridge_member(int sock, const char *brname,
                                const char *ifname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  ifr.ifr_ifindex = tuncat_if_get_index(sock, ifname);
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

static const struct brcache {
  const char *brname;
  const struct brcache *next;
} *g_brcache = NULL;

void tuncat_if_register_created_brname(const char *brname) {
  const struct brcache *old = g_brcache;
  if (brname == NULL)
    brname = "";
  size_t pointer_align = alignof(void *);
  size_t brname_size = strlen(brname) + 1;
  size_t brcache_offset =
      (brname_size + pointer_align - 1) & ~(pointer_align - 1);
  void *buf = malloc(brcache_offset + sizeof(struct brcache));
  struct brcache *brcache = buf + brcache_offset;
  memset(buf, 0, brcache_offset);
  strcpy((void *)brcache->brname, brname);
  brcache->next = old;
  g_brcache = brcache;
}

const char *tuncat_if_finalize_created_brname(void) {
  if (g_brcache == NULL)
    return NULL;
  const struct brcache *old = g_brcache;
  g_brcache = old->next;
  const char *name = old->brname;
  return name;
}

void tuncat_if_finalize_created_brname_on_exit(int status, void *arg) {
  (void)status;
  const char *brname = arg;
  int sock;

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return;
  }
  tuncat_if_change_flags(sock, brname, IFF_UP, 0);
  tuncat_if_delete_bridge(sock, brname);
  close(sock);
}

void tuncat_if_finalize_created_brname_on_signal(int sig) {
  (void)sig;
  while (1) {
    const char *brname = tuncat_if_finalize_created_brname();
    tuncat_if_finalize_created_brname_on_exit(128 + sig, (void *)brname);
    free((void *)brname);
  }
}

static int tuncat_if_set_addr_ipv6(int sock6, const char *ifname,
                                   const char *addrstr) {
  struct in6_ifreq ifr6;
  struct in6_addr addr6;

  memset(&addr6, 0, sizeof(addr6));
  int masksize = inet_net_pton(AF_INET6, addrstr, &addr6, sizeof(addr6));
  if (masksize < 0) {
    fprintf(stderr, "Invalid address\n");
    return -1;
  }

  int ifindex = tuncat_if_get_index(sock6, ifname);
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

static int tuncat_addr_compare(int family, const void *addr1,
                               const void *addr2) {
  if (family == AF_INET) {
    return memcmp(addr1, addr2, sizeof(struct in_addr));
  } else if (family == AF_INET6) {
    return memcmp(addr1, addr2, sizeof(struct in6_addr));
  } else {
    assert("Invalid family" == NULL);
  }
}

static int tuncat_addr_convert_nwaddr(const void *addr, int bits,
                                      void *nwaddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *networkaddr4 = (struct in_addr *)nwaddr;
  uint32_t mask = htonl(~((1 << (32 - bits)) - 1));
  networkaddr4->s_addr = addr4->s_addr & mask;
  return 0;
}

static int tuncat_addr_convert_braddr(const void *addr, int bits,
                                      void *braddr) {
  if (bits < 0 || bits > 32) {
    return -1;
  }
  struct in_addr *addr4 = (struct in_addr *)addr;
  struct in_addr *bcastaddr4 = (struct in_addr *)braddr;
  uint32_t mask = htonl(~((1 << (32 - bits)) - 1));
  bcastaddr4->s_addr = (addr4->s_addr & mask) | ~mask;
  return 0;
}

static int tuncat_addr_convert_nwmask(int family, int bits, void *nwmask) {
  if (family == AF_INET) {
    if (bits < 0 || bits > 32) {
      return -1;
    }
    struct in_addr *mask4 = nwmask;
    mask4->s_addr = htonl(~((1 << (32 - bits)) - 1));
  } else if (family == AF_INET6) {
    if (bits < 0 || bits > 128) {
      return -1;
    }
    struct in6_addr *mask6 = nwmask;
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

static int tuncat_if_set_addr(int sock, const char *ifname,
                              const char *addrstr) {
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
    if (tuncat_addr_convert_nwmask(AF_INET, masklen, &mask.sin_addr) < 0) {
      break;
    }

    memset(&nwork, 0, sizeof(nwork));
    nwork.sin_family = AF_INET;
    nwork.sin_port = 0;
    if (tuncat_addr_convert_nwaddr(&addr.sin_addr, masklen, &nwork.sin_addr) <
        0) {
      break;
    }

    memset(&bcast, 0, sizeof(bcast));
    bcast.sin_family = AF_INET;
    bcast.sin_port = 0;
    if (tuncat_addr_convert_braddr(&addr.sin_addr, masklen, &bcast.sin_addr) <
        0) {
      break;
    }

    if (masklen < 31) {
      // check except netmask is /31 or /31, see RFC 3021
      if (tuncat_addr_compare(AF_INET, &addr.sin_addr, &nwork.sin_addr) == 0) {
        fprintf(stderr, "Cannot set address as network address\n");
        break;
      }
      if (tuncat_addr_compare(AF_INET, &addr.sin_addr, &bcast.sin_addr) == 0) {
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
      if (tuncat_if_change_flags(sock, ifname, 0, IFF_BROADCAST) < 0) {
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
      if (tuncat_if_change_flags(sock, ifname, IFF_BROADCAST, 0) < 0) {
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
  if (tuncat_if_set_addr_ipv6(sock6, ifname, addrstr) < 0) {
    close(sock6);
    return -1;
  }
  close(sock6);

  return 0;
}

int tuncat_if_init(struct tuncat_optspec *optsp) {
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
      if (tuncat_if_get_index(sock, ifname) == 0) {
        if (i < 999)
          break;
        fprintf(stderr, "Cannot get interface index\n");
      }
    }
    tunname = ifname;
  }

  int tunfd = tuncat_if_create_tun_interface(sock, tunname, optsp->ifmode);
  if (tunfd == -1) {
    return EXIT_FAILURE;
  }

  if (optsp->brname == NULL) {
    if (optsp->addr != NULL) {
      if (tuncat_if_set_addr(sock, tunname, optsp->addr) < 0) {
        return EXIT_FAILURE;
      }
    }

  } else {
    int brindex;

    brindex = tuncat_if_get_index(sock, optsp->brname);
    if (brindex == 0) {
      brindex = tuncat_if_create_bridge(sock, optsp->brname);
      if (brindex == -1) {
        return EXIT_FAILURE;
      }
      on_exit(tuncat_if_finalize_created_brname_on_exit, optsp->brname);
      struct sigaction sa;
      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = tuncat_if_finalize_created_brname_on_signal;
      sigaction(SIGINT, &sa, NULL);
      sigaction(SIGTERM, &sa, NULL);
    }

    if (tuncat_if_change_flags(sock, optsp->brname, 0, IFF_UP | IFF_RUNNING) <
        0) {
      return EXIT_FAILURE;
    }

    if (optsp->addr != NULL) {
      if (tuncat_if_set_addr(sock, optsp->brname, optsp->addr) < 0) {
        return EXIT_FAILURE;
      }
    }

    if (tuncat_if_add_bridge_member(sock, optsp->brname, tunname) < 0) {
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
        if (tuncat_if_add_bridge_member(
                sock, tuncat_if_finalize_created_brname(), ifname) < 0) {
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
