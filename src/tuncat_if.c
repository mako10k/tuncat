#include "tuncat_if.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <net/if.h> // must be before <linux/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int change_ifflags(int sock, const char *ifname, int flags_clear,
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

int create_tunif(int sock, const char *ifname, enum ifmode ifmode) {
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

  if (change_ifflags(sock, ifr.ifr_name, 0, IFF_UP | IFF_RUNNING) < 0) {
    return -1;
  }

  return fd;
}

int get_ifindex(int sock, const char *ifname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    return 0;
  }

  return ifr.ifr_ifindex;
}

int create_bridge(int sock, const char *brname) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, brname, IFNAMSIZ);
  if (ioctl(sock, SIOCBRADDBR, &ifr) < 0) {
    perror("Cannot create bridge device");
    return -1;
  }

  return 0;
}

int delete_bridge(int sock, const char *brname) {
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

static const struct brcache {
  const char *brname;
  const struct brcache *next;
} *g_brcache = NULL;

void add_brname(const char *brname) {
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

const char *remove_brname() {
  if (g_brcache == NULL)
    return NULL;
  const struct brcache *old = g_brcache;
  g_brcache = old->next;
  const char *name = old->brname;
  return name;
}

void cleanbr(int status, void *arg) {
  (void)status;
  const char *brname = arg;
  int sock;

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return;
  }
  change_ifflags(sock, brname, IFF_UP, 0);
  delete_bridge(sock, brname);
  close(sock);
}

void cleanbr_sig(int sig) {
  (void)sig;
  while (1) {
    const char *brname = remove_brname();
    cleanbr(128 + sig, (void *)brname);
    free((void *)brname);
  }
}
