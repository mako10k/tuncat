#include "tuncat_net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int inet6_net_pton(int af, const char *cp, void *buf, size_t len) {
  if (af != AF_INET6) {
    errno = EAFNOSUPPORT;
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
  return bits;
}

#ifdef inet_net_pton
#undef inet_net_pton
#endif

extern int inet_net_pton(int af, const char *cp, void *buf, size_t len);

int inet_net_pton_orig(int af, const char *cp, void *buf, size_t len) {
  if (af == AF_INET)
    return inet_net_pton(af, cp, buf, len);
  if (af == AF_INET6)
    return inet6_net_pton(af, cp, buf, len);
  errno = EAFNOSUPPORT;
  return -1;
}
