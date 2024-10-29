#include "tuncat_net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * **inet6_net_pton** : getting numeric form of IPv6 Address and Netmask
 *
 * @param af  address family (AF_INET6 only)
 * @param cp  string form of IPv6 Address and Netmask
 * @param buf buffer to store numeric form of IPv6 Address
 * @param len length of buffer
 * @return    netmask bits
 */
static int inet6_net_pton(int af, const char *cp, void *buf, size_t len) {
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

int inet_net_pton(int af, const char *cp, void *buf, size_t len) {
  if (af == AF_INET)
#undef inet_net_pton
    return inet_net_pton(af, cp, buf, len);
#define inet_net_pton inet_net_pton_replaced
  if (af == AF_INET6)
    return inet6_net_pton(af, cp, buf, len);
  errno = EAFNOSUPPORT;
  return -1;
}
