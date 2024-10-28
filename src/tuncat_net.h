#ifndef __TUNCAT_NET_H__
#define __TUNCAT_NET_H__

#include "tuncat.h"
#include <stddef.h>

/**
 * **inet6_net_pton** : getting numeric form of IPv6 Address and Netmask
 *
 * @param af  address family (AF_INET6 only)
 * @param cp  string form of IPv6 Address and Netmask
 * @param buf buffer to store numeric form of IPv6 Address
 * @param len length of buffer
 * @return    netmask bits
 */
int inet6_net_pton(int af, const char *cp, void *buf, size_t len);

/**
 * **inet_net_pton_orig** : getting numeric form of IPv4 or IPv6 Address and
 * Netmask
 *
 * @param af  address family (AF_INET or AF_INET6)
 * @param cp  string form of IPv4 Address and Netmask
 * @param buf buffer to store numeric form of IPv4 Address
 * @param len length of buffer
 * @return    netmask bits
 */
int inet_net_pton_orig(int af, const char *cp, void *buf, size_t len);

#define inet_net_pton inet_net_pton_orig

#endif // __TUNCAT_NET_H__