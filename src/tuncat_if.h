#ifndef __TUNCAT_IF_H__
#define __TUNCAT_IF_H__

#include "tuncat.h"

int change_ifflags(int sock, const char *ifname, int flags_clear,
                   int flags_set);

int create_tunif(int sock, const char *ifname, enum ifmode ifmode);

int get_ifindex(int sock, const char *ifname);

int create_bridge(int sock, const char *brname);

int delete_bridge(int sock, const char *brname);

int add_bridge_member(int sock, const char *brname, const char *ifname);

void add_brname(const char *brname);

const char *remove_brname(void);

void cleanbr(int status, void *arg);

void cleanbr_sig(int sig);

#endif // __TUNCAT_IF_H__