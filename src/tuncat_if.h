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

size_t read_if_frame_size(const char *ifrbuf, size_t ifrpos, size_t *ifrfsizep);

size_t write_if_frame_size(char *ifwbuf, size_t ifwlen, size_t ifwrfsize);

#define IF_FRAME_SIZE_LEN 2

#endif // __TUNCAT_IF_H__