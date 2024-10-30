#ifndef __TUNCAT_IF_H__
#define __TUNCAT_IF_H__

#include "tuncat.h"

int tuncat_if_change_flags(int sock, const char *ifname, int flags_clear,
                           int flags_set);

int tuncat_if_create_tun_interface(int sock, const char *ifname,
                                   enum ifmode ifmode);

int tuncat_if_get_index(int sock, const char *ifname);

int tuncat_if_create_bridge(int sock, const char *brname);

int tuncat_if_delete_bridge(int sock, const char *brname);

int tuncat_if_add_bridge_member(int sock, const char *brname,
                                const char *ifname);

void tuncat_if_register_created_brname(const char *brname);

const char *tuncat_if_finalize_created_brname(void);

void tuncat_if_finalize_created_brname_on_exit(int status, void *arg);

void tuncat_if_finalize_created_brname_on_signal(int sig);

int tuncat_if_init(struct tuncat_optspec *optsp);

#endif // __TUNCAT_IF_H__