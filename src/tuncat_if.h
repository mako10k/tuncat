#pragma once
#include "tuncat.h"
#include "tuncat_opt.h"

int inet6_net_pton(int af, const char *cp, void *buf, size_t len);
int inet_net_pton_orig(int af, const char *cp, void *buf, size_t len);

int init_if(struct tuncat_commandline_options *optsp);

