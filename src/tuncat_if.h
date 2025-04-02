#pragma once
#include "tuncat.h"
#include "tuncat_opt.h"

int tuncat_inet_net_pton(int af, const char *cp, void *buf, size_t len);

int tuncat_if_init(struct tuncat_commandline_options *optsp);
