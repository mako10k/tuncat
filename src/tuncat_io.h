#pragma once
#include "tuncat.h"
#include "tuncat_opt.h"

int forward_packets(struct tuncat_commandline_options *optsp, int tunfd,
                    int tr_ifd, int tr_ofd);
int open_socket(struct tuncat_commandline_options opts);
