#include "tuncat_opt.h"
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int tuncat_parse_opts(struct tuncat_commandline_options *popts, int argc,
                      char *const argv[]) {
  struct tuncat_commandline_options opts = {0};
  int opt;
  int optindex = 0;
  struct option longopts[] = {
      {"ifname", required_argument, NULL, 'n'},
      {"ifaddress", required_argument, NULL, 'a'},
      {"tunnel-mode", required_argument, NULL, 'm'},
      {"bridge-name", required_argument, NULL, 'b'},
      {"bridge-members", required_argument, NULL, 'i'},
      {"transfer-mode", required_argument, NULL, 't'},
      {"address", required_argument, NULL, 'l'},
      {"port", required_argument, NULL, 'p'},
      {"ipv4", no_argument, NULL, '4'},
      {"ipv6", no_argument, NULL, '6'},
      {"mptcp", no_argument, NULL, 'M'},
      {"compress", no_argument, NULL, 'c'},
      {"max-frame-size", required_argument, NULL, 'F'},
      {"ifbuffer-size", required_argument, NULL, 'I'},
      {"trbuffer-size", required_argument, NULL, 'T'},
      {"version", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };
  while ((opt = getopt_long(argc, argv, "m:n:b:i:a:t:l:p:46McI:T:F:vh",
                            longopts, &optindex)) != -1) {
    switch (opt) {

    case 'm':
      assert(optarg != NULL);
      if (opts.ifmode != IFMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -m\n");
        print_usage(stderr);
        return -1;
      }
      if (strcasecmp(optarg, IFMODE_L2_OPT) == 0) {
        opts.ifmode = IFMODE_L2;
      } else if (strcasecmp(optarg, IFMODE_L3_OPT) == 0) {
        opts.ifmode = IFMODE_L3;
      } else {
        fprintf(stderr, "Invalid tunnel interface mode \"%s\"\n", optarg);
        print_usage(stderr);
        return -1;
      }
      break;

    case 'n':
      assert(optarg != NULL);
      if (opts.ifname != NULL) {
        fprintf(stderr, "Duplicated option -n\n");
        print_usage(stderr);
        return -1;
      }
      opts.ifname = optarg;
      break;

    case 'a':
      assert(optarg != NULL);
      if (opts.addr != NULL) {
        fprintf(stderr, "Duplicated option -a\n");
        print_usage(stderr);
        return -1;
      }
      opts.addr = optarg;
      break;

    case 'b':
      assert(optarg != NULL);
      if (opts.brname != NULL) {
        fprintf(stderr, "Duplicated option -b\n");
        print_usage(stderr);
        return -1;
      }
      opts.brname = optarg;
      break;

    case 'i':
      assert(optarg != NULL);
      if (opts.braddifname != NULL) {
        fprintf(stderr, "Duplicated option -i\n");
        print_usage(stderr);
        return -1;
      }
      opts.braddifname = optarg;
      break;

    case 't':
      assert(optarg != NULL);
      if (opts.trmode != TRMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -t\n");
        print_usage(stderr);
        return -1;
      }
      if (strcmp(optarg, TRMODE_STDIO_OPT) == 0) {
        opts.trmode = TRMODE_STDIO;
      } else if (strcmp(optarg, TRMODE_SERVER_OPT) == 0) {
        opts.trmode = TRMODE_SERVER;
      } else if (strcmp(optarg, TRMODE_CLIENT_OPT) == 0) {
        opts.trmode = TRMODE_CLIENT;
      } else {
        fprintf(stderr, "Invalid transfer mode \"%s\"\n", optarg);
        print_usage(stderr);
        return -1;
      }
      break;

    case 'l':
      assert(optarg != NULL);
      if (opts.node != NULL) {
        fprintf(stderr, "Duplicated option -l\n");
        print_usage(stderr);
        return -1;
      }
      opts.node = optarg;
      break;

    case 'p':
      assert(optarg != NULL);
      if (opts.port != NULL) {
        fprintf(stderr, "Duplicated option -p\n");
        print_usage(stderr);
        return -1;
      }
      opts.port = optarg;
      break;

    case '4':
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr);
        return -1;
      }
      opts.ipmode = IPMODE_IPV4;
      break;

    case '6':
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr);
        return -1;
      }
      opts.ipmode = IPMODE_IPV6;
      break;

    case 'M':
      if (opts.mptcp) {
        fprintf(stderr, "Duplicated option -M\n");
        print_usage(stderr);
        return -1;
      }
      opts.mptcp = 1;
      break;

    case 'c':
      if (opts.compflag != COMPFLAG_UNSPEC) {
        fprintf(stderr, "Duplicated option -c\n");
        print_usage(stderr);
        return -1;
      }
      opts.compflag = COMPFLAG_COMPRESS;
      break;

    case 'F':
      if (opts.max_frame_size != 0) {
        fprintf(stderr, "Duplicated option -F\n");
        print_usage(stderr);
        return -1;
      }
      {
        char *p;
        opts.max_frame_size = strtoul(optarg, &p, 0);
        if (p == optarg || *p != '\0') {
          fprintf(stderr, "Invalid option value -F\n");
          print_usage(stderr);
          return -1;
        }
        if (opts.max_frame_size < IF_MAX_FRAME_SIZE_MIN ||
            opts.max_frame_size > IF_MAX_FRAME_SIZE_MAX) {
          fprintf(stderr, "Invalid option value -F\n");
          print_usage(stderr);
          return -1;
        }
      }
      break;
    case 'I':
      if (opts.ifbuffer_size != 0) {
        fprintf(stderr, "Duplicated option -I\n");
        print_usage(stderr);
        return -1;
      }
      {
        char *p;
        opts.ifbuffer_size = strtoul(optarg, &p, 0);
        if (p == optarg || *p != '\0') {
          fprintf(stderr, "Invalid option value -I\n");
          print_usage(stderr);
          return -1;
        }
        if (opts.ifbuffer_size < IF_BUFFER_SIZE_MIN ||
            opts.ifbuffer_size > IF_BUFFER_SIZE_MAX) {
          fprintf(stderr, "Invalid option value -I\n");
          print_usage(stderr);
          return -1;
        }
      }
      break;
    case 'T':
      if (opts.trbuffer_size != 0) {
        fprintf(stderr, "Duplicated option -T\n");
        print_usage(stderr);
        return -1;
      }
      {
        char *p;
        opts.trbuffer_size = strtoul(optarg, &p, 0);
        if (p == optarg || *p != '\0') {
          fprintf(stderr, "Invalid option value -T\n");
          print_usage(stderr);
          return -1;
        }
        if (opts.trbuffer_size < TR_BUFFER_SIZE_MIN ||
            opts.trbuffer_size > TR_BUFFER_SIZE_MAX) {
          fprintf(stderr, "Invalid option value -T\n");
          print_usage(stderr);
          return -1;
        }
      }
      break;
    case 'v':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      exit(EXIT_SUCCESS);
    case 'h':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      print_usage(stdout);
      exit(EXIT_SUCCESS);
    default:
      fprintf(stderr, "Invalid option -%c\n", optopt);
      print_usage(stderr);
      return -1;
    }
  }
  *popts = opts;
  return 0;
}

int tuncat_check_opt(struct tuncat_commandline_options opts) {
  if (opts.ifmode == IFMODE_UNSPEC) {
    opts.ifmode = IFMODE_DEFAULT;
  }

  if (opts.brname != NULL && opts.ifmode == IFMODE_L3) {
    fprintf(stderr, "-b is not supported for L3 mode\n");
    print_usage(stderr);
    return -1;
  }

  switch (opts.trmode) {

  case TRMODE_UNSPEC:
    opts.trmode = TRMODE_DEFAULT;
    break;

  case TRMODE_STDIO:
    if (opts.node != NULL) {
      fprintf(stderr, "-l is not supported for stdio mode\n");
      print_usage(stderr);
      return -1;
    }
    if (opts.port != NULL) {
      fprintf(stderr, "-p is not supported for stdio mode\n");
      print_usage(stderr);
      return -1;
    }
    if (opts.ipmode != 0) {
      fprintf(stderr, "-4 or -6 is not supported for stdio mode\n");
    }
    break;

  case TRMODE_SERVER:
    break;

  case TRMODE_CLIENT:
    if (opts.node == NULL) {
      fprintf(stderr, "-l is required for client mode\n");
      print_usage(stderr);
      return -1;
    }
    break;
  }

  if (opts.port == NULL) {
    opts.port = PORT_DEFAULT;
  }

  if (opts.braddifname != NULL && opts.brname == NULL) {
    fprintf(stderr, "-i is not supported without -b\n");
    print_usage(stderr);
    return -1;
  }
  return 0;
}
