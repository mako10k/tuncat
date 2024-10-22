#include <alloca.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h> // must be before <linux/if.h>

#include <errno.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <netinet/in.h>
#include <snappy-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tuncat.h"

void print_usage(FILE *fp, int argc, char *const argv[]) {
  fprintf(fp, "\n");
  fprintf(fp, "Usage:\n");
  fprintf(fp, "  %s [options]\n", argv[0]);
  fprintf(fp, "\n");
  fprintf(fp, "Options:\n");
  fprintf(fp, "  -n,--ifname=<name>          Interface name\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L3 payload mode%s\n", IFMODE_TUN_OPT,
          strcmp(IFMODE_DEFAULT_OPT, IFMODE_TUN_OPT) == 0 ? "  (default)" : "");
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L2 payload mode%s\n", IFMODE_TAP_OPT,
          strcmp(IFMODE_DEFAULT_OPT, IFMODE_TAP_OPT) == 0 ? " (default)" : "");
  fprintf(fp, "  -b,--bridge-name=<name>     Bridge interface (L2 payload)\n");
  fprintf(fp, "  -i,--bridge-members=<ifname>[,<if_name>...]\n");
  fprintf(fp, "                              Bridge members   (L2 payload)\n");
  fprintf(fp, "  -t,--userspace-mode=%-6s  Stdio mode%s\n", TRMODE_STDIO_OPT,
          strcmp(TRMODE_DEFAULT_OPT, TRMODE_STDIO_OPT) == 0 ? "       (default)"
                                                            : "");
  fprintf(
      fp, "  -t,--userspace-mode=%-6s  TCP server mode%s\n", TRMODE_SERVER_OPT,
      strcmp(TRMODE_DEFAULT_OPT, TRMODE_SERVER_OPT) == 0 ? "  (default)" : "");
  fprintf(
      fp, "  -t,--userspace-mode=%-6s  TCP client mode%s\n", TRMODE_CLIENT_OPT,
      strcmp(TRMODE_DEFAULT_OPT, TRMODE_CLIENT_OPT) == 0 ? "  (default)" : "");
  fprintf(fp, "  -l,--address=<addr>         Listen Address   (default: any) "
              "  (TCP server)\n");
  fprintf(fp,
          "  -p,--port=<port>            Listen port      (default: %5s) (TCP "
          "server)\n",
          PORT_DEFAULT);
  fprintf(fp, "  -l,--address=<addr>         Connect Address  (required)       "
              "(TCP client)\n");
  fprintf(fp,
          "  -p,--port=<port>            Connect Port     (default: %5s) (TCP "
          "client)\n",
          PORT_DEFAULT);
  fprintf(fp, "  -4,--ipv4                   Force ipv4       (TCP server or "
              "TCP client)\n");
  fprintf(fp, "  -6,--ipv6                   Force ipv6       (TCP server or "
              "TCP client)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -c,--compress               Compress mode\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -v,--version                Print version\n");
  fprintf(fp, "  -h,--help                   Print this usage\n");
  fprintf(fp, "\n");
}

char *brname = NULL;

void cleanbr() {
  if (brname) {
    struct ifreq ifr;
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket");
      return;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, brname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
      perror("Cannot get bridge device flags");
      return;
    }
    if ((ifr.ifr_flags & IFF_UP) == 0) {
      ifr.ifr_flags &= ~IFF_UP;
      if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Cannot set bridge device flags");
        return;
      }
    }
    if (ioctl(sock, SIOCBRDELBR, brname) < 0) {
      perror("Cannot delete bridge device");
    }
  }
}

int forward_packets(int argc, char *const argv[], struct tuncat_opts *optsp,
                    int tr_ifd, int tr_ofd) {
  size_t if_isiz, if_osiz, tr_isiz, tr_osiz;
  char *if_ibuf, *if_obuf, *tr_ibuf, *tr_obuf;
  int fd, if_ifd, if_ofd;
  struct ifreq ifr;
  size_t if_ipos, if_opos, tr_ipos, tr_opos;
  int compflag;

  compflag = optsp->compflag == COMPFLAG_COMPRESS;

  if_isiz = IF_BUFFER_SIZE;
  if_osiz = IF_BUFFER_SIZE;
  tr_isiz = TR_BUFFER_SIZE(if_osiz);
  tr_osiz = TR_BUFFER_SIZE(if_isiz);

  if_ibuf = alloca(if_isiz);
  if_obuf = alloca(if_osiz);
  tr_ibuf = alloca(tr_isiz);
  tr_obuf = alloca(tr_osiz);

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("open");
    return EXIT_FAILURE;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  if (optsp->ifmode == IFMODE_TUN)
    ifr.ifr_flags = IFF_TUN;
  if (optsp->ifmode == IFMODE_TAP)
    ifr.ifr_flags = IFF_TAP;

  if (optsp->ifname) {
    strncpy(ifr.ifr_name, optsp->ifname, IFNAMSIZ);
  }
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("Error while creating tunnel interface");
    return EXIT_FAILURE;
  }

  {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
      perror("socket");
      return EXIT_FAILURE;
    }

    if (ioctl(sock, SIOCGIFFLAGS, (void *)&ifr) < 0) {
      perror("ioctl(SIOCGIFFLAGS)");
      return EXIT_FAILURE;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, (void *)&ifr) < 0) {
      perror("ioctl(SIOCSIFFLAGS)");
      return EXIT_FAILURE;
    }

    if (optsp->brname != NULL) {
      int ifindex, brindex;

      ifindex = if_nametoindex(ifr.ifr_name);
      if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex(\"%s\")\n", ifr.ifr_name);
        return EXIT_FAILURE;
      }

      brindex = if_nametoindex(optsp->brname);
      if (brindex == 0) {
        if (ioctl(sock, SIOCBRADDBR, optsp->brname) < 0) {
          perror("Cannot create bridge device");
          print_usage(stderr, argc, argv);
          return EXIT_FAILURE;
        }
        brname = optsp->brname;
        atexit(cleanbr);
      }

      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, optsp->brname, IFNAMSIZ);

      if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Cannot get bridge device flags");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if ((ifr.ifr_flags & IFF_UP) == 0) {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
          perror("Cannot set bridge device flags");
          print_usage(stderr, argc, argv);
          return EXIT_FAILURE;
        }
      }
      ifr.ifr_ifindex = ifindex;
      if (ioctl(sock, SIOCBRADDIF, (void *)&ifr) < 0) {
        perror("Invalid bridge device");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (optsp->braddifname) {
        int i, len = strlen(optsp->braddifname);
        char *braddifname = alloca(len + 1);
        char *ifname, *ifn;

        ifname = strcpy(braddifname, optsp->braddifname);
        for (;;) {
          if ((ifn = strchr(ifname, ','))) {
            *ifn = '\0';
          }
          ifindex = if_nametoindex(ifname);
          if (ifindex == 0) {
            fprintf(stderr, "if_nametoindex(\"%s\")\n", ifname);
            return EXIT_FAILURE;
          }
          memset(&ifr, 0, sizeof(ifr));
          strncpy(ifr.ifr_name, optsp->brname, IFNAMSIZ);
          ifr.ifr_ifindex = ifindex;
          if (ioctl(sock, SIOCBRADDIF, (void *)&ifr) < 0) {
            char *mes = alloca(256 + strlen(ifname) + strlen(ifr.ifr_name));
            sprintf(mes, "warn: cannot append %s to %s", ifname, ifr.ifr_name);
            perror(mes);
          }
          if (!ifn) {
            break;
          }
          ifname = ifn + 1;
        }
      }
    }

    close(sock);
  }

  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return EXIT_FAILURE;
  }
  if (fcntl(tr_ifd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return EXIT_FAILURE;
  }
  if (tr_ifd != tr_ofd && fcntl(tr_ofd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return EXIT_FAILURE;
  }

  if_ifd = fd;
  if_ofd = fd;

  if_ipos = 0;
  if_opos = 0;
  tr_ipos = 0;
  tr_opos = 0;
  for (;;) {
    int nfds;
    fd_set rfds, wfds;
    nfds = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    // If there is some data on Interface Input Buffer(IIB),
    // and the IIB has enough space to compress.
    // then compress and move it to Transport Output Buffer(TOB).
    if (if_ipos > 0) // IIB is not empty
    {
      size_t tr_oavl = tr_osiz - tr_opos; // TOB writable size
      size_t tr_csiz = compflag ? 2 + snappy_max_compressed_length(if_ipos)
                                : if_ipos; // TOB requirement size
      if (tr_oavl >= tr_csiz) {
        size_t opos;

        if (compflag) {
          opos = tr_oavl - 2;
          if (snappy_compress(if_ibuf, if_ipos, tr_obuf + tr_opos + 2, &opos) !=
              SNAPPY_OK) {
            fprintf(stderr, "Fatal: snappy_compress failed\n");
            return EXIT_FAILURE;
          }
        } else {
          memcpy(tr_obuf + tr_opos + 2, if_ibuf, if_ipos);
          opos = if_ipos;
        }
        // fprintf(stderr, "IIB(%u) -> TOB(%u) (compress: %u)\n", if_ipos,
        // tr_opos, 2 + opos);
        *(tr_obuf + tr_opos + 0) = opos >> 8;
        *(tr_obuf + tr_opos + 1) = opos & 255;
        tr_opos += 2 + opos;
        if_ipos = 0;
        continue;
      }
    }

    if (if_opos == 0 && tr_ipos >= 2) {
      size_t ipos;

      ipos = (*((unsigned char *)tr_ibuf + 0) << 8) +
             (*((unsigned char *)tr_ibuf + 1) & 255);
      // fprintf(stderr, "Input Transfer Packet Size : %u(Received: %d)\n",
      // ipos, tr_ipos);
      if (tr_ipos >= 2 + ipos) {
        size_t osiz;

        if (compflag) {
          osiz = if_osiz;
          if (snappy_uncompress(tr_ibuf + 2, ipos, if_obuf, &osiz) !=
              SNAPPY_OK) {
            fprintf(stderr, "Warn: Invalid transfer input stream\n");
            tr_ipos = 0; // reset TIB
            continue;
          }
        } else {
          memcpy(if_obuf, tr_ibuf + 2, ipos);
          osiz = ipos;
        }
        // fprintf(stderr, "TIB(%u) -> IOB(%u) (uncompress: %u)\n", tr_ipos,
        // if_opos, osiz);
        tr_ipos -= ipos + 2;
        if_opos += osiz;
        if (tr_ipos > 0) {
          memmove(tr_ibuf, tr_ibuf + ipos + 2, tr_ipos);
        }
        continue;
      }
    }

    if (tr_ipos < tr_osiz) {
      FD_SET(tr_ifd, &rfds);
      if (nfds <= tr_ifd)
        nfds = tr_ifd + 1;
    }
    if (tr_opos > 0) {
      FD_SET(tr_ofd, &wfds);
      if (nfds <= tr_ofd)
        nfds = tr_ofd + 1;
    }
    if (if_ipos == 0) {
      FD_SET(if_ifd, &rfds);
      if (nfds <= if_ifd)
        nfds = if_ifd + 1;
    }
    if (if_opos > 0) {
      FD_SET(if_ofd, &wfds);
      if (nfds <= if_ofd)
        nfds = if_ofd + 1;
    }
    if (nfds == 0) {
      fprintf(stderr,
              "(tr_ipos: %zu, tr_opos: %zu, if_ipos: %zu, if_opos: %zu)\n",
              tr_ipos, tr_opos, if_ipos, if_opos);
      return EXIT_SUCCESS;
    }
    if ((nfds = select(nfds, &rfds, &wfds, NULL, NULL)) == -1) {
      perror("select");
      return EXIT_FAILURE;
    }
    if (FD_ISSET(if_ifd, &rfds)) {
      ssize_t rsiz;

      rsiz = read(if_ifd, if_ibuf, if_isiz);
      if (rsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read");
        return EXIT_FAILURE;
      }
      if (rsiz == 0) {
        // fprintf (stderr, "II closed\n");
        return EXIT_SUCCESS;
      }
      // fprintf(stderr, "II(%u) -> IIB(%u)\n", rsiz, if_ipos);
      if_ipos += rsiz;
      continue;
    }
    if (FD_ISSET(if_ofd, &wfds)) {
      ssize_t wsiz;

      wsiz = write(if_ofd, if_obuf, if_opos);
      if (wsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write");
        return EXIT_FAILURE;
      }
      // fprintf(stderr, "IOB(%u) -> IO(%u)\n", if_opos, wsiz);
      if_opos -= wsiz;
      if (if_opos > 0) {
        memmove(if_obuf, if_obuf + wsiz, if_opos);
      }
      continue;
    }

    if (FD_ISSET(tr_ifd, &rfds)) {
      ssize_t rsiz;

      rsiz = read(tr_ifd, tr_ibuf + tr_ipos, tr_isiz - tr_ipos);
      if (rsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read");
        return EXIT_FAILURE;
      }
      if (rsiz == 0) {
        // fprintf (stderr, "TI closed\n");
        return EXIT_SUCCESS;
      }
      // fprintf(stderr, "TI(%u) -> TIB (%u)\n", rsiz, tr_ipos);
      tr_ipos += rsiz;
      continue;
    }
    if (FD_ISSET(tr_ofd, &wfds)) {
      ssize_t wsiz;

      wsiz = write(tr_ofd, tr_obuf, tr_opos);
      if (wsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write");
        return EXIT_FAILURE;
      }
      // fprintf(stderr, "TOB(%u) -> TO(%u)\n", tr_opos, wsiz);
      tr_opos -= wsiz;
      if (tr_opos > 0) {
        memmove(tr_obuf, tr_obuf + wsiz, tr_opos);
      }
      continue;
    }
  }
}

int main(int argc, char *const argv[]) {
  int sock;

  int opt;
  struct tuncat_opts opts;
  struct option longopts[] = {
      {"ifname", required_argument, NULL, 'n'},
      {"tunnel-mode", required_argument, NULL, 'm'},
      {"bridge-name", required_argument, NULL, 'b'},
      {"bridge-members", required_argument, NULL, 'i'},
      {"userspace-mode", required_argument, NULL, 't'},
      {"address", required_argument, NULL, 'l'},
      {"port", required_argument, NULL, 'p'},
      {"ipv4", no_argument, NULL, '4'},
      {"ipv6", no_argument, NULL, '6'},
      {"compress", no_argument, NULL, 'c'},
      {"version", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  memset(&opts, 0, sizeof(opts));

  int optindex = 0;
  while ((opt = getopt_long(argc, argv, "m:n:b:i:t:l:p:46cvh", longopts,
                            &optindex)) != -1) {
    switch (opt) {
    case 'm':
      if (opts.ifmode != 0) {
        fprintf(stderr, "Duplicated option -m\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcmp(optarg, IFMODE_TAP_OPT) == 0) {
        opts.ifmode = IFMODE_TAP;
      } else if (strcmp(optarg, IFMODE_TUN_OPT) == 0) {
        opts.ifmode = IFMODE_TUN;
      } else {
        fprintf(stderr, "Invalid tunnel interface mode \"%s\"\n", optarg);
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      break;
    case 'n':
      if (opts.ifname != NULL) {
        fprintf(stderr, "Duplicated option -n\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ifname = optarg;
      break;
    case 'b':
      if (opts.brname != NULL) {
        fprintf(stderr, "Duplicated option -b\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.brname = optarg;
      break;
    case 'i':
      if (opts.braddifname != NULL) {
        fprintf(stderr, "Duplicated option -i\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.braddifname = optarg;
      break;
    case 't':
      if (opts.trmode != 0) {
        fprintf(stderr, "Duplicated option -t\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcmp(optarg, TRMODE_STDIO_OPT) == 0) {
        opts.trmode = TRMODE_STDIO;
      } else if (strcmp(optarg, TRMODE_SERVER_OPT) == 0) {
        opts.trmode = TRMODE_SERVER;
      } else if (strcmp(optarg, TRMODE_CLIENT_OPT) == 0) {
        opts.trmode = TRMODE_CLIENT;
      } else {
        fprintf(stderr, "Invalid transfer mode \"%s\"\n", optarg);
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      break;
    case 'l':
      if (opts.node != NULL) {
        fprintf(stderr, "Duplicated option -l\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.node = optarg;
      break;
    case 'p':
      if (opts.port != NULL) {
        fprintf(stderr, "Duplicated option -p\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.port = optarg;
      break;
    case '4':
      if (opts.ipmode != 0) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV4;
      break;
    case '6':
      if (opts.ipmode != 0) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV6;
      break;
    case 'c':
      if (opts.compflag) {
        fprintf(stderr, "Duplicated option -c\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.compflag = 1;
      break;
    case 'v':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      return EXIT_SUCCESS;
    case 'h':
      fprintf(stdout, "%s : Create tunnel interface\n", PACKAGE_STRING);
      print_usage(stdout, argc, argv);
      return EXIT_SUCCESS;
    default:
      fprintf(stderr, "Invalid option -%c\n", optopt);
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
  }

  if (opts.ifmode == 0) {
    opts.ifmode = IFMODE_DEFAULT;
  }

  if (opts.brname != NULL && opts.ifmode == IFMODE_TUN) {
    fprintf(stderr, "-b is not supported for tun mode\n");
    print_usage(stderr, argc, argv);
    return EXIT_FAILURE;
  }

  if (opts.trmode == 0) {
    opts.trmode = TRMODE_DEFAULT;
  }

  if (opts.trmode == TRMODE_STDIO) {
    if (opts.node != NULL) {
      fprintf(stderr, "-l is not supported for stdio mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    if (opts.port != NULL) {
      fprintf(stderr, "-p is not supported for stdio mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    if (opts.ipmode != 0) {
      fprintf(stderr, "-4 or -6 is not supported for stdio mode\n");
    }
  }

  if (opts.trmode == TRMODE_CLIENT) {
    if (opts.node == NULL) {
      fprintf(stderr, "-l is required for client mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
  }

  if (opts.port == NULL) {
    opts.port = PORT_DEFAULT;
  }

  if (opts.braddifname != NULL && opts.brname == NULL) {
    fprintf(stderr, "-i is not supported without -b\n");
    print_usage(stderr, argc, argv);
    return EXIT_FAILURE;
  }
  if (opts.trmode == TRMODE_STDIO) {
    return forward_packets(argc, argv, &opts, 0, 1);
  }

  {
    struct addrinfo aih, *airp, *rp;
    int s;

    memset(&aih, 0, sizeof(aih));
    aih.ai_family = AF_UNSPEC;
    if (opts.ipmode == IPMODE_IPV4)
      aih.ai_family = AF_INET;
    if (opts.ipmode == IPMODE_IPV6)
      aih.ai_family = AF_INET6;
    if (opts.trmode == TRMODE_SERVER)
      aih.ai_flags = AI_PASSIVE;
    aih.ai_socktype = SOCK_STREAM;
    aih.ai_protocol = 0;
    aih.ai_canonname = NULL;
    aih.ai_addr = NULL;
    aih.ai_next = NULL;

    if ((s = getaddrinfo(opts.node, opts.port, &aih, &airp))) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      return EXIT_FAILURE;
    }

    for (rp = airp; rp; rp = rp->ai_next) {
      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == -1)
        continue;
      if (opts.trmode == TRMODE_SERVER) {
        if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
          break;
      } else {
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
          break;
      }
      close(sock);
    }

    if (rp == NULL) {
      fprintf(stderr, "Invalid host or port address\n");
      return EXIT_FAILURE;
    }

    freeaddrinfo(airp);
  }
  if (opts.trmode == TRMODE_SERVER) {

    if (listen(sock, 5) == -1) {
      perror("listen");
      close(sock);
      return EXIT_FAILURE;
    }

    for (;;) {
      int csock;
      struct sockaddr caddr;
      socklen_t clen;
      pid_t pid;

      waitpid(-1, NULL, WNOHANG);

      clen = sizeof(caddr);
      csock = accept(sock, &caddr, &clen);
      if (csock == -1) {
        perror("accept");
        return EXIT_FAILURE;
      }

      pid = fork();
      if (pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
      }

      if (pid == 0) {
        close(sock);
        return forward_packets(argc, argv, &opts, csock, csock);
      }

      close(csock);
    }
  } else {
    return forward_packets(argc, argv, &opts, sock, sock);
  }
}
