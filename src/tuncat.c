#include "tuncat.h"
#include "tuncat_if.h"

#include <net/if.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <pthread.h>
#include <snappy-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * **print_usage** : print usage
 *
 * @param fp    file pointer
 * @param argc  argument count
 * @param argv  argument vector
 */
static void print_usage(FILE *fp, int argc, char *const argv[]) {
  (void)argc;

#define ISDEFS(DEF, VAR) (VAR), (strcmp((DEF), (VAR)) == 0 ? "  (default)" : "")

  fprintf(fp, "\n");
  fprintf(fp, "Usage:\n");
  fprintf(fp, "  %s [options]\n", argv[0]);
  fprintf(fp, "\n");
  fprintf(fp, "Options:\n");
  fprintf(fp, "  -n,--ifname=<name>          Interface name\n");
  fprintf(fp,
          "  -a,--ifaddress=<addr>       Interface address (only with -n)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L3 payload mode%s\n",
          ISDEFS(IFMODE_DEFAULT_OPT, IFMODE_L3_OPT));
  fprintf(fp, "  -m,--tunnel-mode=%-6s     L2 payload mode%s\n",
          ISDEFS(IFMODE_DEFAULT_OPT, IFMODE_L2_OPT));
  fprintf(fp, "\n");
  fprintf(fp, "  -b,--bridge-name=<name>     Bridge interface (L2 payload)\n");
  fprintf(fp, "  -i,--bridge-members=<ifname>[,<if_name>...]\n");
  fprintf(
      fp,
      "                              Bridge members   (only with bridge)\n");
  fprintf(fp, "  -a,--ifaddress=<addr>       Bridge interface address (only "
              "with -b)\n");
  fprintf(fp, "\n");
  fprintf(fp, "  -t,--transfer-mode=%-6s   Stdio mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_STDIO_OPT));
  fprintf(fp, "  -t,--transfer-mode=%-6s   TCP server mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_SERVER_OPT));
  fprintf(fp, "  -t,--transfer-mode=%-6s   TCP client mode%s\n",
          ISDEFS(TRMODE_DEFAULT_OPT, TRMODE_CLIENT_OPT));
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

#define FRAME_LEN_MAX 65536
#define FRAME_LEN_SIZE 2
#define COMP_LEN_SIZE_MAX 3

/**
 * **tuncat_raw_to_frame** : read raw data from fd_raw and write frame data to
 * fd_frame
 *
 * @param fd_raw    file descriptor for raw data
 * @param fd_frame  file descriptor for frame data
 * @return 0 on success, -1 on failure
 */
static int tuncat_raw_to_frame(int fd_raw, int fd_frame) {
  assert(fd_raw >= 0);
  assert(fd_frame >= 0);
  char buf[FRAME_LEN_MAX + FRAME_LEN_SIZE];

  while (1) {
    ssize_t size_raw = read(fd_raw, buf + FRAME_LEN_SIZE, FRAME_LEN_MAX);
    if (size_raw == -1) {
      if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
          errno == EINPROGRESS) {
        continue;
      }
      perror("read raw");
      return -1;
    }
    assert(size_raw >= FRAME_LEN_SIZE);
    (*(uint16_t *)buf) = htons(size_raw);
    const size_t size_frame_to_write = size_raw + FRAME_LEN_SIZE;
    size_t size_frame_write_pos = 0;
    while (size_frame_write_pos < size_frame_to_write) {
      ssize_t size_frame_write =
          write(fd_frame, buf + size_frame_write_pos,
                size_frame_to_write - size_frame_write_pos);
      if (size_frame_write == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write frame");
        return -1;
      }
      size_frame_write_pos += size_frame_write;
    }
    if (size_raw == 0) {
      return 0;
    }
  }
}

/**
 * **tuncat_frame_to_raw** : read frame data from fd_frame and write raw data to
 * fd_raw
 *
 * @param fd_frame  file descriptor for frame data
 * @param fd_raw    file descriptor for raw data
 * @return 0 on success, -1 on failure
 */
static int tuncat_frame_to_raw(int fd_frame, int fd_raw) {
  assert(fd_frame >= 0);
  assert(fd_raw >= 0);
  char buf[FRAME_LEN_MAX + FRAME_LEN_SIZE];

  size_t size_frame_read_pos = 0;
  while (1) {
    while (size_frame_read_pos < FRAME_LEN_SIZE) {
      ssize_t size_frame_read = read(fd_frame, buf + size_frame_read_pos,
                                     sizeof(buf) - size_frame_read_pos);
      if (size_frame_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read frame");
        return -1;
      }
      if (size_frame_read == 0) {
        return 0;
      }
      size_frame_read_pos += size_frame_read;
    }
    assert(size_frame_read_pos >= FRAME_LEN_SIZE);
    const size_t size_raw_to_write = ntohs(*(uint16_t *)buf);
    if (size_raw_to_write == 0) {
      return 0;
    }
    const size_t size_frame_to_read = size_raw_to_write + FRAME_LEN_SIZE;
    while (size_frame_read_pos < size_frame_to_read) {
      ssize_t size_frame_read = read(fd_frame, buf + size_frame_read_pos,
                                     sizeof(buf) - size_frame_read_pos);
      if (size_frame_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read frame");
        return -1;
      }
      size_frame_read_pos += size_frame_read;
    }
    ssize_t size_raw = write(fd_raw, buf + FRAME_LEN_SIZE, size_raw_to_write);
    if (size_raw == -1) {
      if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
          errno == EINPROGRESS) {
        continue;
      }
      perror("write raw");
      return -1;
    }
    if ((size_t)size_raw < size_raw_to_write) {
      // TODO: inform short write?
    }
    const size_t size_frame_transfered = size_raw_to_write + FRAME_LEN_SIZE;
    memmove(buf, buf + size_frame_transfered,
            size_frame_read_pos - size_frame_transfered);
    size_frame_read_pos -= size_frame_transfered;
  }
}

/**
 * **tuncat_comp_len_read** : read compressed length from buf
 *
 * @param buf     buffer
 * @param size    buffer size
 * @param rsizep  read size
 * @return compressed length
 */
static int tuncat_comp_len_read(const char *buf, size_t size, size_t *rsizep) {
  assert(rsizep != NULL);
  if (size <= 0)
    return 0;
  size_t rsize = buf[0] & 0x7f;
  if ((buf[0] & 0x80) == 0) {
    *rsizep = rsize;
    return 1;
  }
  if (size <= 1)
    return 0;
  rsize |= (buf[1] & 0x7f) << 7;
  if ((buf[1] & 0x80) == 0) {
    *rsizep = rsize;
    return 2;
  }
  if (size <= 2)
    return 0;
  rsize |= (buf[2] & 0xff) << 14;
  *rsizep = rsize;
  return 3;
}

/**
 * **tuncat_comp_len_write** : write compressed length to buf
 *
 * @param buf    buffer
 * @param size   buffer size
 * @param rsize  compressed length
 * @return written size
 */
static size_t tuncat_comp_len_write(char *buf, size_t size, size_t rsize) {
  if (size < 1)
    return 0;
  if (rsize < 0x80) {
    buf[0] = rsize;
    return 1;
  }
  if (size < 2)
    return 0;
  if (rsize < 0x4000) {
    buf[0] = 0x80 | (rsize & 0x7f);
    buf[1] = rsize >> 7;
    return 2;
  }
  if (size < 3)
    return 0;
  if (rsize < 0x200000) {
    buf[0] = 0x80 | (rsize & 0x7f);
    buf[1] = 0x80 | ((rsize >> 7) & 0x7f);
    buf[2] = rsize >> 14;
    return 3;
  }
  return -1;
}

/**
 * **tuncat_comp_len_size** : calculate compressed length size
 *
 * @param size  compressed length
 * @return compressed length size
 */
static size_t tuncat_comp_len_size(size_t size) {
  if (size < 0x80)
    return 1;
  if (size < 0x4000)
    return 2;
  if (size < 0x200000)
    return 3;
  return -1;
}

/**
 * **tuncat_frame_to_comp** : read frame data from fd_frame and write compressed
 * data to fd_comp
 *
 * @param fd_frame  file descriptor for frame data
 * @param fd_comp   file descriptor for compressed data
 * @return 0 on success, -1 on failure
 */
static int tuncat_frame_to_comp(int fd_frame, int fd_comp) {
  assert(fd_frame >= 0);
  assert(fd_comp >= 0);
  const size_t COMP_LEN_MAX = snappy_max_compressed_length(FRAME_LEN_MAX);
  char ibuf[FRAME_LEN_MAX + FRAME_LEN_SIZE];
  char cbuf[COMP_LEN_MAX];
  char obuf[COMP_LEN_MAX + COMP_LEN_SIZE_MAX];
  size_t size_frame_read_pos = 0;
  while (1) {
    while (size_frame_read_pos < FRAME_LEN_SIZE) {
      ssize_t size_frame_read = read(fd_frame, ibuf + size_frame_read_pos,
                                     sizeof(ibuf) - size_frame_read_pos);
      if (size_frame_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read frame");
        return -1;
      }
      if (size_frame_read == 0) {
        return 0;
      }
      size_frame_read_pos += size_frame_read;
    }
    size_t size_frame = ntohs(*(uint16_t *)ibuf);
    while (size_frame_read_pos < size_frame + FRAME_LEN_SIZE) {
      ssize_t size_frame_read = read(fd_frame, ibuf + size_frame_read_pos,
                                     sizeof(ibuf) - size_frame_read_pos);
      if (size_frame_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read frame");
        return -1;
      }
      if (size_frame_read == 0) {
        return 0;
      }
      size_frame_read_pos += size_frame_read;
    }
    size_t size_comp = sizeof(cbuf);
    if (snappy_compress(ibuf + FRAME_LEN_SIZE, size_frame, cbuf, &size_comp) !=
        SNAPPY_OK) {
      fprintf(stderr, "snappy_compress failed\n");
      return -1;
    }
    size_t size_comp_len = tuncat_comp_len_size(size_comp);
    assert(size_comp_len != (size_t)-1);
    size_t size_comp_len_written =
        tuncat_comp_len_write(obuf, sizeof(obuf), size_comp);
    assert(size_comp_len_written == size_comp_len);
    size_t size_comp_write_pos = 0;
    const size_t size_comp_to_write = size_comp_len + size_comp;
    while (size_comp_write_pos < size_comp_to_write) {
      ssize_t size_comp_write = write(fd_comp, obuf + size_comp_write_pos,
                                      size_comp_to_write - size_comp_write_pos);
      if (size_comp_write == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write comp");
        return -1;
      }
      size_comp_write_pos += size_comp_write;
    }
    const size_t size_frame_transfered = size_frame + FRAME_LEN_SIZE;
    memcpy(ibuf, ibuf + size_frame_transfered,
           size_frame_read_pos - size_frame_transfered);
    size_frame_read_pos -= size_frame_transfered;
  }
}

/**
 * **tuncat_comp_to_frame** : read compressed data from fd_comp and write frame
 * data to fd_frame
 *
 * @param fd_comp   file descriptor for compressed data
 * @param fd_frame  file descriptor for frame data
 * @return 0 on success, -1 on failure
 */
static int tuncat_comp_to_frame(int fd_comp, int fd_frame) {
  assert(fd_comp >= 0);
  assert(fd_frame >= 0);
  const size_t COMP_LEN_MAX = snappy_max_compressed_length(FRAME_LEN_MAX);
  char ibuf[COMP_LEN_MAX + COMP_LEN_SIZE_MAX];
  char obuf[FRAME_LEN_MAX + FRAME_LEN_SIZE];
  size_t size_comp_read_pos = 0;
  while (1) {
    size_t size_comp_len = 0;
    size_t size_comp = 0;
    while (1) {
      ssize_t size_comp_read = read(fd_comp, ibuf + size_comp_read_pos,
                                    sizeof(ibuf) - size_comp_read_pos);
      if (size_comp_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read comp");
        return -1;
      }
      if (size_comp_read == 0) {
        return 0;
      }
      size_comp_read_pos += size_comp_read;
      size_comp_len =
          tuncat_comp_len_read(ibuf, size_comp_read_pos, &size_comp);
      if (size_comp_len == 0) {
        continue;
      }
      if (size_comp_len == (size_t)-1) {
        fprintf(stderr, "tuncat_comp_len_read failed\n");
        return -1;
      }
      break;
    }
    while (size_comp_read_pos < size_comp_len + size_comp) {
      ssize_t size_comp_read = read(fd_comp, ibuf + size_comp_read_pos,
                                    sizeof(ibuf) - size_comp_read_pos);
      if (size_comp_read == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read comp");
        return -1;
      }
      if (size_comp_read == 0) {
        return 0;
      }
      size_comp_read_pos += size_comp_read;
    }
    size_t size_frame = sizeof(obuf);
    if (snappy_uncompressed_length(ibuf + size_comp_len, size_comp,
                                   &size_frame) != SNAPPY_OK) {
      fprintf(stderr, "snappy_uncompressed_length failed\n");
      return -1; // TODO: reset stream
    }
    assert(size_frame <= sizeof(obuf) - FRAME_LEN_SIZE);
    if (snappy_uncompress(ibuf + size_comp_len, size_comp,
                          obuf + FRAME_LEN_SIZE, &size_frame) != SNAPPY_OK) {
      fprintf(stderr, "snappy_uncompress failed\n");
      return -1; // TODO: reset stream
    }
    (*(uint16_t *)obuf) = htons(size_frame);
    size_t size_frame_written = 0;
    while (size_frame_written < size_frame + FRAME_LEN_SIZE) {
      ssize_t size_frame_write =
          write(fd_frame, obuf + size_frame_written,
                size_frame + FRAME_LEN_SIZE - size_frame_written);
      if (size_frame_write == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write frame");
        return -1;
      }
      size_frame_written += size_frame_write;
    }
    const size_t size_comp_transfered = size_comp_len + size_comp;
    memmove(ibuf, ibuf + size_comp_transfered,
            size_comp_read_pos - size_comp_transfered);
    size_comp_read_pos -= size_comp_transfered;
  }
}

static void *tuncat_raw_to_frame_thread(void *arg) {
  int *fds = arg;
  int ifrfd = fds[0];
  int trsfd = fds[1];
  return (void *)(intptr_t)tuncat_raw_to_frame(ifrfd, trsfd);
}

static void *tuncat_frame_to_raw_thread(void *arg) {
  int *fds = arg;
  int trrfd = fds[0];
  int ifwfd = fds[1];
  return (void *)(intptr_t)tuncat_frame_to_raw(trrfd, ifwfd);
}

static int forward_packets(int tunfd, int tr_ifd, int tr_ofd) {
  pthread_t th_if_to_tr, th_tr_to_if;

  int fds_if_to_tr[2] = {tunfd, tr_ofd};
  int fds_tr_to_if[2] = {tr_ifd, tunfd};

  if (pthread_create(&th_if_to_tr, NULL, tuncat_raw_to_frame_thread,
                     fds_if_to_tr) != 0) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  if (pthread_create(&th_tr_to_if, NULL, tuncat_frame_to_raw_thread,
                     fds_tr_to_if) != 0) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  void *ret_if_to_tr, *ret_tr_to_if;
  if (pthread_join(th_if_to_tr, &ret_if_to_tr) != 0) {
    perror("pthread_join");
    return EXIT_FAILURE;
  }
  if (pthread_join(th_tr_to_if, &ret_tr_to_if) != 0) {
    perror("pthread_join");
    return EXIT_FAILURE;
  }

  return (intptr_t)ret_if_to_tr == 0 && (intptr_t)ret_tr_to_if == 0
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}

int main(int argc, char *const argv[]) {
  int sock;

  int opt;
  struct tuncat_optspec opts;
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
      {"compress", no_argument, NULL, 'c'},
      {"version", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  memset(&opts, 0, sizeof(opts));

  int optindex = 0;
  while ((opt = getopt_long(argc, argv, "m:n:b:i:a:t:l:p:46cvh", longopts,
                            &optindex)) != -1) {
    switch (opt) {
    case 'm':
      if (opts.ifmode != IFMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -m\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcasecmp(optarg, IFMODE_L2_OPT) == 0) {
        opts.ifmode = IFMODE_L2;
      } else if (strcasecmp(optarg, IFMODE_L3_OPT) == 0) {
        opts.ifmode = IFMODE_L3;
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
    case 'a':
      if (opts.addr != NULL) {
        fprintf(stderr, "Duplicated option -a\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.addr = optarg;
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
      if (opts.trmode != TRMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -t\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      if (strcasecmp(optarg, TRMODE_STDIO_OPT) == 0) {
        opts.trmode = TRMODE_STDIO;
      } else if (strcasecmp(optarg, TRMODE_SERVER_OPT) == 0) {
        opts.trmode = TRMODE_SERVER;
      } else if (strcasecmp(optarg, TRMODE_CLIENT_OPT) == 0) {
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
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV4;
      break;
    case '6':
      if (opts.ipmode != IPMODE_UNSPEC) {
        fprintf(stderr, "Duplicated option -4 or -6\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.ipmode = IPMODE_IPV6;
      break;
    case 'c':
      if (opts.compflag != COMPFLAG_UNSPEC) {
        fprintf(stderr, "Duplicated option -c\n");
        print_usage(stderr, argc, argv);
        return EXIT_FAILURE;
      }
      opts.compflag = COMPFLAG_COMPRESS;
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

  if (opts.ifmode == IFMODE_UNSPEC) {
    opts.ifmode = IFMODE_DEFAULT;
  }

  if (opts.brname != NULL && opts.ifmode == IFMODE_L3) {
    fprintf(stderr, "-b is not supported for L3 mode\n");
    print_usage(stderr, argc, argv);
    return EXIT_FAILURE;
  }

  switch (opts.trmode) {

  case TRMODE_UNSPEC:
    opts.trmode = TRMODE_DEFAULT;
    break;

  case TRMODE_STDIO:
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
    break;

  case TRMODE_SERVER:
    break;

  case TRMODE_CLIENT:
    if (opts.node == NULL) {
      fprintf(stderr, "-l is required for client mode\n");
      print_usage(stderr, argc, argv);
      return EXIT_FAILURE;
    }
    break;
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
    int tunfd = tuncat_if_init(&opts);
    if (tunfd == -1) {
      return EXIT_FAILURE;
    }
    return forward_packets(tunfd, STDIN_FILENO, STDOUT_FILENO);
  }

  {
    struct addrinfo aih, *airp, *rp;
    int s;

    memset(&aih, 0, sizeof(aih));
    switch (opts.ipmode) {
    case IPMODE_UNSPEC:
      aih.ai_family = AF_UNSPEC;
      break;
    case IPMODE_IPV4:
      aih.ai_family = AF_INET;
      break;
    case IPMODE_IPV6:
      aih.ai_family = AF_INET6;
      break;
    }
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
        int optval = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
                       sizeof(optval)) == -1) {
          perror("setsockopt");
          close(sock);
          return EXIT_FAILURE;
        }
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

  int tunfd = tuncat_if_init(&opts);
  if (tunfd == -1) {
    return EXIT_FAILURE;
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
        return forward_packets(tunfd, csock, csock);
      }

      close(csock);
    }
  } else {
    return forward_packets(tunfd, sock, sock);
  }
}
