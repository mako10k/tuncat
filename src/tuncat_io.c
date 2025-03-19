#include "tuncat_io.h"
#include "tuncat_opt.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <snappy-c.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static size_t read_packet_size(const char *buf) {
  return ntohs(*(uint16_t *)buf);
}

static void write_packet_size(char *buf, size_t size) {
  assert(size <= 65535);
  *(uint16_t *)buf = htons(size & 65535);
}

int forward_packets(struct tuncat_commandline_options *optsp, int tunfd,
                    int tr_ifd, int tr_ofd) {
  enum compflag compflag = optsp->compflag;

  size_t max_frame_size =
      optsp->max_frame_size ? optsp->max_frame_size : IF_MAX_FRAME_SIZE_DEF;

  const size_t if_read_buf_size =
      optsp->ifbuffer_size ? optsp->ifbuffer_size : 2 * max_frame_size;
  const size_t if_write_buf_size =
      optsp->ifbuffer_size ? optsp->ifbuffer_size : 2 * max_frame_size;
  const size_t tr_recv_buf_size =
      optsp->trbuffer_size ? optsp->trbuffer_size : if_write_buf_size;
  const size_t tr_send_buf_size =
      optsp->trbuffer_size ? optsp->trbuffer_size : if_read_buf_size;

  char if_read_buf[if_read_buf_size];
  char if_write_buf[if_write_buf_size];
  char tr_recv_buf[tr_recv_buf_size];
  char tr_send_buf[tr_send_buf_size];

  const int if_read_fd = tunfd;
  const int if_write_fd = tunfd;

  size_t if_read_buf_pos = 0;
  size_t if_write_buf_pos = 0;
  size_t tr_recv_buf_pos = 0;
  size_t tr_send_buf_pos = 0;

  if (fcntl(tunfd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return -1;
  }
  if (fcntl(tr_ifd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return -1;
  }
  if (tr_ifd != tr_ofd && fcntl(tr_ofd, F_SETFL, O_NONBLOCK) == -1) {
    perror("fcntl");
    return -1;
  }

  // Transfer Information
  write_packet_size(&tr_send_buf[tr_send_buf_pos], 0);
  tr_send_buf_pos += IF_FRAME_SIZE_LEN;
  tr_send_buf[tr_send_buf_pos++] = (char)optsp->ifmode;
  tr_send_buf[tr_send_buf_pos++] = (char)optsp->compflag;
  write_packet_size(&tr_send_buf[tr_send_buf_pos], optsp->max_frame_size);
  tr_send_buf_pos += IF_FRAME_SIZE_LEN;

  for (;;) {
    int nfds;
    fd_set rfds, wfds;
    nfds = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    // ---------------------------------------------------
    // Interface Read Buffer -> Transfer Send Buffer
    // ---------------------------------------------------
    while (1) {

      // brake if the packet size cannot read from interface read buffer
      if (if_read_buf_pos < IF_FRAME_SIZE_LEN)
        break;

      // read packet size from interface read buffer
      const size_t if_read_packet_size = read_packet_size(if_read_buf);

      // brake if the packet content cannot read from interface read buffer
      if (if_read_buf_pos < IF_FRAME_SIZE_LEN + if_read_packet_size)
        break;

      // calculate writing capacity of transfer send buffer
      const size_t tr_send_buf_writable_size =
          tr_send_buf_size - tr_send_buf_pos;

      // calculate required size of transfer send buffer
      size_t tr_send_buf_required_size =
          IF_FRAME_SIZE_LEN + if_read_packet_size;
      if (compflag == COMPFLAG_COMPRESS) {
        // calculate MAX required size of transfer send buffer with compression
        tr_send_buf_required_size =
            IF_FRAME_SIZE_LEN +
            snappy_max_compressed_length(if_read_packet_size);
      }

      // brake if the transfer send buffer cannot store the packet
      if (tr_send_buf_writable_size < tr_send_buf_required_size)
        break;

      if (compflag == COMPFLAG_COMPRESS) {
        // read from interface read buffer, compress and write packet

        size_t compressed_size =
            tr_send_buf_size - (IF_FRAME_SIZE_LEN + tr_send_buf_pos);

        // compressing the packet
        if (snappy_compress(&if_read_buf[IF_FRAME_SIZE_LEN],
                            if_read_packet_size,
                            &tr_send_buf[IF_FRAME_SIZE_LEN + tr_send_buf_pos],
                            &compressed_size) != SNAPPY_OK) {
          fprintf(stderr, "Fatal: snappy_compress failed\n");
          return -1;
        }

        // write compressed packet size
        write_packet_size(&tr_send_buf[tr_send_buf_pos], compressed_size);

        // move the position of transfer send buffer
        tr_send_buf_pos += IF_FRAME_SIZE_LEN + compressed_size;

      } else if (tr_send_buf_writable_size >= tr_send_buf_required_size) {

        // copy packet from interface read buffer to transfer send buffer
        memcpy(&tr_send_buf[tr_send_buf_pos], if_read_buf,
               IF_FRAME_SIZE_LEN + if_read_packet_size);

        // move the position of transfer send buffer
        tr_send_buf_pos += IF_FRAME_SIZE_LEN + if_read_packet_size;
      }

      // move the following data of interface read buffer
      memmove(if_read_buf,
              &if_read_buf[IF_FRAME_SIZE_LEN + if_read_packet_size],
              if_read_buf_pos - (IF_FRAME_SIZE_LEN + if_read_packet_size));
      // ^ TODO: should be minimize buffer move

      // move the position of interface read buffer
      if_read_buf_pos -= IF_FRAME_SIZE_LEN + if_read_packet_size;
    }

    // ---------------------------------------------------
    // Transfer Recv Buffer -> Interface Write Buffer
    // ---------------------------------------------------
    while (1) {

      // brake if the packet size cannot read from transfer receive buffer
      if (tr_recv_buf_pos < IF_FRAME_SIZE_LEN)
        break;

      // read packet size from transfer receive buffer
      const size_t tr_recv_packet_size = read_packet_size(tr_recv_buf);

      // operate information packet
      if (tr_recv_packet_size == 0) {
        // 4 byte of transfer information
        if (tr_recv_buf_pos < IF_FRAME_SIZE_LEN + 4)
          break;
        const enum ifmode received_ifmode = tr_recv_buf[IF_FRAME_SIZE_LEN];
        const enum compflag received_compflag =
            tr_recv_buf[IF_FRAME_SIZE_LEN + 1];
        const size_t received_max_frame_size =
            read_packet_size(&tr_recv_buf[IF_FRAME_SIZE_LEN + 2]);
        memmove(tr_recv_buf, &tr_recv_buf[IF_FRAME_SIZE_LEN + 4],
                tr_recv_buf_pos - (IF_FRAME_SIZE_LEN + 4));
        tr_recv_buf_pos -= IF_FRAME_SIZE_LEN + 4;

        // TODO: check received information
        (void)received_ifmode;
        (void)received_compflag;
        (void)received_max_frame_size;

        continue;
      }

      // brake if the packet content cannot read from transfer receive buffer
      if (tr_recv_buf_pos < IF_FRAME_SIZE_LEN + tr_recv_packet_size)
        break;

      // calculate writing capacity of interface write buffer
      const size_t if_write_buf_writable_size =
          if_write_buf_size - if_write_buf_pos;

      // calculate required size of interface write buffer
      size_t if_write_buf_required_size;

      if (compflag == COMPFLAG_COMPRESS) {
        // calculate required size of interface write buffer with compression
        size_t uncompressed_size;
        if (snappy_uncompressed_length(&tr_recv_buf[IF_FRAME_SIZE_LEN],
                                       tr_recv_packet_size,
                                       &uncompressed_size) != SNAPPY_OK) {
          fprintf(stderr, "Warn: Invalid transfer input stream\n");
          tr_recv_buf_pos -= IF_FRAME_SIZE_LEN + tr_recv_packet_size;
          continue;
        }
        if_write_buf_required_size = IF_FRAME_SIZE_LEN + uncompressed_size;

        // brake if the interface write buffer cannot store the packet
        if (if_write_buf_writable_size < if_write_buf_required_size)
          break;

        // decompress the packet
        if (snappy_uncompress(
                &tr_recv_buf[IF_FRAME_SIZE_LEN], tr_recv_packet_size,
                &if_write_buf[IF_FRAME_SIZE_LEN + if_write_buf_pos],
                &uncompressed_size) != SNAPPY_OK) {
          fprintf(stderr, "Warn: Invalid transfer input stream\n");

          // waste the packet
          tr_recv_buf_pos -= IF_FRAME_SIZE_LEN + tr_recv_packet_size;
          continue;
        }

        // write uncompressed packet size
        write_packet_size(&if_write_buf[if_write_buf_pos], uncompressed_size);

        // move the position of interface write buffer
        if_write_buf_pos += IF_FRAME_SIZE_LEN + uncompressed_size;
      } else {

        // write packet from transfer receive buffer to interface write buffer
        memcpy(&if_write_buf[if_write_buf_pos], tr_recv_buf,
               IF_FRAME_SIZE_LEN + tr_recv_packet_size);

        // move the position of interface write buffer
        if_write_buf_pos += IF_FRAME_SIZE_LEN + tr_recv_packet_size;
      }

      // move the following data of transfer receive buffer
      memmove(tr_recv_buf,
              &tr_recv_buf[IF_FRAME_SIZE_LEN + tr_recv_packet_size],
              tr_recv_buf_pos - (IF_FRAME_SIZE_LEN + tr_recv_packet_size));

      // move the position of transfer receive buffer
      tr_recv_buf_pos -= IF_FRAME_SIZE_LEN + tr_recv_packet_size;
    }

    // ---------------------------------------------------
    // Select and I/O
    // ---------------------------------------------------
    if (tr_recv_buf_pos < tr_send_buf_size) {
      FD_SET(tr_ifd, &rfds);
      if (nfds <= tr_ifd)
        nfds = tr_ifd + 1;
    }

    if (tr_send_buf_pos > 0) {
      FD_SET(tr_ofd, &wfds);
      if (nfds <= tr_ofd)
        nfds = tr_ofd + 1;
    }

    if (if_read_buf_pos + IF_FRAME_SIZE_LEN + max_frame_size <
        if_read_buf_size) {
      FD_SET(if_read_fd, &rfds);
      if (nfds <= if_read_fd)
        nfds = if_read_fd + 1;
    }

    if (if_write_buf_pos >= IF_FRAME_SIZE_LEN &&
        if_write_buf_pos >=
            IF_FRAME_SIZE_LEN + read_packet_size(if_write_buf)) {
      FD_SET(if_write_fd, &wfds);
      if (nfds <= if_write_fd)
        nfds = if_write_fd + 1;
    }

    if (nfds == 0) {
      fprintf(
          stderr, "(tr_ipos: %zu, tr_opos: %zu, if_ipos: %zu, if_opos: %zu)\n",
          tr_recv_buf_pos, tr_send_buf_pos, if_read_buf_pos, if_write_buf_pos);
      return 0;
    }

    nfds = select(nfds, &rfds, &wfds, NULL, NULL);
    if (nfds == -1) {
      perror("select");
      return -1;
    }

    // ---------------------------------------------------
    // Transfer Recv from Channel -> Transfer Recv Buffer
    // ---------------------------------------------------
    if (FD_ISSET(tr_ifd, &rfds)) {
      ssize_t rsiz = read(tr_ifd, tr_recv_buf + tr_recv_buf_pos,
                          tr_recv_buf_size - tr_recv_buf_pos);
      if (rsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read");
        return -1;
      }
      if (rsiz == 0) {
        return 0;
      }
      tr_recv_buf_pos += (size_t)rsiz;
      continue;
    }

    // ---------------------------------------------------
    // Interface Write Buffer -> Interface Write to Device
    // ---------------------------------------------------
    if (FD_ISSET(if_write_fd, &wfds)) {
      size_t packet_size = read_packet_size(if_write_buf);

      ssize_t wsiz =
          write(if_write_fd, &if_write_buf[IF_FRAME_SIZE_LEN], packet_size);
      if (wsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write");
        return -1;
      }
      if_write_buf_pos -= IF_FRAME_SIZE_LEN + (size_t)wsiz;
      memmove(if_write_buf, &if_write_buf[IF_FRAME_SIZE_LEN + wsiz],
              if_write_buf_pos);
      continue;
    }

    // ---------------------------------------------------
    // Interface Read from Device -> Interface Read Buffer
    // ---------------------------------------------------
    if (FD_ISSET(if_read_fd, &rfds)) {
      ssize_t rsiz = read(if_read_fd, if_read_buf + IF_FRAME_SIZE_LEN,
                          if_read_buf_size - IF_FRAME_SIZE_LEN);
      if (rsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("read");
        return -1;
      }
      if (rsiz == 0) {
        return 0;
      }
      write_packet_size(if_read_buf, (size_t)rsiz);
      if_read_buf_pos += IF_FRAME_SIZE_LEN + (size_t)rsiz;
      continue;
    }

    // ---------------------------------------------------
    // Transfer Send Buffer -> Transfer Send to Channel
    // ---------------------------------------------------
    if (FD_ISSET(tr_ofd, &wfds)) {
      ssize_t wsiz;

      wsiz = write(tr_ofd, tr_send_buf, tr_send_buf_pos);
      if (wsiz == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK ||
            errno == EINPROGRESS) {
          continue;
        }
        perror("write");
        return -1;
      }
      tr_send_buf_pos -= (size_t)wsiz;
      if (tr_send_buf_pos > 0) {
        memmove(tr_send_buf, tr_send_buf + wsiz, tr_send_buf_pos);
      }
      continue;
    }
  }
}

int open_socket(struct tuncat_commandline_options opts) {
  struct addrinfo aih, *airp, *rp;
  int s;
  int sock;

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
    return -1;
  }

  for (rp = airp; rp; rp = rp->ai_next) {
    int protocol = rp->ai_protocol;
    if (opts.mptcp && protocol == IPPROTO_TCP) {
      protocol = IPPROTO_MPTCP;
    }
    sock = socket(rp->ai_family, rp->ai_socktype, protocol);
    if (sock == -1)
      continue;
    if (opts.trmode == TRMODE_SERVER) {
      int optval = 1;
      if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) ==
          -1) {
        perror("setsockopt");
        close(sock);
        return -1;
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
    perror("socket");
    freeaddrinfo(airp);
    return -1;
  }

  freeaddrinfo(airp);
  return sock;
}
