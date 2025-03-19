#include "tuncat.h"
#include "tuncat_if.h"
#include "tuncat_io.h"
#include "tuncat_opt.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define inet_net_pton inet_net_pton_orig

void print_usage(FILE *fp) {
  extern char *program_invocation_name;
  fprintf(fp, "\nUsage:\n");
  fprintf(fp, "  %s [options]\n\n", program_invocation_name);

  fprintf(fp, "Options:\n");
  fprintf(fp, "  -n, --ifname=<name>          Interface name\n");
  fprintf(
      fp,
      "  -a, --ifaddress=<addr>       Interface address (only with -n)\n\n");

  fprintf(fp, "  -m, --tunnel-mode=%-6s     L3 payload mode%s\n", IFMODE_L3_OPT,
          strcmp(IFMODE_DEFAULT_OPT, IFMODE_L3_OPT) == 0 ? "  (default)" : "");
  fprintf(fp, "  -m, --tunnel-mode=%-6s     L2 payload mode%s\n\n",
          IFMODE_L2_OPT,
          strcmp(IFMODE_DEFAULT_OPT, IFMODE_L2_OPT) == 0 ? " (default)" : "");

  fprintf(fp, "  -b, --bridge-name=<name>     Bridge interface (L2 payload)\n");
  fprintf(fp, "  -i, --bridge-members=<ifname>[,<if_name>...]\n");
  fprintf(fp,
          "                              Bridge members (only with bridge)\n");
  fprintf(fp, "  -a, --ifaddress=<addr>       Bridge interface address (only "
              "with -b)\n\n");

  fprintf(fp, "  -t, --transfer-mode=%-6s   Stdio mode%s\n", TRMODE_STDIO_OPT,
          strcmp(TRMODE_DEFAULT_OPT, TRMODE_STDIO_OPT) == 0 ? "       (default)"
                                                            : "");
  fprintf(
      fp, "  -t, --transfer-mode=%-6s   TCP server mode%s\n", TRMODE_SERVER_OPT,
      strcmp(TRMODE_DEFAULT_OPT, TRMODE_SERVER_OPT) == 0 ? "  (default)" : "");
  fprintf(
      fp, "  -t, --transfer-mode=%-6s   TCP client mode%s\n", TRMODE_CLIENT_OPT,
      strcmp(TRMODE_DEFAULT_OPT, TRMODE_CLIENT_OPT) == 0 ? "  (default)" : "");
  fprintf(fp, "  -l, --address=<addr>         Listen Address (default: any) "
              "(TCP server)\n");
  fprintf(fp,
          "  -p, --port=<port>            Listen port (default: %5s) (TCP "
          "server)\n",
          PORT_DEFAULT);
  fprintf(fp, "  -l, --address=<addr>         Connect Address (required) (TCP "
              "client)\n");
  fprintf(fp,
          "  -p, --port=<port>            Connect Port (default: %5s) (TCP "
          "client)\n",
          PORT_DEFAULT);
  fprintf(
      fp,
      "  -4, --ipv4                   Force ipv4 (TCP server or TCP client)\n");
  fprintf(
      fp,
      "  -6, --ipv6                   Force ipv6 (TCP server or TCP client)\n");
  fprintf(fp, "  -M, --mptcp                  Enable MPTCP (TCP server or TCP "
              "client)\n\n");

  fprintf(fp, "  -c, --compress               Compress mode\n\n");

  fprintf(fp, "  -F, --max-frame-size=<size>  Max frame size (default: %zu)\n",
          (size_t)IF_MAX_FRAME_SIZE_DEF);
  fprintf(fp, "  -I, --ifbuffer-size=<size>   Interface buffer size (default: "
              "<Max frame size> * 2)\n");
  fprintf(fp, "  -T, --trbuffer-size=<size>   Transfer buffer size (default: "
              "<Interface Buffersize>)\n\n");

  fprintf(fp, "  -v, --version                Print version\n");
  fprintf(fp, "  -h, --help                   Print this usage\n\n");
}

int main(int argc, char *const argv[]) {
  struct tuncat_commandline_options opts = {0};
  if (tuncat_parse_opts(&opts, argc, argv) == -1) {
    return EXIT_FAILURE;
  }

  if (tuncat_check_opt(opts) == -1) {
    return EXIT_FAILURE;
  }

  if (opts.trmode == TRMODE_STDIO) {
    int tunfd = init_if(&opts);
    if (tunfd == -1) {
      return EXIT_FAILURE;
    }
    return forward_packets(&opts, tunfd, STDIN_FILENO, STDOUT_FILENO) == -1
               ? EXIT_FAILURE
               : EXIT_SUCCESS;
  }

  int tunfd = init_if(&opts);
  if (tunfd == -1) {
    return EXIT_FAILURE;
  }

  int sock = open_socket(opts);
  if (sock == -1) {
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
        return forward_packets(&opts, tunfd, csock, csock) == -1 ? EXIT_FAILURE
                                                                 : EXIT_SUCCESS;
      }

      close(csock);
    }
  } else {
    return forward_packets(&opts, tunfd, sock, sock) == -1 ? EXIT_FAILURE
                                                           : EXIT_SUCCESS;
  }
}
