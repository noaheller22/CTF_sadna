#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

// Touch OpenSSL so the binary links against libcrypto (no output).
#include <openssl/bn.h>
static void link_libcrypto(void) { BIGNUM *b = BN_new(); if (b) BN_free(b); }

// Create a listening TCP socket on 0.0.0.0:port
static int make_listener(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); exit(1); }
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("bind"); exit(1); }
    if (listen(s, 64) < 0) { perror("listen"); exit(1); }
    return s;
}

// Connect to the backend at ip:port
static int connect_backend(const char* ip, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { perror("inet_pton"); close(s); return -1; }
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("connect"); close(s); return -1; }
    return s;
}

// Relay bytes both directions until one side closes or errors
static void relay(int cfd, int bfd) {
    char buf[8192];
    for (;;) {
        fd_set r; FD_ZERO(&r); FD_SET(cfd, &r); FD_SET(bfd, &r);
        int maxfd = (cfd > bfd ? cfd : bfd) + 1;
        if (select(maxfd, &r, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(cfd, &r)) {
            ssize_t n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            for (ssize_t off = 0; off < n; ) {
                ssize_t m = send(bfd, buf + off, n - off, 0);
                if (m <= 0) { off = n; break; } else off += m;
            }
        }
        if (FD_ISSET(bfd, &r)) {
            ssize_t n = recv(bfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            for (ssize_t off = 0; off < n; ) {
                ssize_t m = send(cfd, buf + off, n - off, 0);
                if (m <= 0) { off = n; break; } else off += m;
            }
        }
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN); // avoid crash if peer closes
    link_libcrypto();         // ensure linkage to libcrypto (no prints)

    int listen_port = 4501;
    const char* backend_ip = "127.0.0.1";
    int backend_port = 4441;

    // Optional CLI: ./mini_proxy [listen_port] [backend_ip] [backend_port]
    if (argc >= 2) listen_port = atoi(argv[1]);
    if (argc >= 3) backend_ip   = argv[2];
    if (argc >= 4) backend_port = atoi(argv[3]);

    int ls = make_listener(listen_port);

    for (;;) {
        int cfd = accept(ls, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        int bfd = connect_backend(backend_ip, backend_port);
        if (bfd < 0) { close(cfd); continue; }

        pid_t pid = fork();
        if (pid == 0) {
            // Child: handle one connection end-to-end.
            close(ls);
            relay(cfd, bfd);
            shutdown(bfd, SHUT_RDWR); close(bfd);
            shutdown(cfd, SHUT_RDWR); close(cfd);
            _exit(0);
        }
        // Parent: cleanup and go back to accept next client.
        close(bfd);
        close(cfd);
    }
}