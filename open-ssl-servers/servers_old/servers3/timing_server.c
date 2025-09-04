#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/opensslv.h>
#include <openssl/bn.h>

static void touch_libcrypto(void) {
    BIGNUM* b = BN_new(); if (b) BN_free(b);
    fprintf(stderr, "[relay] linked with OpenSSL: %s\n", OPENSSL_VERSION_TEXT);
}

static int connect_to(const char* host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    int flag = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { perror("inet_pton"); close(s); return -1; }
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("connect"); close(s); return -1; }
    return s;
}

static int listen_on(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); exit(1); }
    int on = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    int flag = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("bind"); exit(1); }
    if (listen(s, 128) < 0) { perror("listen"); exit(1); }
    return s;
}

static void relay_pair(int cfd, int bfd) {
    for (;;) {
        fd_set rfds; FD_ZERO(&rfds);
        FD_SET(cfd, &rfds); FD_SET(bfd, &rfds);
        int mx = (cfd > bfd ? cfd : bfd) + 1;
        int r = select(mx, &rfds, NULL, NULL, NULL);
        if (r <= 0) break;

        char buf[8192];
        if (FD_ISSET(cfd, &rfds)) {
            ssize_t n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            for (ssize_t off = 0; off < n; ) {
                ssize_t m = send(bfd, buf + off, n - off, 0);
                if (m <= 0) { off = n; break; } else off += m;
            }
        }
        if (FD_ISSET(bfd, &rfds)) {
            ssize_t n = recv(bfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            for (ssize_t off = 0; off < n; ) {
                ssize_t m = send(cfd, buf + off, n - off, 0);
                if (m <= 0) { off = n; break; } else off += m;
            }
        }
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    touch_libcrypto();

    const char* backend_host = getenv("BACKEND_HOST"); if (!backend_host) backend_host = "127.0.0.1";
    int backend_port = getenv("BACKEND_PORT") ? atoi(getenv("BACKEND_PORT")) : 4442;
    int listen_port  = getenv("LISTEN_PORT")  ? atoi(getenv("LISTEN_PORT"))  : 4502;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"--backend-host") && i+1<argc) backend_host = argv[++i];
        else if (!strcmp(argv[i],"--backend-port") && i+1<argc) backend_port = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--listen-port")  && i+1<argc) listen_port  = atoi(argv[++i]);
    }

    int s = listen_on(listen_port);
    fprintf(stderr, "[relay] listening 0.0.0.0:%d -> %s:%d\n", listen_port, backend_host, backend_port);

    for (;;) {
        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) { if (errno==EINTR) continue; perror("accept"); break; }
        int flag = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        int bfd = connect_to(backend_host, backend_port);
        if (bfd < 0) { close(cfd); continue; }

        pid_t pid = fork();
        if (pid == 0) {
            close(s);
            relay_pair(cfd, bfd);
            shutdown(bfd, SHUT_RDWR); close(bfd);
            shutdown(cfd, SHUT_RDWR); close(cfd);
            _exit(0);
        }
        close(bfd);
        close(cfd);
    }
    return 0;
}