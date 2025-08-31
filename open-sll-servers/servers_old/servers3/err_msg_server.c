// try AES-128-CBC decrypt with a fixed KEY/IV via OpenSSL,
// and send back EXACTLY OpenSSL's error text on failure, or "OK\n" on success.

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>

static const unsigned char KEY[16] = "0123456789abcdef";   // 16-byte AES key
static const unsigned char IV [16] = "abcdef0123456789";   // 16-byte AES IV

// Collect the entire OpenSSL error queue into a buffer
static int err_cb(const char *str, size_t len, void *u) {
    struct Buf { char *p; size_t cap, used; } *b = (struct Buf*)u;
    if (b->used + len >= b->cap) len = b->cap - b->used - 1;
    if ((long)len > 0) { memcpy(b->p + b->used, str, len); b->used += len; }
    b->p[b->used] = '\0';
    return 1;
}

static void handle_client(int cli_fd) {
    uint16_t n_be;
    if (read(cli_fd, &n_be, 2) != 2) return;        // need 2 bytes length
    uint16_t n = ntohs(n_be);                       // big-endian → host

    unsigned char ct[n];
    if (read(cli_fd, ct, n) != n) return;           // read exactly n bytes

    // Clear any previous OpenSSL errors so we only report fresh ones
    ERR_clear_error();

    // EVP decrypt (AES-128-CBC with fixed key/iv)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 1, l1 = 0, l2 = 0;
    unsigned char pt[n + 16];                       // room for padding

    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, KEY, IV);
    ok &= EVP_DecryptUpdate(ctx, pt, &l1, ct, n);
    ok &= EVP_DecryptFinal_ex(ctx, pt + l1, &l2);   // fails on bad padding
    EVP_CIPHER_CTX_free(ctx);

    if (ok) {
        // Success path: just say OK
        (void)write(cli_fd, "OK\n", 3);
        return;
    }

    // Failure: dump OpenSSL's own error queue back to the client verbatim
    char buf[1024] = {0};
    struct { char *p; size_t cap, used; } acc = { buf, sizeof(buf), 0 };
    ERR_print_errors_cb(err_cb, &acc);
    // Ensure a newline terminator at least once
    if (acc.used == 0 || buf[acc.used - 1] != '\n') {
        size_t left = sizeof(buf) - acc.used - 1;
        const char nl = '\n';
        if (left > 0) { buf[acc.used++] = nl; buf[acc.used] = '\0'; }
    }
    (void)write(cli_fd, buf, strlen(buf));
}

int main(int argc, char **argv) {
    // Optional: ./echo_openssl_server [listen_port]
    int port = 4444;
    if (argc >= 2) port = atoi(argv[1]);

    signal(SIGPIPE, SIG_IGN);               // don't die on peer close
    // (OpenSSL modern versions auto-init; ERR strings come via ERR_print_errors_cb)

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);  // 0.0.0.0
    a.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { if (errno==EINTR) continue; perror("accept"); continue; }
        handle_client(c);
        close(c);
    }
}
