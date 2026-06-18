/*
 * client.c — round-trip demo for the SCG C ABI.
 *
 * Build (after `cargo build -p scg-client`):
 *   the simplest way is the Makefile one directory up:
 *     cd .. && make c_client
 *   or compile directly from this directory:
 *     cc -I../../include client.c -L../../../../target/debug -lscg_client -o c_client
 *
 * Usage:
 *   ./c_client <app_id> <uds|shm> <normal|safety> [mgmt_socket] [message]
 *
 * Requires a running gateway with a matching rule. Exits non-zero on error.
 */
#include "scg_client.h"

#include <stdio.h>
#include <string.h>

static int transport_from(const char *s) {
    if (strcmp(s, "uds") == 0) return SCG_TRANSPORT_UDS;
    if (strcmp(s, "shm") == 0) return SCG_TRANSPORT_SHM;
    return -1;
}

static int class_from(const char *s) {
    if (strcmp(s, "normal") == 0) return SCG_CLASS_NORMAL;
    if (strcmp(s, "safety") == 0) return SCG_CLASS_SAFETY;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <app_id> <uds|shm> <normal|safety> [mgmt_socket] [message]\n",
                argv[0]);
        return 2;
    }

    const char *app_id = argv[1];
    int transport = transport_from(argv[2]);
    int traffic_class = class_from(argv[3]);
    const char *mgmt = (argc > 4 && argv[4][0] != '\0') ? argv[4] : NULL;
    const char *message = (argc > 5) ? argv[5] : "hello from C";

    if (transport < 0 || traffic_class < 0) {
        fprintf(stderr, "invalid transport/class\n");
        return 2;
    }

    char err[256] = {0};
    ScgClientHandle *client = scg_client_connect(
        mgmt, app_id, transport, traffic_class, SCG_DIRECTION_ENCRYPT, err, sizeof(err));
    if (client == NULL) {
        fprintf(stderr, "connect failed: %s\n", err);
        return 1;
    }
    printf("connected\n");

    if (scg_client_send(client, 1, (const uint8_t *)message, strlen(message)) != SCG_OK) {
        fprintf(stderr, "send failed: %s\n", scg_client_last_error(client));
        scg_client_close(client);
        return 1;
    }
    printf("sent %zu bytes\n", strlen(message));

    uint32_t traffic_id = 0;
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = scg_client_recv(client, &traffic_id, &buf, &len, 5000);
    if (rc == SCG_OK) {
        printf("recv: traffic_id=%u %zu bytes: %.*s\n", traffic_id, len, (int)len, buf);
        scg_client_free_buf(buf, len);
    } else if (rc == SCG_TIMEOUT) {
        fprintf(stderr, "recv timed out\n");
        scg_client_close(client);
        return 1;
    } else {
        fprintf(stderr, "recv failed: %s\n", scg_client_last_error(client));
        scg_client_close(client);
        return 1;
    }

    scg_client_close(client);
    printf("closed\n");
    return 0;
}
