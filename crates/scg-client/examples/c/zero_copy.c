// Zero-copy SHM send example for the SCG client C ABI.
//
// Instead of scg_client_send() (which copies the caller's buffer into the ring),
// this builds the message DIRECTLY in the shared-memory ring slot:
//
//   scg_client_reserve() -> writable pointer into shared memory
//   ...write the payload straight into that pointer...
//   scg_client_commit()  -> publish + wake the gateway
//
// Requires the SHM *slot* ring (the byte-stream ring has no fixed slot to lend
// out; reserve() returns SCG_ERR there and the caller should use scg_client_send).
//
// Build (from crates/scg-client/examples):  make zc_client
// Run:  LD_LIBRARY_PATH=../../../target/debug ./zc_client app-telemetry normal

#include "scg_client.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <app_id> <normal|safety> [mgmt_socket] [message]\n", argv[0]);
        return 2;
    }
    const char *app_id = argv[1];
    int traffic_class = (strcmp(argv[2], "safety") == 0) ? SCG_CLASS_SAFETY : SCG_CLASS_NORMAL;
    const char *mgmt = (argc > 3 && argv[3][0] != '\0') ? argv[3] : NULL;
    const char *message = (argc > 4) ? argv[4] : "hello (zero-copy) from C";

    char err[256] = {0};
    ScgClientHandle *client = scg_client_connect(
        mgmt, app_id, SCG_TRANSPORT_SHM, traffic_class, SCG_DIRECTION_ENCRYPT, err, sizeof(err));
    if (client == NULL) {
        fprintf(stderr, "connect failed: %s\n", err);
        return 1;
    }
    printf("connected\n");

    size_t msg_len = strlen(message);

    // Reserve a slot; retry briefly while the ring is full (SCG_FULL).
    uint8_t *slot = NULL;
    size_t cap = 0;
    int rc;
    for (int attempt = 0; attempt < 1000; attempt++) {
        rc = scg_client_reserve(client, &slot, &cap);
        if (rc == SCG_OK) {
            break;
        }
        if (rc == SCG_FULL) {
            struct timespec ts = {0, 50 * 1000}; // 50 us backoff
            nanosleep(&ts, NULL);
            continue;
        }
        fprintf(stderr, "reserve failed: %s\n", scg_client_last_error(client));
        scg_client_close(client);
        return 1;
    }
    if (rc != SCG_OK) {
        fprintf(stderr, "reserve: ring stayed full\n");
        scg_client_close(client);
        return 1;
    }
    if (msg_len > cap) {
        fprintf(stderr, "message (%zu B) exceeds slot capacity (%zu B)\n", msg_len, cap);
        scg_client_close(client);
        return 1;
    }

    // Build the message straight into shared memory (no staging buffer), then publish.
    memcpy(slot, message, msg_len);
    if (scg_client_commit(client, 1, msg_len) != SCG_OK) {
        fprintf(stderr, "commit failed: %s\n", scg_client_last_error(client));
        scg_client_close(client);
        return 1;
    }
    printf("committed %zu bytes in place (slot capacity %zu)\n", msg_len, cap);

    uint32_t traffic_id = 0;
    uint8_t *buf = NULL;
    size_t len = 0;
    rc = scg_client_recv(client, &traffic_id, &buf, &len, 5000);
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
