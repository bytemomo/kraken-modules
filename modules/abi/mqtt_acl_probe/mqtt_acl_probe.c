#define KRAKEN_MODULE_BUILD
#include <kraken_module_abi_v2.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;
static const char *MODULE_ID = "mqtt-acl-probe";
static const char *LOG_PREFIX = "[mqtt-acl-probe] ";

typedef struct {
    char *user;
    char *pass;
} cred_t;

typedef struct {
    cred_t *list;
    size_t count;
} cred_list_t;

static void free_cred_list(cred_list_t *cl) {
    if (!cl) return;
    for (size_t i = 0; i < cl->count; i++) {
        free(cl->list[i].user);
        free(cl->list[i].pass);
    }
    free(cl->list);
    cl->list = NULL;
    cl->count = 0;
}

typedef struct {
    uint8_t buf[1024];
    size_t len;
} mqtt_packet_t;

static int mqtt_encode_string(uint8_t *buf, const char *s) {
    size_t len = strlen(s);
    if (len > 65535) return -1;
    buf[0] = (uint8_t)(len >> 8);
    buf[1] = (uint8_t)(len & 0xFF);
    memcpy(buf + 2, s, len);
    return (int)(len + 2);
}

static int mqtt_build_connect(mqtt_packet_t *pkt, const char *client_id, const char *user, const char *pass) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    const char *proto = "MQTT";
    int wrote = mqtt_encode_string(p, proto);
    if (wrote < 0) return -1;
    p += wrote;
    *p++ = 4;
    uint8_t flags = 0;
    if (user && *user) flags |= 0x80;
    if (pass && *pass) flags |= 0x40;
    *p++ = flags;
    *p++ = 0;
    *p++ = 60;
    wrote = mqtt_encode_string(p, client_id);
    if (wrote < 0) return -1;
    p += wrote;
    if (user && *user) {
        wrote = mqtt_encode_string(p, user);
        if (wrote < 0) return -1;
        p += wrote;
    }
    if (pass && *pass) {
        wrote = mqtt_encode_string(p, pass);
        if (wrote < 0) return -1;
        p += wrote;
    }

    size_t rem_len = p - pkt->buf;
    uint8_t head[5];
    size_t hl = 1;
    head[0] = 0x10;
    size_t x = rem_len;
    do {
        uint8_t b = x % 128;
        x /= 128;
        if (x > 0) b |= 128;
        head[hl++] = b;
    } while (x > 0);

    if (rem_len + hl > sizeof(pkt->buf)) return -1;
    memmove(pkt->buf + hl, pkt->buf, rem_len);
    memcpy(pkt->buf, head, hl);
    pkt->len = rem_len + hl;
    return (int)pkt->len;
}

static int mqtt_build_subscribe(mqtt_packet_t *pkt, const char *topic) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    size_t topic_len = strlen(topic);
    size_t rem_len = 2 + 2 + topic_len + 1;
    *p++ = 0x82;
    *p++ = (uint8_t)rem_len;
    *p++ = 0;
    *p++ = 1;
    int wrote = mqtt_encode_string(p, topic);
    if (wrote < 0) return -1;
    p += wrote;
    *p++ = 0;
    pkt->len = p - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_build_publish_qos1(mqtt_packet_t *pkt, const char *topic, const char *msg) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    *p++ = 0x32;
    size_t topic_len = strlen(topic);
    size_t msg_len = strlen(msg);
    size_t rem_len = 2 + topic_len + 2 + msg_len;
    size_t rem_temp = rem_len;
    do {
        uint8_t b = rem_temp % 128;
        rem_temp /= 128;
        if (rem_temp > 0) b |= 128;
        *p++ = b;
    } while (rem_temp > 0);
    int wrote = mqtt_encode_string(p, topic);
    if (wrote < 0) return -1;
    p += wrote;
    *p++ = 0;
    *p++ = 2;
    memcpy(p, msg, msg_len);
    p += msg_len;
    pkt->len = p - pkt->buf;
    return (int)pkt->len;
}

static int send_all(const KrakenConnectionOps *ops, KrakenConnectionHandle conn, const uint8_t *buf, size_t len, uint32_t timeout_ms) {
    int64_t sent = ops->send(conn, buf, len, timeout_ms);
    return sent == (int64_t)len ? 0 : -1;
}

static int recv_into(const KrakenConnectionOps *ops, KrakenConnectionHandle conn, uint8_t *buf, size_t bufsize, uint32_t timeout_ms) {
    int64_t got = ops->recv(conn, buf, bufsize, timeout_ms);
    if (got <= 0) return -1;
    return (int)got;
}

static bool parse_connack_ok(const uint8_t *buf, size_t n, uint8_t *reason_out) {
    if (n < 4 || buf[0] != 0x20) return false;
    if (reason_out) *reason_out = buf[3];
    return buf[3] == 0x00;
}

static bool parse_suback_ok(const uint8_t *buf, size_t n, uint8_t *reason_out) {
    if (n < 5 || buf[0] != 0x90) return false;
    if (reason_out) *reason_out = buf[n - 1];
    return buf[n - 1] <= 0x02;
}

static bool parse_puback_ok(const uint8_t *buf, size_t n, uint8_t *reason_out) {
    if (n < 4 || buf[0] != 0x40) return false;
    if (reason_out) *reason_out = buf[n - 1];
    return true;
}

static void add_acl_finding(KrakenRunResultV2 *res, const KrakenTarget *target, const char *id, const char *title, const char *severity, const char *desc, const cred_t *cred,
                            bool success) {
    KrakenFindingV2 f = {0};
    f.id = mystrdup(id);
    f.module_id = mystrdup(MODULE_ID);
    f.success = success;
    f.title = mystrdup(title);
    f.severity = mystrdup(severity);
    f.description = mystrdup(desc);
    f.timestamp = time(NULL);
    copy_target(&f.target, target);

    f.tags.count = 2;
    f.tags.strings = (const char **)malloc(2 * sizeof(char *));
    f.tags.strings[0] = mystrdup("mqtt");
    f.tags.strings[1] = mystrdup("acl");

    if (cred) {
        f.evidence.count = 2;
        f.evidence.items = (KrakenKeyValue *)calloc(f.evidence.count, sizeof(KrakenKeyValue));
        f.evidence.items[0].key = mystrdup("username");
        f.evidence.items[0].value = mystrdup(cred->user ? cred->user : "");
        f.evidence.items[1].key = mystrdup("password");
        f.evidence.items[1].value = mystrdup(cred->pass ? cred->pass : "");
    }

    add_finding_v2(res, &f);
}

static void log_prefixed(KrakenRunResultV2 *res, const char *msg) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", LOG_PREFIX, msg);
    add_log_v2(res, buf);
}

static cred_list_t load_creds(const char *path) {
    cred_list_t cl = {0};
    if (!path || !*path) return cl;
    FILE *f = fopen(path, "r");
    if (!f) return cl;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
       
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;
        char *sep = strchr(line, ':');
        char *user = NULL;
        char *pass = NULL;
        if (sep) {
            *sep = '\0';
            user = mystrdup(line);
            pass = mystrdup(sep + 1);
        } else {
            user = mystrdup(line);
            pass = mystrdup("");
        }
        cl.list = (cred_t *)realloc(cl.list, (cl.count + 1) * sizeof(cred_t));
        cl.list[cl.count].user = user;
        cl.list[cl.count].pass = pass;
        cl.count++;
    }
    fclose(f);
    return cl;
}

static uint32_t extract_timeout(const char *params_json, uint32_t def) {
    if (!params_json) return def;
    const char *t = strstr(params_json, "timeout_ms");
    if (!t) return def;
    const char *colon = strchr(t, ':');
    if (!colon) return def;
    uint32_t v = (uint32_t)strtoul(colon + 1, NULL, 10);
    return v ? v : def;
}

static char *extract_string_param(const char *params_json, const char *key) {
    if (!params_json || !key) return NULL;
    const char *p = strstr(params_json, key);
    if (!p) return NULL;
    const char *colon = strchr(p, ':');
    if (!colon) return NULL;
    const char *q = strchr(colon, '\"');
    if (!q) return NULL;
    q++;
    const char *end = strchr(q, '\"');
    if (!end) return NULL;
    size_t len = (size_t)(end - q);
    char *out = (char *)malloc(len + 1);
    if (out) {
        memcpy(out, q, len);
        out[len] = '\0';
    }
    return out;
}

static int probe_credential(KrakenRunResultV2 *res, const KrakenTarget *target, const KrakenConnectionOps *ops, KrakenConnectionHandle base_conn, const cred_t *cred,
                            const char *topic, uint32_t timeout_ms, bool reuse_conn, bool *connect_ok_out, bool *sub_ok_out, bool *pub_ok_out) {
    if (connect_ok_out) *connect_ok_out = false;
    if (sub_ok_out) *sub_ok_out = false;
    if (pub_ok_out) *pub_ok_out = false;

    KrakenConnectionHandle h = base_conn;
    bool opened = false;
    if (!reuse_conn && ops->open) {
        h = ops->open(base_conn, timeout_ms);
        opened = (h != NULL);
        if (!opened) { log_prefixed(res, "failed to open connection"); return -1; }
    }

    char cid[48];
    snprintf(cid, sizeof(cid), "acl-%u", (unsigned)rand());

    mqtt_packet_t pkt;
    if (mqtt_build_connect(&pkt, cid, cred ? cred->user : NULL, cred ? cred->pass : NULL) < 0) {
        log_prefixed(res, "failed to build CONNECT");
        if (opened && ops->close) ops->close(h);
        return -1;
    }
    if (send_all(ops, h, pkt.buf, pkt.len, timeout_ms) != 0) {
        log_prefixed(res, "CONNECT send failed");
        if (opened && ops->close) ops->close(h);
        return -1;
    }
    uint8_t resp[128];
    int n = recv_into(ops, h, resp, sizeof(resp), timeout_ms);
    uint8_t reason = 0xff;
    bool conn_ok = n > 0 && parse_connack_ok(resp, (size_t)n, &reason);
    if (conn_ok) {
        if (connect_ok_out) *connect_ok_out = true;
        log_prefixed(res, "CONNECT accepted");
    } else {
        log_prefixed(res, "CONNECT rejected");
        if (opened && ops->close) ops->close(h);
        return 0;
    }

   
    if (mqtt_build_subscribe(&pkt, topic) < 0 || send_all(ops, h, pkt.buf, pkt.len, timeout_ms) != 0) {
        log_prefixed(res, "SUBSCRIBE send failed");
        add_acl_finding(res, target, "MQTT-ACL-SUB", "MQTT SUBSCRIBE to probe topic", "info", "Probe topic subscription send failed.", cred, false);
        if (opened && ops->close) ops->close(h);
        return 0;
    }
    n = recv_into(ops, h, resp, sizeof(resp), timeout_ms);
    uint8_t sub_reason = 0xff;
    bool sub_ok = n > 0 && parse_suback_ok(resp, (size_t)n, &sub_reason);
    if (sub_ok_out) *sub_ok_out = sub_ok;
    if (sub_ok) {
        add_acl_finding(res, target, "MQTT-ACL-SUB", "MQTT SUBSCRIBE to probe topic", "high", "Probe topic subscription accepted.", cred, true);
    } else {
        log_prefixed(res, "SUBSCRIBE rejected");
    }

   
    const char *payload = "kraken-acl-probe";
    if (mqtt_build_publish_qos1(&pkt, topic, payload) >= 0 && send_all(ops, h, pkt.buf, pkt.len, timeout_ms) == 0) {
        n = recv_into(ops, h, resp, sizeof(resp), timeout_ms);
        if (n <= 0) {
           
            n = recv_into(ops, h, resp, sizeof(resp), timeout_ms);
        }
        uint8_t pub_reason = 0xff;
        bool pub_ok = n > 0 && parse_puback_ok(resp, (size_t)n, &pub_reason);
        if (pub_ok_out) *pub_ok_out = pub_ok;
        if (pub_ok) {
            add_acl_finding(res, target, "MQTT-ACL-PUB", "MQTT PUBLISH to probe topic", "high", "Probe topic publish acknowledged.", cred, true);
        } else {
            log_prefixed(res, "PUBLISH not acknowledged");
        }
    } else {
        log_prefixed(res, "PUBLISH send failed");
    }

    if (opened && ops->close) ops->close(h);
    return 0;
}

KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn, const KrakenConnectionOps *ops, const KrakenTarget *target, uint32_t timeout_ms,
                             const char *params_json, KrakenRunResultV2 **out_result) {
    srand((unsigned)time(NULL));

    KrakenRunResultV2 *result = (KrakenRunResultV2 *)calloc(1, sizeof(KrakenRunResultV2));
    if (!result) return -1;

    copy_target(&result->target, target);

    char *creds_path = extract_string_param(params_json, "creds_file");
    char *topic = extract_string_param(params_json, "topic");
    if (!topic) topic = mystrdup("kraken/acl/probe");
    uint32_t op_timeout = extract_timeout(params_json, timeout_ms ? timeout_ms : 5000);

    cred_list_t creds = load_creds(creds_path);
    bool anon_conn = false, anon_sub = false, anon_pub = false;
    cred_t anon = {.user = NULL, .pass = NULL};
    log_prefixed(result, "Testing anonymous access");
    probe_credential(result, target, ops, conn, &anon, topic, op_timeout, true, &anon_conn, &anon_sub, &anon_pub);

    if (!(anon_conn && (anon_sub || anon_pub)) && creds.count > 0) {
        for (size_t i = 0; i < creds.count; i++) {
            char logbuf[256];
            snprintf(logbuf, sizeof(logbuf), "%sTesting credential %s/%s", LOG_PREFIX,
                     creds.list[i].user ? creds.list[i].user : "",
                     creds.list[i].pass ? creds.list[i].pass : "");
            add_log_v2(result, logbuf);
            probe_credential(result, target, ops, conn, &creds.list[i], topic, op_timeout, true, NULL, NULL, NULL);
        }
    } else if (anon_conn && (anon_sub || anon_pub)) {
        log_prefixed(result, "Anonymous access allowed; skipping credential list to reduce noise");
    }

    free(creds_path);
    free(topic);
    free_cred_list(&creds);

    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free_v2(void *p) {
    if (!p) return;
    KrakenRunResultV2 *res = (KrakenRunResultV2 *)p;

    free_target(&res->target);

    for (size_t i = 0; i < res->findings_count; i++) {
        KrakenFindingV2 *f = &res->findings[i];
        free((void *)f->id);
        free((void *)f->module_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free_target(&f->target);
        for (size_t j = 0; j < f->evidence.count; j++) {
            free((void *)f->evidence.items[j].key);
            free((void *)f->evidence.items[j].value);
        }
        free(f->evidence.items);
        for (size_t j = 0; j < f->tags.count; j++) {
            free((void *)f->tags.strings[j]);
        }
        free(f->tags.strings);
    }
    free(res->findings);

    for (size_t i = 0; i < res->logs.count; i++) {
        free((void *)res->logs.strings[i]);
    }
    free(res->logs.strings);

    free(res);
}
