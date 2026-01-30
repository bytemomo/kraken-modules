#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define KRAKEN_MODULE_BUILD
#include <kraken_module_abi.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION = KRAKEN_ABI_VERSION;
static const char *LOG_PREFIX = "[mqtt-sys-disclosure] ";


typedef struct {
    uint8_t buf[512];
    size_t len;
} mqtt_packet_t;

static int mqtt_encode_string(uint8_t *buf, const char *s) {
    size_t len = strlen(s);
    if (len > 65535)
        return -1;
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
    if (wrote < 0)
        return -1;
    p += wrote;
    *p++ = 4;
    uint8_t flags = 0;
    if (user && *user)
        flags |= 0x80;
    if (pass && *pass)
        flags |= 0x40;
    *p++ = flags;
    *p++ = 0;
    *p++ = 60;
    wrote = mqtt_encode_string(p, client_id);
    if (wrote < 0)
        return -1;
    p += wrote;
    if (user && *user) {
        wrote = mqtt_encode_string(p, user);
        if (wrote < 0)
            return -1;
        p += wrote;
    }
    if (pass && *pass) {
        wrote = mqtt_encode_string(p, pass);
        if (wrote < 0)
            return -1;
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
        if (x > 0)
            b |= 128;
        head[hl++] = b;
    } while (x > 0);

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
    if (wrote < 0)
        return -1;
    p += wrote;
    *p++ = 0;
    pkt->len = p - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_build_publish(mqtt_packet_t *pkt, const char *topic, const char *msg) {
    pkt->len = 0;
    uint8_t *p = pkt->buf;
    *p++ = 0x30;
    size_t topic_len = strlen(topic);
    size_t msg_len = strlen(msg);
    size_t rem_len = 2 + topic_len + msg_len;
    size_t rem_temp = rem_len;
    do {
        uint8_t b = rem_temp % 128;
        rem_temp /= 128;
        if (rem_temp > 0)
            b |= 128;
        *p++ = b;
    } while (rem_temp > 0);
    int wrote = mqtt_encode_string(p, topic);
    if (wrote < 0)
        return -1;
    p += wrote;
    memcpy(p, msg, msg_len);
    pkt->len = (p + msg_len) - pkt->buf;
    return (int)pkt->len;
}

static int mqtt_parse_connack(const uint8_t *buf, size_t n) {
    return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
}

static int mqtt_parse_suback(const uint8_t *buf, size_t n) {
    return n >= 3 && buf[0] == 0x90;
}


static uint32_t effective_timeout(uint32_t timeout_ms) {
    return timeout_ms ? timeout_ms : 5000;
}

static int send_all(int sock, const uint8_t *buf, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t sent = send(sock, buf + offset, len - offset, 0);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;
        offset += (size_t)sent;
    }
    return 0;
}

static int finish_connect(int sock, int flags, uint32_t timeout_ms) {
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLOUT,
    };
    int wait_ms = (int)effective_timeout(timeout_ms);
    int pr = poll(&pfd, 1, wait_ms);
    if (pr <= 0)
        return -1;

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
        return -1;

   
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    return 0;
}

static int connect_tcp(const char *host, uint16_t port, uint32_t timeout_ms) {
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    int sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0) {
            close(sock);
            sock = -1;
            continue;
        }
        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            sock = -1;
            continue;
        }

        int ret = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if (ret == 0) {
            fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
            break;
        }

        if (errno == EINPROGRESS) {
            if (finish_connect(sock, flags, timeout_ms) == 0)
                break;
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

static ssize_t mqtt_read_packet(int sock, uint8_t *buf, size_t buf_len) {
    ssize_t r = recv(sock, buf, 1, 0);
    if (r <= 0)
        return r;
    size_t offset = (size_t)r;

    size_t multiplier = 1;
    size_t remaining_length = 0;
    uint8_t byte = 0;
    do {
        if (offset >= buf_len)
            return -1;
        r = recv(sock, &byte, 1, 0);
        if (r <= 0)
            return r;
        buf[offset++] = byte;
        remaining_length += (byte & 127) * multiplier;
        multiplier *= 128;
        if (multiplier > (128 * 128 * 128 * 128))
            return -1;
    } while (byte & 128);

    if (remaining_length > buf_len - offset)
        return -1;

    size_t to_read = remaining_length;
    while (to_read > 0) {
        r = recv(sock, buf + offset, to_read, 0);
        if (r <= 0)
            return r;
        offset += (size_t)r;
        to_read -= (size_t)r;
    }
    return (ssize_t)offset;
}

static ssize_t mqtt_read_packet_with_timeout(int sock, uint8_t *buf, size_t buf_len, uint32_t timeout_ms) {
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLIN,
    };
    int wait_ms = (int)effective_timeout(timeout_ms);
    int pr = poll(&pfd, 1, wait_ms);
    if (pr == 0)
        return 0;
    if (pr < 0) {
        if (errno == EINTR)
            return 0;
        return -1;
    }
    return mqtt_read_packet(sock, buf, buf_len);
}


static int mqtt_client_connect(int *out_sock, const char *host, uint16_t port, const char *client_id, const char *user, const char *pass,
                               uint32_t timeout_ms) {
    int sock = connect_tcp(host, port, timeout_ms);
    if (sock < 0)
        return -1;

    mqtt_packet_t pkt;
    if (mqtt_build_connect(&pkt, client_id, user, pass) < 0) {
        close(sock);
        return -1;
    }

    if (send_all(sock, pkt.buf, pkt.len) != 0) {
        close(sock);
        return -1;
    }

    uint8_t resp[32];
    ssize_t got = mqtt_read_packet_with_timeout(sock, resp, sizeof(resp), timeout_ms);
    if (got <= 0 || !mqtt_parse_connack(resp, (size_t)got)) {
        close(sock);
        return -1;
    }

    *out_sock = sock;
    return 0;
}

static int mqtt_client_subscribe(int sock, const char *topic, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    int len = mqtt_build_subscribe(&pkt, topic);
    if (len < 0)
        return -1;
    if (send_all(sock, pkt.buf, (size_t)len) != 0)
        return -1;

    uint8_t resp[64];
    ssize_t got = mqtt_read_packet_with_timeout(sock, resp, sizeof(resp), timeout_ms);
    if (got <= 0 || !mqtt_parse_suback(resp, (size_t)got))
        return -1;
    return 0;
}

static int mqtt_client_publish(int sock, const char *topic, const char *msg, uint32_t timeout_ms) {
    mqtt_packet_t pkt;
    int len = mqtt_build_publish(&pkt, topic, msg);
    if (len < 0)
        return -1;
    return send_all(sock, pkt.buf, (size_t)len);
}

static uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

static bool mqtt_wait_for_sys_topic(int sock, const char *prefix, uint32_t wait_window_ms, char *topic_buf, size_t topic_buf_len, char *payload_buf, size_t payload_buf_len) {
    if (!prefix || !*prefix)
        prefix = "$SYS/";
    if (topic_buf_len == 0)
        return false;
    size_t prefix_len = strlen(prefix);
    uint64_t deadline = now_ms() + wait_window_ms;
    uint8_t packet[1024];

    while (1) {
        uint64_t now = now_ms();
        if (now >= deadline)
            break;
        uint32_t remaining = (uint32_t)(deadline - now);
        ssize_t got = mqtt_read_packet_with_timeout(sock, packet, sizeof(packet), remaining);
        if (got < 0)
            break;
        if (got == 0)
            continue;
        if ((packet[0] & 0xF0) != 0x30)
            continue;

        size_t offset = 1;
        size_t multiplier = 1;
        size_t remaining_length = 0;
        uint8_t byte;
        do {
            if (offset >= (size_t)got)
                break;
            byte = packet[offset++];
            remaining_length += (byte & 127) * multiplier;
            multiplier *= 128;
        } while (byte & 128);
        if (offset + 2 > (size_t)got)
            continue;

        size_t topic_len = ((size_t)packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        if (topic_len == 0 || offset + topic_len > (size_t)got)
            continue;

        size_t topic_copy_len = topic_len;
        if (topic_copy_len >= topic_buf_len)
            topic_copy_len = topic_buf_len - 1;
        memcpy(topic_buf, packet + offset, topic_copy_len);
        topic_buf[topic_copy_len] = '\0';

        offset += topic_len;

        if (strncmp(topic_buf, prefix, prefix_len) == 0) {
            if (payload_buf && payload_buf_len > 0) {
                size_t payload_len = 0;
                if ((size_t)got > offset)
                    payload_len = (size_t)got - offset;
                size_t max_bytes = (payload_buf_len - 1) / 2;
                if (payload_len > max_bytes)
                    payload_len = max_bytes;
                for (size_t i = 0; i < payload_len; i++) {
                    snprintf(payload_buf + (i * 2), payload_buf_len - (i * 2), "%02x", packet[offset + i]);
                }
                payload_buf[payload_len * 2] = '\0';
            }
            return true;
        }
    }
    return false;
}


KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result) {
    srand((unsigned)time(NULL));
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;
    char logbuf[256];
snprintf(logbuf, sizeof(logbuf), "%sMQTT $SYS disclosure assessment started", LOG_PREFIX);
add_log(result, logbuf);

    char *username = json_extract_string(params_json, "username");
    char *password = json_extract_string(params_json, "password");
    char *sys_prefix = json_extract_string(params_json, "sys_prefix");
    if (!sys_prefix)
        sys_prefix = mystrdup("$SYS/");

    int subscriber = -1;
    int publisher = -1;
    bool leak_detected = false;
    char leaked_topic[256] = {0};
    char leaked_payload[512] = {0};

    uint32_t op_timeout = effective_timeout(timeout_ms);

    char client_id[48];
    snprintf(client_id, sizeof(client_id), "krk-sub-%u", (unsigned)rand());
    if (mqtt_client_connect(&subscriber, host, (uint16_t)port, client_id, username, password, op_timeout) != 0) {
        snprintf(logbuf, sizeof(logbuf), "%sfailed to open subscriber connection", LOG_PREFIX);
    add_log(result, logbuf);
        goto finalize;
    }
    snprintf(logbuf, sizeof(logbuf), "%ssubscriber connected", LOG_PREFIX);
    add_log(result, logbuf);

    if (mqtt_client_subscribe(subscriber, "#", op_timeout) != 0) {
        snprintf(logbuf, sizeof(logbuf), "%sfailed to subscribe to '#' topic", LOG_PREFIX);
        add_log(result, logbuf);
        goto finalize;
    }
    snprintf(logbuf, sizeof(logbuf), "%ssubscriber registered to '#' topic", LOG_PREFIX);
    add_log(result, logbuf);

    snprintf(client_id, sizeof(client_id), "krk-pub-%u", (unsigned)rand());
    if (mqtt_client_connect(&publisher, host, (uint16_t)port, client_id, username, password, op_timeout) != 0) {
        snprintf(logbuf, sizeof(logbuf), "%sfailed to open publisher connection", LOG_PREFIX);
    add_log(result, logbuf);
        goto finalize;
    }
    snprintf(logbuf, sizeof(logbuf), "%spublisher connected", LOG_PREFIX);
    add_log(result, logbuf);

    char topic[128];
    char payload[128];
    snprintf(topic, sizeof(topic), "kraken/test/%u", (unsigned)rand());
    snprintf(payload, sizeof(payload), "kraken_probe_%u", (unsigned)rand());

    if (mqtt_client_publish(publisher, topic, payload, op_timeout) != 0) {
        snprintf(logbuf, sizeof(logbuf), "%spublisher failed to send probe message", LOG_PREFIX);
    add_log(result, logbuf);
        goto finalize;
    }
    snprintf(logbuf, sizeof(logbuf), "%sprobe message published", LOG_PREFIX);
    add_log(result, logbuf);

    uint32_t wait_window = op_timeout * 2;
    if (wait_window > 15000)
        wait_window = 15000;
    leak_detected = mqtt_wait_for_sys_topic(subscriber, sys_prefix, wait_window, leaked_topic, sizeof(leaked_topic), leaked_payload, sizeof(leaked_payload));
    if (leak_detected) {
        char logbuf[256];
        snprintf(logbuf, sizeof(logbuf), "%sreceived $SYS topic via '#': %s", LOG_PREFIX, leaked_topic);
        add_log(result, logbuf);
        if (leaked_payload[0] != '\0') {
            char paybuf[300];
            snprintf(paybuf, sizeof(paybuf), "%spayload preview: %s", LOG_PREFIX, leaked_payload);
            add_log(result, paybuf);
        }
    } else {
        snprintf(logbuf, sizeof(logbuf), "%sno $SYS topic observed via '#' subscription", LOG_PREFIX);
        add_log(result, logbuf);
    }

finalize:
    if (subscriber >= 0)
        close(subscriber);
    if (publisher >= 0)
        close(publisher);

    KrakenFinding finding = {0};
    finding.id = mystrdup("mqtt-sys-disclosure");
    finding.module_id = mystrdup("MQTT-SYS-DISCLOSURE");
    finding.success = leak_detected;
    finding.title = mystrdup("MQTT $SYS topic disclosure");
    finding.severity = mystrdup(leak_detected ? "high" : "info");
    finding.description = mystrdup(leak_detected ? "Broker forwards $SYS topics to '#' subscribers" : "Broker filters $SYS topics from '#' subscribers");
    finding.timestamp = time(NULL);
    finding.target.host = mystrdup(host);
    finding.target.port = (uint16_t)port;

    if (leak_detected) {
        finding.evidence.count = leaked_payload[0] ? 2 : 1;
        finding.evidence.items = (KrakenKeyValue *)calloc(finding.evidence.count, sizeof(KrakenKeyValue));
        if (finding.evidence.items) {
            finding.evidence.items[0].key = mystrdup("topic");
            finding.evidence.items[0].value = mystrdup(leaked_topic);
            if (finding.evidence.count > 1) {
                finding.evidence.items[1].key = mystrdup("payload_preview");
                finding.evidence.items[1].value = mystrdup(leaked_payload);
            }
        }
    }

    finding.tags.count = 2;
    finding.tags.strings = (const char **)malloc(2 * sizeof(char *));
    if (finding.tags.strings) {
        finding.tags.strings[0] = mystrdup("mqtt");
        finding.tags.strings[1] = mystrdup("sys");
    }

    add_finding(result, &finding);

    free(username);
    free(password);
    free(sys_prefix);

    *out_result = result;
    return 0;
}


KRAKEN_API void kraken_free(void *p) {
    if (!p)
        return;

    KrakenRunResult *result = (KrakenRunResult *)p;

    free((void *)result->target.host);

    for (size_t i = 0; i < result->findings_count; i++) {
        KrakenFinding *f = &result->findings[i];
        free((void *)f->id);
        free((void *)f->module_id);
        free((void *)f->title);
        free((void *)f->severity);
        free((void *)f->description);
        free((void *)f->target.host);

        for (size_t j = 0; j < f->evidence.count; j++) {
            free((void *)f->evidence.items[j].key);
            free((void *)f->evidence.items[j].value);
        }
        free(f->evidence.items);

        for (size_t j = 0; j < f->tags.count; j++) {
            free((void *)f->tags.strings[j]);
        }
        free((void *)f->tags.strings);
    }
    free(result->findings);

    for (size_t i = 0; i < result->logs.count; i++) {
        free((void *)result->logs.strings[i]);
    }
    free(result->logs.strings);

    free(result);
}
