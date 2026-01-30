#define KRAKEN_MODULE_BUILD
#include <kraken_module_abi.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PACKETS 256
#define MAX_PACKET_SIZE 17000
#define MAX_CONNECTIONS 32

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION = KRAKEN_ABI_VERSION;


typedef enum {
    INVALID = 0,
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    PUBREC = 5,
    PUBREL = 6,
    PUBCOMP = 7,
    SUBSCRIBE = 8,
    SUBACK = 9,
    UNSUBSCRIBE = 10,
    UNSUBACK = 11,
    PINGREQ = 12,
    PINGRESP = 13,
    DISCONNECT = 14,
    AUTH = 15
} MqttPacketType;

typedef struct {
    MqttPacketType type;
    uint8_t data[MAX_PACKET_SIZE];
    size_t data_len;
} mqtt_packet;

static const char *mqtt_packet_name(MqttPacketType type) {
    switch (type) {
        case CONNECT:
            return "CONNECT";
        case CONNACK:
            return "CONNACK";
        case PUBLISH:
            return "PUBLISH";
        case PUBACK:
            return "PUBACK";
        case PUBREC:
            return "PUBREC";
        case PUBREL:
            return "PUBREL";
        case PUBCOMP:
            return "PUBCOMP";
        case SUBSCRIBE:
            return "SUBSCRIBE";
        case SUBACK:
            return "SUBACK";
        case UNSUBSCRIBE:
            return "UNSUBSCRIBE";
        case UNSUBACK:
            return "UNSUBACK";
        case PINGREQ:
            return "PINGREQ";
        case PINGRESP:
            return "PINGRESP";
        case DISCONNECT:
            return "DISCONNECT";
        case AUTH:
            return "AUTH";
        default:
            return "INVALID";
    }
}

static MqttPacketType mqtt_packet_type_from_string(const char *str) {
    if (!str)
        return INVALID;
    if (strcmp(str, "CONNECT") == 0)
        return CONNECT;
    if (strcmp(str, "CONNACK") == 0)
        return CONNACK;
    if (strcmp(str, "PUBLISH") == 0)
        return PUBLISH;
    if (strcmp(str, "PUBACK") == 0)
        return PUBACK;
    if (strcmp(str, "PUBREC") == 0)
        return PUBREC;
    if (strcmp(str, "PUBREL") == 0)
        return PUBREL;
    if (strcmp(str, "PUBCOMP") == 0)
        return PUBCOMP;
    if (strcmp(str, "SUBSCRIBE") == 0)
        return SUBSCRIBE;
    if (strcmp(str, "SUBACK") == 0)
        return SUBACK;
    if (strcmp(str, "UNSUBSCRIBE") == 0)
        return UNSUBSCRIBE;
    if (strcmp(str, "UNSUBACK") == 0)
        return UNSUBACK;
    if (strcmp(str, "PINGREQ") == 0)
        return PINGREQ;
    if (strcmp(str, "PINGRESP") == 0)
        return PINGRESP;
    if (strcmp(str, "DISCONNECT") == 0)
        return DISCONNECT;
    if (strcmp(str, "AUTH") == 0)
        return AUTH;
    return INVALID;
}

uint8_t *decode_packet_data_from_hex_percent(const char *hex_str, size_t *out_len) {
    size_t len = strlen(hex_str);

    uint8_t *buffer = malloc(len / 4);
    if (!buffer) {
        return NULL;
    }

    size_t idx = 0;
    for (size_t i = 0; i < len;) {
        if (hex_str[i] == '%' && i + 3 < len) {
            unsigned int byte;
            if (sscanf(hex_str + i + 2, "%2x", &byte) == 1) {
                buffer[idx++] = (uint8_t)byte;
            }
            i += 4;
        } else {
            i++;
        }
    }

    *out_len = idx;
    return buffer;
}

static int read_file(const char *file_path, mqtt_packet packet_list[MAX_PACKETS], size_t *packet_count) {
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char line_type[64];
    char line_data[90000];
    size_t count = 0;

    while (fgets(line_type, sizeof(line_type), fp) && fgets(line_data, sizeof(line_data), fp)) {
        if (count >= MAX_PACKETS) {
           
            break;
        }

        line_type[strcspn(line_type, "\r\n")] = 0;
        line_data[strcspn(line_data, "\r\n")] = 0;

        if (strlen(line_type) == 0 || strlen(line_data) == 0)
            continue;

        MqttPacketType type = mqtt_packet_type_from_string(line_type);

        if (type == INVALID) {
            continue;
        }

        packet_list[count].type = type;

        size_t decoded_len = 0;
        uint8_t *decoded = decode_packet_data_from_hex_percent(line_data, &decoded_len);
        if (!decoded) {
            continue;
        }

        if (decoded_len > MAX_PACKET_SIZE) {
            decoded_len = MAX_PACKET_SIZE;
        }

       

        memcpy(packet_list[count].data, decoded, decoded_len);
        packet_list[count].data_len = decoded_len;

        free(decoded);

        count++;
    }

    fclose(fp);
    *packet_count = count;
    return 0;
}

int send_packet(int sock, mqtt_packet *p) {
    ssize_t sent = send(sock, p->data, p->data_len, 0);
    if (sent != (ssize_t)p->data_len) {
        perror("send");
        return -1;
    }
    return 0;
}

int read_mqtt_response(int sock) {
    uint8_t header[5];
    ssize_t r = recv(sock, header, 1, 0);
    if (r <= 0)
        return -1;

    uint8_t remaining_length = 0;
    int multiplier = 1;
    int bytes_read = 0;
    do {
        r = recv(sock, &header[bytes_read], 1, 0);
        if (r <= 0)
            return -1;
        remaining_length += (header[bytes_read] & 127) * multiplier;
        multiplier *= 128;
        bytes_read++;
    } while (header[bytes_read - 1] & 128);

    uint8_t *payload = malloc(remaining_length);
    if (!payload)
        return -1;

    r = recv(sock, payload, remaining_length, 0);
    free(payload);

    if (r <= 0)
        return -1;

    return 0;
}

typedef struct {
    int sock;
    int done;
} connection_info;

typedef struct {
    connection_info connections[MAX_CONNECTIONS];
    size_t connection_count;
    pthread_mutex_t done_mutex;
} replay_context;

typedef struct {
    connection_info *conn;
    pthread_mutex_t *mutex;
} reading_loop_arg;

void *reading_loop(void *arg) {
    reading_loop_arg *rla = (reading_loop_arg *)arg;
    while (1) {
        pthread_mutex_lock(rla->mutex);
        int done = rla->conn->done;
        pthread_mutex_unlock(rla->mutex);
        if (done) {
            break;
        }

        read_mqtt_response(rla->conn->sock);
        usleep(1000);
    }
    return NULL;
}

int replay_packets(const char *broker_ip, uint16_t broker_port, mqtt_packet packets[], size_t n) {
    replay_context ctx = {0};
    pthread_mutex_init(&ctx.done_mutex, NULL);

    int current_sock = -1;
    pthread_t threads[MAX_CONNECTIONS] = {0};

    for (size_t i = 0; i < n; i++) {
        mqtt_packet *p = &packets[i];

        if (current_sock < 0 || p->type == CONNECT) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                pthread_mutex_destroy(&ctx.done_mutex);
                return -1;
            }

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(broker_port);
            inet_pton(AF_INET, broker_ip, &addr.sin_addr);

            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock);
                pthread_mutex_destroy(&ctx.done_mutex);
                return -1;
            }
            current_sock = sock;
        }

        ssize_t sent = send(current_sock, p->data, p->data_len, 0);
        if (sent != (ssize_t)p->data_len) {
           
        }
    }

   
    for (size_t i = 0; i < ctx.connection_count; i++) {
        pthread_mutex_lock(&ctx.done_mutex);
        ctx.connections[i].done = 1;
        pthread_mutex_unlock(&ctx.done_mutex);

        pthread_join(threads[i], NULL);
        close(ctx.connections[i].sock);
    }
    if (current_sock >= 0) {
        close(current_sock);
    }

    pthread_mutex_destroy(&ctx.done_mutex);
    return 0;
}

int heartbeat(const char *broker_ip, uint16_t broker_port) {
    char port_buf[6];
    snprintf(port_buf, sizeof(port_buf), "%u", broker_port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(broker_ip, port_buf, &hints, &res);
    if (gai != 0) {
       
        return 1;
    }

    int status = 1;
    int last_errno = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            last_errno = errno;
            continue;
        }

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
            status = 0;
            close(sock);
            break;
        }

        last_errno = errno;
        close(sock);
    }

    if (status != 0 && last_errno) {
        errno = last_errno;
        perror("heartbeat connect");
    }

    freeaddrinfo(res);
    return status;
}


KRAKEN_API int kraken_run(const char *host, uint32_t port, uint32_t timeout_ms, const char *params_json, KrakenRunResult **out_result) {
   
    KrakenRunResult *result = (KrakenRunResult *)calloc(1, sizeof(KrakenRunResult));
    if (!result)
        return -1;

    result->target.host = mystrdup(host);
    result->target.port = (uint16_t)port;

   
    char *sequence_num = json_extract_string(params_json, "sequence_num");
    int seq_num = 0;
    if (sequence_num && *sequence_num) {
        seq_num = (int)strtol(sequence_num, NULL, 10);
    } else {
        add_log(result, "missing or empty sequence_num, defaulting to 0");
    }
    free(sequence_num);

    time_t ts = time(NULL);
    for (int i = 0; i < seq_num; i++) {
        bool is_successfull = false;

        char buff[1000] = {};
        int ok = sprintf(buff, "path%d", i);
        char *path = json_extract_string(params_json, buff);
        if (!path || !*path) {
            add_log(result, "missing replay path in params, skipping entry");
            free(path);
            continue;
        }

       
        const char *filename = strrchr(path, '/');
        filename = filename ? filename + 1 : path;
        char title[256] = {0};
        const char *dot = strrchr(filename, '.');
        size_t name_len = dot ? (size_t)(dot - filename) : strlen(filename);
        if (name_len > sizeof(title) - 1) name_len = sizeof(title) - 1;
        strncpy(title, filename, name_len);

        {
            mqtt_packet packets[MAX_PACKETS];
            size_t packet_count = 0;

            if (read_file(path, packets, &packet_count) != 0) {
                add_log(result, "Failed to read packet file");
                free(path);
                continue;
            }

            if (replay_packets(host, port, packets, packet_count) != 0) {
                add_log(result, "Failed to connect for packet replay");
                free(path);
                continue;
            }
            usleep(1000);

            if (heartbeat(host, port)) {
                is_successfull = true;
               
                break;
            }
        }

        KrakenFinding f = {0};
        f.id = mystrdup("");
        f.module_id = mystrdup("MQTT-REPLAY");
        f.success = is_successfull;
        f.title = mystrdup(title);
        f.severity = mystrdup("high");
        f.description = mystrdup("The broker crashed or became unreachable after replaying malformed MQTT packets");
        f.timestamp = ts;
        f.target.host = mystrdup(host);
        f.target.port = port;

        f.tags.count = 2;
        f.tags.strings = (const char **)malloc(2 * sizeof(char *));
        f.tags.strings[0] = mystrdup("mqtt");
        f.tags.strings[1] = mystrdup(title);

        free(path);

        add_finding(result, &f);
    }

    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free(void *p) {
    if (!p) {
        return;
    }

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
    free((void *)result->logs.strings);

    free(result);
}
