#define KRAKEN_MODULE_BUILD
#define BUILDING_MQTT_AUTH_CHECK_V2
#include <kraken_module_abi_v2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;
static const char *LOG_PREFIX = "[mqtt-auth-check] ";

static void log_prefixed(KrakenRunResultV2 *res, const char *msg) {
  char buf[256];
  snprintf(buf, sizeof(buf), "%s%s", LOG_PREFIX, msg);
  add_log_v2(res, buf);
}

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

static int mqtt_build_connect(mqtt_packet_t *pkt, const char *client_id,
                              const char *user, const char *pass) {
  pkt->len = 0;
  uint8_t *p = pkt->buf;
  const char *proto = "MQTT";
  p += mqtt_encode_string(p, proto);
  *p++ = 4;
  uint8_t flags = 0;
  if (user && *user)
    flags |= 0x80;
  if (pass && *pass)
    flags |= 0x40;
  *p++ = flags;
  *p++ = 0;
  *p++ = 60;
  p += mqtt_encode_string(p, client_id);
  if (user && *user)
    p += mqtt_encode_string(p, user);
  if (pass && *pass)
    p += mqtt_encode_string(p, pass);

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
  p += mqtt_encode_string(p, topic);
  *p++ = 0;
  pkt->len = p - pkt->buf;
  return (int)pkt->len;
}

static int mqtt_build_publish(mqtt_packet_t *pkt, const char *topic,
                              const char *msg) {
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
  p += mqtt_encode_string(p, topic);
  memcpy(p, msg, msg_len);
  pkt->len = (p + msg_len) - pkt->buf;
  return (int)pkt->len;
}

static int mqtt_parse_connack(uint8_t *buf, size_t n) {
  return n >= 4 && buf[0] == 0x20 && buf[3] == 0x00;
}

static int mqtt_parse_suback(uint8_t *buf, size_t n) {
  return n >= 3 && buf[0] == 0x90;
}


static int mqtt_check_auth(KrakenConnectionHandle conn,
                           const KrakenConnectionOps *ops, const char *user,
                           const char *pass, uint32_t timeout_ms) {
  mqtt_packet_t pkt;
  char cid[32];
  snprintf(cid, sizeof(cid), "kraken_%u", (unsigned)rand());

 
  int len = mqtt_build_connect(&pkt, cid, user, pass);

 
  int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
  if (sent <= 0) {
    return -1;
  }

 
  uint8_t resp[16];
  int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
  if (received <= 0) {
    return -1;
  }

 
  return mqtt_parse_connack(resp, (size_t)received) ? 1 : 0;
}

static int mqtt_check_pubsub(KrakenConnectionHandle conn,
                             const KrakenConnectionOps *ops,
                             uint32_t timeout_ms) {
  mqtt_packet_t pkt;
  const char *topic = "kraken/test/topic";

 
  int len = mqtt_build_subscribe(&pkt, topic);
  int64_t sent = ops->send(conn, pkt.buf, len, timeout_ms);
  if (sent <= 0) {
    return 0;
  }

 
  uint8_t resp[16];
  int64_t received = ops->recv(conn, resp, sizeof(resp), timeout_ms);
  int sub_ok = (received > 0 && mqtt_parse_suback(resp, (size_t)received));

 
  const char *msg = "hello from Kraken";
  len = mqtt_build_publish(&pkt, topic, msg);
  sent = ops->send(conn, pkt.buf, len, timeout_ms);

  return sub_ok;
}

typedef struct {
  char **entries;
  size_t count;
} creds_list_t;

static void free_creds_list(creds_list_t *list) {
  if (!list)
    return;
  for (size_t i = 0; i < list->count; i++) {
    free(list->entries[i]);
  }
  free(list->entries);
  list->entries = NULL;
  list->count = 0;
}

static creds_list_t load_creds_file(const char *path) {
  creds_list_t list = {0};

  FILE *f = fopen(path, "r");
  if (!f) {
    return list;
  }

  char line[256];
  while (fgets(line, sizeof(line), f)) {
   
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
      line[--len] = '\0';
    }

    if (len == 0 || line[0] == '#') {
      continue;
    }

    list.count++;
    list.entries = (char **)realloc(list.entries, list.count * sizeof(char *));
    list.entries[list.count - 1] = mystrdup(line);
  }

  fclose(f);
  return list;
}


KRAKEN_API int kraken_run_v2(KrakenConnectionHandle conn,
                             const KrakenConnectionOps *ops,
                             const KrakenTarget *target, uint32_t timeout_ms,
                             const char *params_json,
                             KrakenRunResultV2 **out_result) {
  srand((unsigned)time(NULL));

 
  KrakenRunResultV2 *result =
      (KrakenRunResultV2 *)calloc(1, sizeof(KrakenRunResultV2));
  if (!result)
    return -1;

  copy_target(&result->target, target);

  log_prefixed(result,
               "MQTT authentication assessment started (V2 with conduit)");

 
  const KrakenConnectionInfo *info = ops->get_info(conn);

  char log_buf[512];
  snprintf(log_buf, sizeof(log_buf), "Connection type: %s",
           info->type == KRAKEN_CONN_TYPE_STREAM ? "stream" : "datagram");
  add_log_v2(result, log_buf);

  time_t ts = time(NULL);

 
  log_prefixed(result, "Testing anonymous MQTT authentication...");

  int anon_result = mqtt_check_auth(conn, ops, NULL, NULL, timeout_ms);

  if (anon_result == 1) {
    KrakenFindingV2 f = {0};
    f.id = mystrdup("MQTT-ANON");
    f.module_id = mystrdup("mqtt-auth-check-v2");
    f.success = true;
    f.title = mystrdup("Anonymous authentication accepted");
    f.severity = mystrdup("high");
    f.description =
        mystrdup("The MQTT broker allows unauthenticated clients to connect.");
    f.timestamp = ts;
    copy_target(&f.target, target);

    f.tags.count = 3;
    f.tags.strings = (const char **)malloc(3 * sizeof(char *));
    f.tags.strings[0] = mystrdup("mqtt");
    f.tags.strings[1] = mystrdup("auth");
    f.tags.strings[2] = mystrdup("anonymous");

    add_finding_v2(result, &f);
    log_prefixed(result, "FINDING: Anonymous authentication is allowed!");

   
    log_prefixed(result, "Testing anonymous publish/subscribe...");
    int pubsub_ok = mqtt_check_pubsub(conn, ops, timeout_ms);

    if (pubsub_ok) {
      KrakenFindingV2 f_pubsub = {0};
      f_pubsub.id = mystrdup("MQTT-PUBSUB-ANON");
      f_pubsub.module_id = mystrdup("mqtt-auth-check-v2");
      f_pubsub.success = true;
      f_pubsub.title = mystrdup("Unauthenticated publish/subscribe allowed");
      f_pubsub.severity = mystrdup("critical");
      f_pubsub.description =
          mystrdup("The MQTT broker allows unauthenticated clients to publish "
                   "and/or subscribe to topics.");
      f_pubsub.timestamp = ts;
      copy_target(&f_pubsub.target, target);

      f_pubsub.tags.count = 3;
      f_pubsub.tags.strings = (const char **)malloc(3 * sizeof(char *));
      f_pubsub.tags.strings[0] = mystrdup("mqtt");
      f_pubsub.tags.strings[1] = mystrdup("pubsub");
      f_pubsub.tags.strings[2] = mystrdup("unauthenticated");

      add_finding_v2(result, &f_pubsub);
      log_prefixed(result, "FINDING: Anonymous publish/subscribe is allowed!");
    } else {
      log_prefixed(result, "Anonymous publish/subscribe is restricted (good)");
    }

  } else if (anon_result == 0) {
    log_prefixed(result, "Anonymous authentication rejected (good)");
  } else {
    log_prefixed(result,
                 "Failed to test anonymous authentication (connection issue)");
  }

 
  char *creds_path = json_extract_string(params_json, "creds_file");
  if (creds_path && *creds_path) {
    snprintf(log_buf, sizeof(log_buf), "%sCredential testing from file: %s",
             LOG_PREFIX, creds_path);
    add_log_v2(result, log_buf);

    creds_list_t creds = load_creds_file(creds_path);
    if (creds.count > 0) {
      snprintf(log_buf, sizeof(log_buf), "%sLoaded %zu credential pairs",
               LOG_PREFIX, creds.count);
      add_log_v2(result, log_buf);

     
      if (ops->open && ops->close) {
        for (size_t i = 0; i < creds.count; i++) {
          const char *entry = creds.entries[i];
         
          const char *colon = strchr(entry, ':');
          char user[128] = {0};
          char pass[128] = {0};

          if (colon) {
            size_t ulen = (size_t)(colon - entry);
            if (ulen >= sizeof(user))
              ulen = sizeof(user) - 1;
            strncpy(user, entry, ulen);
            strncpy(pass, colon + 1, sizeof(pass) - 1);
          } else {
            strncpy(user, entry, sizeof(user) - 1);
          }

          snprintf(log_buf, sizeof(log_buf), "%sTesting credentials: %s:***",
                   LOG_PREFIX, user);
          add_log_v2(result, log_buf);

         
          KrakenConnectionHandle new_conn = ops->open(conn, timeout_ms);
          if (!new_conn) {
            snprintf(log_buf, sizeof(log_buf),
                     "%sFailed to open connection for credential test",
                     LOG_PREFIX);
            add_log_v2(result, log_buf);
            continue;
          }

          int cred_result =
              mqtt_check_auth(new_conn, ops, user, pass, timeout_ms);

          if (cred_result == 1) {
            KrakenFindingV2 f = {0};
            f.id = mystrdup("MQTT-WEAK-CREDS");
            f.module_id = mystrdup("mqtt-auth-check-v2");
            f.success = true;
            f.title = mystrdup("Weak credentials accepted");
            f.severity = mystrdup("high");

            char desc[512];
            snprintf(desc, sizeof(desc),
                     "The MQTT broker accepted default/weak credentials: %s",
                     user);
            f.description = mystrdup(desc);
            f.timestamp = ts;
            copy_target(&f.target, target);

            f.tags.count = 3;
            f.tags.strings = (const char **)malloc(3 * sizeof(char *));
            f.tags.strings[0] = mystrdup("mqtt");
            f.tags.strings[1] = mystrdup("auth");
            f.tags.strings[2] = mystrdup("weak-credentials");

            f.evidence.count = 1;
            f.evidence.items = (KrakenKeyValue *)malloc(sizeof(KrakenKeyValue));
            f.evidence.items[0].key = mystrdup("username");
            f.evidence.items[0].value = mystrdup(user);

            add_finding_v2(result, &f);

            snprintf(log_buf, sizeof(log_buf),
                     "%sFINDING: Weak credentials accepted: %s", LOG_PREFIX,
                     user);
            add_log_v2(result, log_buf);
          }

          ops->close(new_conn);
        }
      } else {
        log_prefixed(result, "Multi-connection not supported by runner, "
                             "credential testing skipped");
      }
    } else {
      snprintf(log_buf, sizeof(log_buf), "%sNo credentials loaded from %s",
               LOG_PREFIX, creds_path);
      add_log_v2(result, log_buf);
    }

    free_creds_list(&creds);
    free(creds_path);
  }

  *out_result = result;
  return 0;
}


KRAKEN_API void kraken_free_v2(void *p) {
  if (!p)
    return;

  KrakenRunResultV2 *result = (KrakenRunResultV2 *)p;

  free_target(&result->target);

  for (size_t i = 0; i < result->findings_count; i++) {
    KrakenFindingV2 *f = &result->findings[i];
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
  free(result->findings);

  for (size_t i = 0; i < result->logs.count; i++) {
    free((void *)result->logs.strings[i]);
  }
  free(result->logs.strings);

  free(result);
}
